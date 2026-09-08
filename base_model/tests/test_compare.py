"""The comparison scorer, against recordings whose answers are known.

Written as synthetic recordings rather than fixtures cut from a real run,
because the properties being pinned are about how the scorer treats *absences*
-- no quarantine events, no ledger, a device that received nothing -- and a real
recording cannot be trusted to contain the exact absence under test.

The rule these tests exist to defend is the project's own: **"not measured" is
never rendered as zero.** A baseline that reports `0 ms` isolation latency
instead of `--` reads as *better than* the treatment arm to anyone skimming the
table, which is the exact opposite of the truth.
"""

import json

import pytest

from base_model.compare import (
    ArmResult,
    format_comparison,
    score_arm,
    write_per_node_csv,
    write_trust_series_csv,
)

SERVERS = [f'srv{i}' for i in range(1, 9)]
ATTACKS = {'srv1': 'grayhole', 'srv3': 'sybil', 'srv6': 'drop', 'srv8': 'onoff'}
ONSETS = {'srv1': 40.0, 'srv3': 20.0, 'srv6': 30.0, 'srv8': 50.0}
DEVICE_ATTACKS = {'iot37': 'flood', 'iot38': 'spoof', 'iot39': 'bad_credentials'}


def _topology(n_iot=40, static=True):
    nodes = [{'id': 's0', 'kind': 'core_switch', 'dpid': 1}]
    links = []
    for i in range(1, 9):
        nodes.append({'id': f's{i}', 'kind': 'edge_switch', 'dpid': i + 1})
        nodes.append({
            'id': f'srv{i}', 'kind': 'server', 'ip': f'10.0.1.{i}',
            'attack': ATTACKS.get(f'srv{i}', 'none'),
            'attack_start_s': ONSETS.get(f'srv{i}', 0.0),
        })
        links.append({'a': 's0', 'b': f's{i}', 'kind': 'core_link'})
        links.append({'a': f's{i}', 'b': f'srv{i}', 'kind': 'server_link'})
    for j in range(1, n_iot + 1):
        node = {
            'id': f'iot{j}', 'kind': 'iot', 'ip': f'10.0.0.{j}',
            'attack': DEVICE_ATTACKS.get(f'iot{j}', 'none'), 'attack_start_s': 0.0,
        }
        if static:
            node['bound_to'] = f'srv{((j - 1) % 8) + 1}'
        nodes.append(node)
        links.append({'a': f'iot{j}', 'b': f's{((j - 1) % 8) + 1}', 'kind': 'iot_link'})
    return {'nodes': nodes, 'links': links}


def _write(path, events):
    with open(path, 'w') as f:
        for ev in events:
            f.write(json.dumps(ev) + '\n')


def _baseline_recording(path, t0=1000.0):
    """8 devices statically bound 1:1 to 8 servers. srv6 black-holes from t=30.

    So iot6 -- and only iot6 -- is starved, permanently, and nothing intervenes.
    """
    events = [{'type': 'topology', 'ts': t0, 'graph': _topology()}]
    events.append({
        'type': 'arm', 'ts': t0 + 0.1, 'arm': 'baseline',
        'strategy': 'static_nearest', 'observe_anomaly': True,
    })
    # 70 steps, srv6 arming at 30: iot6 ends at 30/70 served, unambiguously
    # under the 50% starvation line rather than sitting exactly on it.
    for step in range(70):
        ts = t0 + step
        for j in range(1, 9):
            node = f'srv{j}'
            armed = node == 'srv6' and step >= 30
            status = 'timeout' if armed else 'success'
            events.append({
                'type': 'route', 'ts': ts, 'client_ip': f'10.0.0.{j}',
                'client_port': 40000 + step, 'chosen': node,
                'edge_score': None, 'ranked': [], 'decision_ms': 0.4,
                'strategy': 'static_nearest',
            })
            events.append({
                'type': 'report', 'ts': ts + 0.1, 'device': f'iot{j}',
                'node': node, 'status': status,
                'latency_ms': 4000.0 if armed else 50.0,
                'trust': 0.15 if armed else 0.8, 'committed': False,
                'report_ms': 0.0,
            })
        events.append({
            'type': 'node_status', 'ts': ts + 0.2,
            'nodes': {
                n: {
                    'trust': 0.15 if (n == 'srv6' and step >= 30) else 0.8,
                    'anomaly': 0.9 if (n == 'srv6' and step >= 30) else 0.0,
                    'quarantined': False, 'probation': False,
                }
                for n in SERVERS
            },
        })
        if step >= 35:
            events.append({
                'type': 'anomaly', 'ts': ts + 0.3, 'node': 'srv6',
                'reasons': ['packet-drop tell: timeout rate 1.00 > 0.40'],
                'signals': {'packet_drop': 1.0}, 'anomaly': 0.9, 'gate': 0.5,
                'actioned': False,
            })
    # Every device admitted, including the spoofer and the wrong-key device.
    events.append({
        'type': 'auth_admitted', 'ts': t0 + 15, 'device_id': 'iot1',
        'source_ip': '10.0.0.38', 'expected_ip': '10.0.0.1',
        'source_matches_identity': False, 'reclaimed_from': '10.0.0.1',
        'verified': False,
    })
    events.append({
        'type': 'auth_admitted', 'ts': t0 + 2, 'device_id': 'iot39',
        'source_ip': '10.0.0.39', 'expected_ip': '10.0.0.39',
        'source_matches_identity': True, 'verified': False,
    })
    _write(path, events)


def _treatment_recording(path, t0=1000.0):
    """Same run, with srv6 quarantined at t=33 and its clients re-steered."""
    events = [{'type': 'topology', 'ts': t0, 'graph': _topology(static=False)}]
    for step in range(70):
        ts = t0 + step
        for j in range(1, 9):
            armed = j == 6 and 30 <= step < 33
            node = 'srv2' if (j == 6 and step >= 33) else f'srv{j}'
            status = 'timeout' if armed else 'success'
            events.append({
                'type': 'route', 'ts': ts, 'client_ip': f'10.0.0.{j}',
                'client_port': 40000 + step, 'chosen': node,
                'edge_score': 0.71, 'ranked': [], 'decision_ms': 1.2,
            })
            events.append({
                'type': 'report', 'ts': ts + 0.1, 'device': f'iot{j}',
                'node': node, 'status': status,
                'latency_ms': 4000.0 if armed else 55.0,
                'trust': 0.2 if armed else 0.82,
                'committed': step % 10 == 0, 'report_ms': 0.3,
            })
        events.append({
            'type': 'node_status', 'ts': ts + 0.2,
            'nodes': {
                n: {
                    'trust': 0.2 if (n == 'srv6' and step >= 30) else 0.82,
                    'anomaly': 0.9 if (n == 'srv6' and step >= 30) else 0.0,
                    'quarantined': n == 'srv6' and step >= 33,
                    'probation': False,
                }
                for n in SERVERS
            },
        })
        if step == 32:
            events.append({
                'type': 'anomaly', 'ts': ts + 0.3, 'node': 'srv6',
                'reasons': ['packet-drop tell'], 'signals': {'packet_drop': 1.0},
                'anomaly': 0.9, 'gate': 0.5,
            })
        if step == 33:
            events.append({
                'type': 'quarantine', 'ts': ts + 0.3, 'node': 'srv6',
                'trust': 0.2, 'anomaly': 0.9,
                'isolation_threshold': 0.3, 'anomaly_gate': 0.5,
            })
            events.append({
                'type': 'reroute', 'ts': ts + 0.4, 'node': 'srv6', 'resteer_ms': 180.0,
            })
        if step % 10 == 0:
            events.append({'type': 'block', 'ts': ts + 0.5, 'index': step // 10})
    events.append({
        'type': 'auth_denied', 'ts': t0 + 15, 'device_id': 'iot1',
        'source_ip': '10.0.0.38', 'kind': 'ip_pin', 'reason': 'source IP mismatch',
    })
    events.append({
        'type': 'auth_denied', 'ts': t0 + 2, 'device_id': 'iot39',
        'source_ip': '10.0.0.39', 'kind': 'bad_response', 'reason': 'bad key',
    })
    _write(path, events)


@pytest.fixture
def arms(tmp_path):
    base_path = tmp_path / 'base_events.jsonl'
    treat_path = tmp_path / 'events.jsonl'
    _baseline_recording(base_path)
    _treatment_recording(treat_path)
    return score_arm('baseline', str(base_path)), score_arm('zero_trust', str(treat_path))


# ---------------------------------------------------------------------- #
# Ground truth                                                           #
# ---------------------------------------------------------------------- #
def test_ground_truth_is_read_from_the_recording(arms):
    base, _ = arms
    assert base.truth.attacker_servers == ['srv1', 'srv3', 'srv6', 'srv8']
    assert base.truth.honest_servers == ['srv2', 'srv4', 'srv5', 'srv7']
    assert base.truth.server_onset['srv6'] == 30.0
    assert base.truth.bound_to['iot6'] == 'srv6'
    assert base.strategy == 'static_nearest'
    assert base.arm_label == 'baseline'


# ---------------------------------------------------------------------- #
# Absence is never zero                                                  #
# ---------------------------------------------------------------------- #
def test_baseline_never_quarantines_and_that_reads_as_never(arms):
    base, treat = arms
    assert base.quarantine_events == 0
    assert base.first_quarantine_s == {}
    assert treat.first_quarantine_s['srv6'] == pytest.approx(33.3, abs=0.5)


def test_containment_row_says_never_not_zero(arms):
    base, treat = arms
    text = format_comparison(base, treat)
    line = next(l for l in text.splitlines() if 'srv6 (drop' in l)
    assert 'never' in line
    assert '0.0s' not in line


def test_ledger_row_is_a_dash_for_the_baseline(arms):
    base, treat = arms
    assert base.blocks == 0
    assert treat.blocks > 0
    text = format_comparison(base, treat)
    line = next(l for l in text.splitlines() if 'trust blocks committed' in l)
    assert '--' in line


def test_detections_unactioned_counts_every_baseline_detection(arms):
    base, treat = arms
    assert base.anomaly_events > 0
    assert base.detections_unactioned == base.anomaly_events
    # The treatment arm detected once and acted on it.
    assert treat.detections_unactioned == 0


# ---------------------------------------------------------------------- #
# Service                                                                #
# ---------------------------------------------------------------------- #
def test_starved_device_is_named(arms):
    base, treat = arms
    assert base.starved_devices() == ['iot6']
    assert treat.starved_devices() == []


def test_availability_is_averaged_per_device_not_pooled(arms):
    base, _ = arms
    # iot6 got 30 of 70 tasks served; the other seven got all 70.
    assert base.device_availability('iot6') == pytest.approx(30 / 70)
    assert base.device_availability('iot1') == pytest.approx(1.0)
    # Devices that received nothing report None and are excluded, so this is a
    # mean over the eight that were actually exercised -- seven at 1.0 and one
    # at 0.43. Pooling instead would let the seven hide the one.
    assert base.honest_device_availability() == pytest.approx(
        (7 * 1.0 + 30 / 70) / 8
    )


def test_latency_is_measured_over_successes_only(arms):
    base, _ = arms
    # Timeouts report the client's 4000 ms timeout constant, not a measurement.
    assert base.mean_latency_ms == pytest.approx(50.0)


def test_pdr_and_throughput(arms):
    base, treat = arms
    assert base.tasks_total == 560
    assert base.tasks_timeout == 40
    assert base.pdr == pytest.approx(520 / 560)
    assert treat.pdr > base.pdr
    assert base.throughput_tps is not None and base.throughput_tps > 0


# ---------------------------------------------------------------------- #
# Fairness                                                               #
# ---------------------------------------------------------------------- #
def test_jain_is_computed_over_the_whole_roster(arms):
    base, _ = arms
    # Perfectly uniform static map: 70 routes to each of 8 servers.
    assert base.jain_routes == pytest.approx(1.0)


def test_a_starved_server_lowers_jain_rather_than_vanishing():
    """A server that received nothing must stay in the denominator."""
    arm = ArmResult(name='x', events_path='')
    arm.truth.servers = {f'srv{i}': 'none' for i in range(1, 9)}
    arm.routes_per_node.update({'srv1': 100, 'srv2': 100})
    assert arm.jain_routes == pytest.approx(2 / 8)


# ---------------------------------------------------------------------- #
# Admission                                                              #
# ---------------------------------------------------------------------- #
def test_spoof_is_detected_offline_from_recorded_facts(arms):
    base, treat = arms
    assert len(base.spoof_admitted) == 1
    hit = base.spoof_admitted[0]
    assert hit['claimed'] == 'iot1'
    assert hit['from_ip'] == '10.0.0.38'
    assert hit['actual_device'] == 'iot38'
    assert treat.auth_denied_kinds['ip_pin'] == 1

    text = format_comparison(base, treat)
    assert 'SUCCEEDED' in text
    assert 'REFUSED' in text


def test_wrong_key_device_admitted_in_the_baseline(arms):
    base, treat = arms
    assert base.bad_cred_admitted == ['iot39']
    assert treat.auth_denied_kinds['bad_response'] == 1


# ---------------------------------------------------------------------- #
# Outputs                                                                #
# ---------------------------------------------------------------------- #
def test_trust_series_csv_is_long_format_with_roles(tmp_path, arms):
    base, treat = arms
    out = tmp_path / 'trust_series.csv'
    write_trust_series_csv(out, [base, treat], bucket_s=10.0)
    lines = out.read_text().splitlines()
    assert lines[0] == 'arm,node,role,attack_start_s,t_s,trust,anomaly,samples'
    arms_seen = {line.split(',')[0] for line in lines[1:]}
    assert arms_seen == {'baseline', 'zero_trust'}
    srv6 = [l for l in lines[1:] if l.startswith('baseline,srv6,')]
    assert srv6 and all(l.split(',')[2] == 'drop' for l in srv6)
    # Trust collapses in the baseline and stays collapsed.
    assert float(srv6[-1].split(',')[5]) == pytest.approx(0.15)


def test_per_node_csv_has_a_row_per_arm_per_server(tmp_path, arms):
    base, treat = arms
    out = tmp_path / 'per_node.csv'
    write_per_node_csv(out, [base, treat])
    lines = out.read_text().splitlines()
    assert len(lines) == 1 + 8 * 2
    srv6_base = next(l for l in lines if l.startswith('baseline,srv6,'))
    assert srv6_base.split(',')[11] == '0'      # quarantines
    srv6_treat = next(l for l in lines if l.startswith('zero_trust,srv6,'))
    assert srv6_treat.split(',')[11] == '1'


def test_report_renders_without_a_treatment_arm(arms):
    base, _ = arms
    text = format_comparison(base, None)
    assert 'NOT SUPPLIED' in text
    assert 'srv6' in text


# ---------------------------------------------------------------------- #
# Spoof-contaminated identities                                          #
# ---------------------------------------------------------------------- #
def test_a_spoofed_identity_is_broken_out_not_silently_merged(tmp_path):
    """Two hosts reporting under one name make that name's availability a merge.

    Measured in the real baseline run: the honest iot1 was served 65.1% by its
    grayhole, while iot38 impersonating iot1 was served 13.5% by a blackhole.
    Merged, "iot1" reads 45.7% and drops into the starved list -- a number that
    is neither device's and would be wrong quoted as either.
    """
    path = tmp_path / 'spoofed.jsonl'
    t0 = 1000.0
    events = [{'type': 'topology', 'ts': t0, 'graph': _topology()}]
    for i in range(10):
        events.append({
            'type': 'report', 'ts': t0 + i, 'device': 'iot1', 'node': 'srv1',
            'status': 'success', 'latency_ms': 50.0, 'source_ip': '10.0.0.1',
        })
    for i in range(10):
        events.append({
            'type': 'report', 'ts': t0 + i, 'device': 'iot1', 'node': 'srv6',
            'status': 'timeout', 'latency_ms': 4000.0, 'source_ip': '10.0.0.38',
        })
    _write(path, events)

    arm = score_arm('baseline', str(path))
    contaminated = arm.contaminated_identities()
    assert set(contaminated) == {'iot1'}

    rows = contaminated['iot1']
    assert len(rows) == 2
    # The owner is listed first, so a reader sees the victim's own figure before
    # the one that polluted it.
    owner, impostor = rows
    assert owner['is_the_owner'] is True
    assert owner['source_ip'] == '10.0.0.1'
    assert owner['availability'] == pytest.approx(1.0)
    assert impostor['is_the_owner'] is False
    assert impostor['real_device'] == 'iot38'
    assert impostor['availability'] == pytest.approx(0.0)

    # ...and the merged figure, which is neither of theirs, is what the plain
    # per-device number would have reported.
    assert arm.device_availability('iot1') == pytest.approx(0.5)

    text = format_comparison(arm, None)
    assert 'is a MERGE' in text
    assert 'IMPERSONATING' in text


def test_an_uncontaminated_run_reports_no_merges(arms):
    base, treat = arms
    assert base.contaminated_identities() == {}
    assert treat.contaminated_identities() == {}
    assert 'is a MERGE' not in format_comparison(base, treat)
