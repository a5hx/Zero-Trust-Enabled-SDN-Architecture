"""The route<->report pairing rule, and the ways it is allowed to be wrong.

The central test here is `test_a_dropped_report_does_not_offset_every_later_pairing`.
It encodes the bug that would otherwise reach the paper as a wrong number:
naive per-client FIFO mispairs 2,687 of the treatment arm's 6,454 reports once
a single task goes unreported, and reports residence p95 at 6,572 ms against a
true 200 ms.

The second-order trap is `test_a_static_arm_cannot_detect_the_same_drop_by_offset`.
Under `static_nearest` every outstanding route for a client names the same
server, so a wrong pairing still names the right one and the control arm scores
the broken rule at 0.3% error. Any change that makes abandonment detection
depend only on the skip-scan should fail that test.

No test here opens a real recording. `test_compare.py` states the reason and it
holds: the properties being pinned are about how the scorer treats absences,
and a real run cannot be trusted to contain the exact absence under test.
"""

import ast
import json
from pathlib import Path

from base_model.interactions import (
    ARM_BASELINE,
    ARM_TREATMENT,
    DEFAULT_TASK_TIMEOUT_S,
    HONEST,
    binding_stability,
    client_rows,
    effective_fan_out,
    fan_out,
    outcome_counts,
    pairing_audit,
    score_arm_interactions,
    speed_samples,
    speed_stats,
    time_rows,
    timeline_rows,
)

SERVERS = [f'srv{i}' for i in range(1, 9)]
T0 = 1000.0


def _topology(attacks=None, devices=None):
    attacks = attacks or {}
    devices = devices or {'iot1': 'none'}
    nodes = [{'id': 's0', 'kind': 'core_switch', 'dpid': 1}]
    for i in range(1, 9):
        nodes.append({'id': f'srv{i}', 'kind': 'server', 'ip': f'10.0.1.{i}',
                      'attack': attacks.get(f'srv{i}', 'none'),
                      'attack_start_s': 20.0 if f'srv{i}' in attacks else 0.0})
    for device, attack in devices.items():
        j = int(device[3:])
        nodes.append({'id': device, 'kind': 'iot', 'ip': f'10.0.0.{j}',
                      'attack': attack,
                      'attack_start_s': 20.0 if attack != 'none' else 0.0})
    return {'type': 'topology', 'ts': T0, 'graph': {'nodes': nodes, 'links': []}}


def _route(t, device, server, port=40000):
    j = int(device[3:])
    return {'type': 'route', 'ts': T0 + t, 'client_ip': f'10.0.0.{j}',
            'client_port': port, 'chosen': server, 'decision_ms': 0.5}


def _report(t, device, server, status='success', latency_ms=50.0, **extra):
    ev = {'type': 'report', 'ts': T0 + t, 'device': device, 'node': server,
          'status': status, 'latency_ms': latency_ms}
    ev.update(extra)
    return ev


def _write(path, events):
    with open(path, 'w') as f:
        for ev in events:
            f.write(json.dumps(ev) + '\n')
    return str(path)


def _arm(tmp_path, events, name=ARM_TREATMENT, **kwargs):
    path = _write(tmp_path / f'{name}.jsonl', events)
    return score_arm_interactions(name, path, **kwargs)


# --------------------------------------------------------------------------- #
# The pairing rule
# --------------------------------------------------------------------------- #
def test_pairs_each_report_with_its_own_route(tmp_path):
    arm = _arm(tmp_path, [
        _topology(devices={'iot1': 'none'}),
        _route(1.0, 'iot1', 'srv1', port=1), _report(1.1, 'iot1', 'srv1'),
        _route(2.0, 'iot1', 'srv2', port=2), _report(2.2, 'iot1', 'srv2'),
    ])
    assert [(p.routed_to, round(p.residence_ms)) for p in arm.pairings] == [
        ('srv1', 100), ('srv2', 200)]
    assert all(p.exact and p.sole_inflight for p in arm.pairings)


def test_a_dropped_report_does_not_offset_every_later_pairing(tmp_path):
    """The regression naive FIFO fails.

    iot1's srv1 task never reports. FIFO would then hand the srv2 report the
    srv1 route, the srv3 report the srv2 route, and so on for the rest of the
    run -- every later pairing wrong, and no signal that anything went wrong.
    """
    arm = _arm(tmp_path, [
        _topology(),
        _route(1.0, 'iot1', 'srv1', port=1),          # never reported
        _route(2.0, 'iot1', 'srv2', port=2), _report(2.1, 'iot1', 'srv2'),
        _route(3.0, 'iot1', 'srv3', port=3), _report(3.1, 'iot1', 'srv3'),
    ])
    assert [p.routed_to for p in arm.pairings] == ['srv2', 'srv3']
    assert [round(p.residence_ms) for p in arm.pairings] == [100, 100]
    assert all(p.exact for p in arm.pairings)
    assert [(a.node, a.reason) for a in arm.abandoned] == [('srv1', 'skipped')]


def test_a_static_arm_cannot_detect_the_same_drop_by_offset(tmp_path):
    """Under a static binding the skip-scan is blind, so age has to do it.

    Every outstanding route names srv1, so a wrong pairing still reports the
    right server and `skipped` stays empty however much was abandoned. The
    `task_timeout_s` sweep is the only evidence this arm can offer.
    """
    arm = _arm(tmp_path, [
        _topology(),
        _route(1.0, 'iot1', 'srv1', port=1),          # never reported
        _route(20.0, 'iot1', 'srv1', port=2), _report(20.1, 'iot1', 'srv1'),
    ], name=ARM_BASELINE)
    assert [a.reason for a in arm.abandoned] == ['aged_out']
    # ...and the surviving pairing is the SECOND task, timed from its own route.
    assert len(arm.pairings) == 1
    assert round(arm.pairings[0].residence_ms) == 100


def test_a_route_inside_the_reap_window_is_still_pairable(tmp_path):
    """The sweep must not reap a task that is merely slow.

    A client waits out `task_timeout_s` before it can report a timeout at all,
    so the report necessarily arrives after it. Reaping at the timeout itself
    would discard every timeout in the run -- which is the entire baseline
    availability finding.
    """
    arm = _arm(tmp_path, [
        _topology(),
        _route(1.0, 'iot1', 'srv1', port=1),
        _report(1.0 + DEFAULT_TASK_TIMEOUT_S + 0.2, 'iot1', 'srv1',
                status='timeout', latency_ms=4000.0),
    ])
    assert arm.abandoned == []
    assert [p.status for p in arm.pairings] == ['timeout']


def test_reroute_moves_the_task_to_where_it_landed(tmp_path):
    arm = _arm(tmp_path, [
        _topology(),
        _route(1.0, 'iot1', 'srv6', port=7),
        {'type': 'reroute', 'ts': T0 + 1.1, 'client_ip': '10.0.0.1',
         'client_port': 7, 'from_node': 'srv6', 'to_node': 'srv8',
         'resteer_ms': 12.0},
        _report(1.2, 'iot1', 'srv8'),
    ])
    assert len(arm.pairings) == 1
    p = arm.pairings[0]
    assert (p.routed_to, p.served_by, p.exact) == ('srv8', 'srv8', True)
    assert arm.abandoned == []
    assert arm.reroutes == 1


def test_a_repeated_flow_key_is_the_same_task_not_a_second_one(tmp_path):
    """A retransmitted SYN re-signals a route the controller already has.

    Queuing it twice would invent a task that never existed and then report it
    abandoned -- inflating both the route count and the loss count.
    """
    arm = _arm(tmp_path, [
        _topology(),
        _route(1.0, 'iot1', 'srv1', port=1),
        _route(1.05, 'iot1', 'srv1', port=1),          # same flow, re-signalled
        _report(1.2, 'iot1', 'srv1'),
    ])
    assert arm.duplicate_routes == 1
    assert arm.routes_total == 2          # both were real routing decisions...
    assert len(arm.pairings) == 1         # ...of one task
    assert arm.abandoned == []
    # Timed from the FIRST signal: that is when the task actually started.
    assert round(arm.pairings[0].residence_ms) == 200


def test_a_port_reused_after_the_window_is_a_new_task(tmp_path):
    arm = _arm(tmp_path, [
        _topology(),
        _route(1.0, 'iot1', 'srv1', port=1), _report(1.1, 'iot1', 'srv1'),
        _route(60.0, 'iot1', 'srv1', port=1), _report(60.1, 'iot1', 'srv1'),
    ])
    assert arm.duplicate_routes == 0
    assert len(arm.pairings) == 2


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #
def test_a_spoofed_report_is_keyed_to_the_socket_not_the_claim(tmp_path):
    """The baseline admits a spoofer, so `device` is not a safe queue key.

    iot38 reports as iot1 from its own IP. Keyed on the claim it would steal
    iot1's pairing and charge iot1's server with its outcome; keyed on the
    socket, the victim's pairing survives and the lie is counted.
    """
    arm = _arm(tmp_path, [
        _topology(devices={'iot1': 'none', 'iot38': 'spoof'}),
        _route(1.0, 'iot1', 'srv1', port=1),
        _report(1.1, 'iot1', 'srv1', source_ip='10.0.0.38'),   # the spoofer
        _report(1.2, 'iot1', 'srv1', source_ip='10.0.0.1'),    # the real iot1
    ], name=ARM_BASELINE)
    assert arm.contaminated_reports == 1
    assert arm.orphan_reports == 1        # the spoofer had nothing outstanding
    assert [p.client_ip for p in arm.pairings] == ['10.0.0.1']
    assert round(arm.pairings[0].residence_ms) == 200


def test_an_orphan_report_is_counted_not_dropped(tmp_path):
    arm = _arm(tmp_path, [_topology(), _report(1.0, 'iot1', 'srv1')])
    assert arm.orphan_reports == 1
    assert arm.pairings == []


def test_a_report_naming_no_known_device_is_counted_as_unresolved(tmp_path):
    arm = _arm(tmp_path, [_topology(), _report(1.0, 'gremlin', 'srv1')])
    assert arm.unresolved_reports == 1
    assert arm.orphan_reports == 0        # not the same failure, not merged


# --------------------------------------------------------------------------- #
# Concurrency
# --------------------------------------------------------------------------- #
def test_overlapping_tasks_are_flagged_and_kept_out_of_percentiles(tmp_path):
    """The flood client's own queue is the one place FIFO can still swap.

    `exact` and `sole_inflight` are separate on purpose: the join found the
    right server (exact), but with three in flight nothing proves WHICH of the
    three this report was. Folding the two together would report the flood
    client's concurrency as a pairing failure.
    """
    arm = _arm(tmp_path, [
        _topology(devices={'iot1': 'none', 'iot37': 'flood'}),
        _route(1.0, 'iot37', 'srv1', port=1),
        _route(1.1, 'iot37', 'srv1', port=2),
        _report(1.5, 'iot37', 'srv1'),
        _report(1.6, 'iot37', 'srv1'),
        _route(2.0, 'iot1', 'srv2', port=3), _report(2.1, 'iot1', 'srv2'),
    ])
    flood = [p for p in arm.pairings if p.device == 'iot37']
    honest = [p for p in arm.pairings if p.device == 'iot1']
    assert [p.exact for p in flood] == [True, True]
    assert [p.sole_inflight for p in flood] == [False, True]
    assert flood[0].queue_depth == 2
    # The honest client in the same recording is untouched by its neighbour.
    assert honest[0].sole_inflight and honest[0].trustworthy
    # ...and only the honest, sole-in-flight sample is quotable.
    assert speed_samples(arm, 'latency_ms') == [50.0]


def test_the_flood_client_is_excluded_from_honest_speed_but_still_reported(tmp_path):
    arm = _arm(tmp_path, [
        _topology(devices={'iot1': 'none', 'iot37': 'flood'}),
        _route(1.0, 'iot1', 'srv1', port=1),
        _report(1.1, 'iot1', 'srv1', latency_ms=10.0),
        _route(2.0, 'iot37', 'srv1', port=2),
        _report(2.1, 'iot37', 'srv1', latency_ms=999.0),
    ])
    assert speed_samples(arm, 'latency_ms', honest_only=True) == [10.0]
    assert sorted(speed_samples(arm, 'latency_ms', honest_only=False)) == [10.0, 999.0]


# --------------------------------------------------------------------------- #
# `None`, never 0
# --------------------------------------------------------------------------- #
def test_reroutes_is_none_in_an_arm_with_no_such_mechanism(tmp_path):
    arm = _arm(tmp_path, [_topology(), _route(1.0, 'iot1', 'srv1')],
               name=ARM_BASELINE)
    assert arm.reroutes is None, 'a mechanism that does not exist is not zero of it'
    assert pairing_audit(arm)['reroutes'] is None


def test_speed_stats_reports_none_not_zero_with_no_samples():
    s = speed_stats([])
    assert s['n'] == 0
    assert s['p50'] is None and s['p95'] is None and s['p99'] is None
    assert s['mean'] is None and s['max'] is None


def test_a_never_routed_client_is_none_not_a_perfect_share(tmp_path):
    """A client refused at admission has no dominant-server share.

    0.0 would read as "spread perfectly evenly", which is the opposite of what
    happened, and 1.0 would read as pinned. Only `None` is true.
    """
    arm = _arm(tmp_path, [
        _topology(devices={'iot1': 'none', 'iot39': 'bad_credentials'}),
        _route(1.0, 'iot1', 'srv1'), _report(1.1, 'iot1', 'srv1'),
        {'type': 'auth_denied', 'ts': T0 + 0.5, 'device_id': 'iot39',
         'kind': 'bad_credentials'},
    ])
    stab = binding_stability(arm)
    assert stab['10.0.0.1'] == 1.0
    assert stab['10.0.0.39'] is None
    assert fan_out(arm)['10.0.0.39'] == 0


def test_an_empty_bucket_reports_none_client_jain(tmp_path):
    arm = _arm(tmp_path, [_topology(), _route(1.0, 'iot1', 'srv1')],
               bucket_s=10.0)
    rows = [r for r in time_rows(arm) if r['node'] == 'srv2']
    assert rows and all(r['client_jain'] is None for r in rows)
    assert all(r['distinct_clients'] == 0 for r in rows)


# --------------------------------------------------------------------------- #
# Populations and denominators
# --------------------------------------------------------------------------- #
def test_a_refused_client_still_gets_a_row(tmp_path):
    """Never-routed clients must not vanish from the analysis.

    Dropping them would turn "we refused three hosts" into "there were only 37
    hosts", which is the denominator every fairness number here divides by.
    """
    arm = _arm(tmp_path, [
        _topology(devices={'iot1': 'none', 'iot39': 'bad_credentials'}),
        _route(1.0, 'iot1', 'srv1'), _report(1.1, 'iot1', 'srv1'),
    ])
    rows = {r['device']: r for r in client_rows(arm)}
    assert set(rows) == {'iot1', 'iot39'}
    assert rows['iot39']['total_routes'] == 0
    assert rows['iot39']['servers_routed'] == 0
    assert rows['iot39']['dominant_share'] is None
    audit = pairing_audit(arm)
    assert (audit['clients_in_topology'], audit['clients_routed']) == (2, 1)


def test_fan_out_is_one_per_client_under_a_static_binding(tmp_path):
    arm = _arm(tmp_path, [
        _topology(devices={f'iot{i}': 'none' for i in (1, 2, 3)}),
        *[e for i in (1, 2, 3) for e in (
            _route(i, f'iot{i}', f'srv{i}', port=i),
            _report(i + 0.1, f'iot{i}', f'srv{i}'))],
    ], name=ARM_BASELINE)
    assert set(fan_out(arm).values()) == {1}


def test_effective_fan_out_counts_a_server_reached_only_by_a_resteer(tmp_path):
    arm = _arm(tmp_path, [
        _topology(),
        _route(1.0, 'iot1', 'srv6', port=7),
        {'type': 'reroute', 'ts': T0 + 1.1, 'client_ip': '10.0.0.1',
         'client_port': 7, 'from_node': 'srv6', 'to_node': 'srv8'},
        _report(1.2, 'iot1', 'srv8'),
    ])
    assert fan_out(arm)['10.0.0.1'] == 1            # the selector only chose srv6
    assert effective_fan_out(arm)['10.0.0.1'] == 2  # but srv8 also served it


def test_abandoned_tasks_are_an_outcome_the_server_is_charged_with(tmp_path):
    """A task that never came back is an outcome the client lived through.

    Leaving it out of the denominator is exactly how a blackhole scores 100%.
    """
    arm = _arm(tmp_path, [
        _topology(attacks={'srv6': 'drop'}),
        _route(1.0, 'iot1', 'srv6', port=1),          # swallowed
        _route(2.0, 'iot1', 'srv2', port=2), _report(2.1, 'iot1', 'srv2'),
    ])
    counts = outcome_counts(arm)
    assert counts['srv6'] == {'success': 0, 'timeout': 0, 'failure': 0,
                              'abandoned': 1}
    assert counts['srv2']['success'] == 1


def test_held_time_is_not_charged_to_the_server(tmp_path):
    arm = _arm(tmp_path, [
        _topology(),
        _route(1.0, 'iot1', 'srv1', port=1),
        _report(3.0, 'iot1', 'srv1', held_for_s=1.5),
    ])
    assert round(arm.pairings[0].residence_ms) == 500     # 2000 ms - 1500 ms


# --------------------------------------------------------------------------- #
# Guards
# --------------------------------------------------------------------------- #
def test_occupancy_fields_are_never_read():
    """`observed_load`/`claimed_cpu` are not comparable across the two arms.

    The baseline's current recording integrated them over a 5 s window against
    the treatment arm's 3 s (README.md §7), so a figure built on them would
    compare two different measurements. `plot_load.py` refuses them for the
    same reason. AST, not grep, so the prose in the docstring explaining this
    does not trip the test.
    """
    for module in ('base_model/interactions.py', 'base_model/plot_interactions.py'):
        tree = ast.parse(Path(module).read_text())
        literals = {n.value for n in ast.walk(tree)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        assert 'observed_load' not in literals, module
        assert 'claimed_cpu' not in literals, module


def test_percentile_helper_is_the_repo_wide_one():
    """One percentile implementation, so two reports cannot disagree by method."""
    import base_model.interactions as mod
    from evaluation.nfr_report import _percentile
    assert mod._percentile is _percentile


def test_an_unparseable_tail_line_does_not_fail_the_run(tmp_path):
    path = tmp_path / 'truncated.jsonl'
    with open(path, 'w') as f:
        f.write(json.dumps(_topology()) + '\n')
        f.write(json.dumps(_route(1.0, 'iot1', 'srv1')) + '\n')
        f.write('{"type": "report", "device": "io')      # killed mid-write
    arm = score_arm_interactions(ARM_TREATMENT, str(path))
    assert arm.routes_total == 1


# --------------------------------------------------------------------------- #
# Re-steer attribution
# --------------------------------------------------------------------------- #
def test_a_survivor_is_not_charged_for_a_task_the_quarantined_node_lost(tmp_path):
    """The regression behind srv2's phantom timeouts.

    A blackhole swallows a task; it is quarantined; every stuck flow is
    re-steered onto one survivor; the client then times out and reports naming
    the SURVIVOR. Charging it there gives an honest server a wall of failures
    it had nothing to do with. The controller already says so -- `charged:
    False` and `resteered_from` -- and this tool must read that, not re-derive
    it from `report.node`.
    """
    arm = _arm(tmp_path, [
        _topology(attacks={'srv6': 'drop'}),
        _route(1.0, 'iot1', 'srv6', port=1),
        {'type': 'reroute', 'ts': T0 + 4.5, 'client_ip': '10.0.0.1',
         'client_port': 1, 'from_node': 'srv6', 'to_node': 'srv2'},
        _report(4.9, 'iot1', 'srv2', status='timeout', latency_ms=4000.0,
                charged=False, resteered_from='srv6', held_for_s=3.5),
    ])
    p = arm.pairings[0]
    assert p.routed_to == 'srv2', 'it really did land on srv2'
    assert p.blamed_on == 'srv6', 'but srv6 is what lost it'
    assert p.inherited and not p.trustworthy

    counts = outcome_counts(arm)
    assert counts['srv2']['timeout'] == 0, 'the survivor must not inherit the blame'
    assert counts['srv6']['timeout'] == 1

    row = next(iter(timeline_rows(arm)))
    assert (row['node'], row['blamed_on'], row['resteered_from']) == (
        'srv2', 'srv6', 'srv6')


def test_an_ordinary_report_is_charged_where_it_ran(tmp_path):
    """`charged: None` is an ordinary report, not an uncharged one."""
    arm = _arm(tmp_path, [
        _topology(),
        _route(1.0, 'iot1', 'srv2', port=1),
        _report(1.1, 'iot1', 'srv2', status='timeout', latency_ms=4000.0),
    ])
    p = arm.pairings[0]
    assert not p.inherited and p.blamed_on == 'srv2' and p.trustworthy
    assert outcome_counts(arm)['srv2']['timeout'] == 1
