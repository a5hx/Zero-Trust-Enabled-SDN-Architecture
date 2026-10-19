"""evaluation/replicates.py -- between-run intervals over repeated live runs."""

import json

import pytest

pytest.importorskip('scipy')

from evaluation.replicates import (  # noqa: E402
    attribute_rail,
    check_arm_labels, discover, main, score_run, t_interval, wilson,
)


def _recording(path, *, sybil_gate: bool, rail_enforced=True, theta=None,
               sybil_floor=None):
    """A 60 s run: srv1 honest, srv2 a sybil from t=10 s.

    If `sybil_gate`, srv2 is quarantined at t=15 with A-bar over the gate and
    T well above theta (the gate fired); otherwise its T sinks under theta at
    t=40 and the score quarantines it there.
    """
    t0 = 1000.0
    evs = [{'type': 'topology', 'ts': t0, 'graph': {'nodes': [
        {'kind': 'server', 'id': 'srv1', 'attack': 'none'},
        {'kind': 'server', 'id': 'srv2', 'attack': 'sybil', 'attack_start_s': 10.0},
        {'kind': 'iot', 'id': 'iot1', 'attack': 'none', 'ip': '10.0.0.1'},
    ]}}]
    if theta is not None:
        evs[0]['graph']['thresholds'] = {'isolation': theta, 'anomaly_gate': 0.5,
                                         'anomaly_rail_enforced': rail_enforced}
    for t in range(0, 61, 5):
        t2 = 0.8 if (sybil_gate or t < 40) else 0.2
        if sybil_floor is not None and t >= 15:
            t2 = sybil_floor        # a liar that floors above theta=0.30
        evs.append({'type': 'node_status', 'ts': t0 + t, 'nodes': {
            'srv1': {'trust': 0.8, 'anomaly': 0.0},
            'srv2': {'trust': t2, 'anomaly': 0.9 if t >= 15 else 0.0}}})
        evs.append({'type': 'route', 'ts': t0 + t, 'chosen': 'srv1'})
        evs.append({'type': 'report', 'ts': t0 + t, 'status': 'success',
                    'node': 'srv1', 'device': 'iot1', 'latency_ms': 20.0})
    q_t, q_trust, q_anom = (15, 0.8, 0.9) if sybil_gate else (40, 0.2, 0.0)
    evs.append({'type': 'quarantine', 'ts': t0 + q_t, 'node': 'srv2',
                'trust': q_trust, 'anomaly': q_anom, 'anomaly_gate': 0.5,
                'anomaly_rail_enforced': rail_enforced})
    evs.sort(key=lambda e: e['ts'])
    path.write_text(''.join(json.dumps(e) + '\n' for e in evs))


def test_t_interval_and_wilson():
    mean, sd, lo, hi = t_interval([1.0, 2.0, 3.0])
    assert mean == 2.0 and sd == 1.0
    assert lo == pytest.approx(2.0 - 4.302653 / 3 ** 0.5, rel=1e-5)
    assert t_interval([5.0])[1:] == (None, None, None)   # one run has no spread
    lo, hi = wilson(0, 5)
    assert lo == 0.0 and 0.4 < hi < 0.5                   # not the degenerate [0, 0]


def test_gate_quarantine_is_attributed_to_the_gate(tmp_path):
    p = tmp_path / 'r01.jsonl'
    _recording(p, sybil_gate=True)
    run = score_run('treat', str(p))
    a = run.attackers['srv2']
    assert a.rail == 'gate' and a.contain_s == pytest.approx(5.0)
    assert a.t_at_q == 0.8
    assert a.score_cross_s is None          # the score never got there
    assert run.honest_quarantined == []


def test_score_quarantine_and_crossing_time(tmp_path):
    p = tmp_path / 'r01.jsonl'
    _recording(p, sybil_gate=False, rail_enforced=False)
    run = score_run('scoreonly', str(p))
    a = run.attackers['srv2']
    assert a.rail == 'score'
    assert a.score_cross_s == pytest.approx(30.0)   # t=40 minus onset 10
    assert run.rail_enforced is False


def test_misfiled_recording_is_reported(tmp_path):
    for arm, gate, enforced in (('treat', False, False), ('scoreonly', True, True)):
        d = tmp_path / 'runs' / arm
        d.mkdir(parents=True)
        _recording(d / 'r01.jsonl', sybil_gate=gate, rail_enforced=enforced)
    arms = discover(tmp_path / 'runs')
    assert list(arms) == ['scoreonly', 'treat']       # report order, not alpha
    results = {arm: [score_run(arm, str(p)) for p in ps] for arm, ps in arms.items()}
    assert len(check_arm_labels(results)) == 2
    assert main([str(tmp_path / 'runs'), '--out-dir', str(tmp_path / 'out')]) == 2
    assert (tmp_path / 'out' / 'per_attacker.csv').exists()


def test_a_quarantine_before_onset_is_a_false_positive_not_containment(tmp_path):
    """Run 9: srv8 quarantined 4.9 s before its onset. That must not be
    reported as negative containment latency."""
    p = tmp_path / 'r01.jsonl'
    _recording(p, sybil_gate=True)
    lines = [json.loads(l) for l in p.read_text().splitlines()]
    lines.append({'type': 'quarantine', 'ts': 1005.0, 'node': 'srv2', 'trust': 0.8,
                  'anomaly': 0.9, 'anomaly_gate': 0.5, 'anomaly_rail_enforced': True})
    lines.sort(key=lambda e: e['ts'])
    p.write_text(''.join(json.dumps(e) + '\n' for e in lines))
    run = score_run('treat', str(p))
    a = run.attackers['srv2']
    assert a.pre_onset_quarantines == 1
    assert a.contain_s == pytest.approx(5.0)     # the post-onset one, not -5
    assert run.metrics['pre_onset_quarantines'] == 1.0


class TestThetaSweep:
    """A sweep run must be scored against the theta it ran with, not the
    report's default -- otherwise a run at 0.45 would have its crossings and
    rails judged against 0.30 and the sweep would measure nothing."""

    def test_recorded_theta_overrides_the_default(self, tmp_path):
        p = tmp_path / 'r01.jsonl'
        _recording(p, sybil_gate=True, rail_enforced=False, theta=0.45, sybil_floor=0.41)
        run = score_run('scoreonly_t045', str(p), theta=0.30)
        assert run.theta == 0.45 and run.theta_recorded
        assert run.attackers['srv2'].score_cross_s == pytest.approx(5.0)   # 0.41 < 0.45
        # ...and the same recording judged at 0.30 would never have crossed:
        p2 = tmp_path / 'r02.jsonl'
        _recording(p2, sybil_gate=True, rail_enforced=False, sybil_floor=0.41)
        assert score_run('scoreonly', str(p2)).attackers['srv2'].score_cross_s is None

    def test_rail_attribution_uses_the_recorded_theta(self, tmp_path):
        # A liar quarantined at T=0.41 in a run at theta 0.45 was isolated by
        # the score. Judged against 0.30 it would read 'indeterminate'.
        p = tmp_path / 'r01.jsonl'
        _recording(p, sybil_gate=False, rail_enforced=False, theta=0.45)
        lines = [json.loads(l) for l in p.read_text().splitlines()]
        for e in lines:
            if e['type'] == 'quarantine':
                e['trust'] = 0.41
        p.write_text(''.join(json.dumps(e) + '\n' for e in lines))
        assert score_run('scoreonly_t045', str(p), theta=0.30).attackers['srv2'].rail == 'score'
        assert attribute_rail(False, 0.41, 0.0, 0.30, 0.5) == 'indeterminate'

    def test_a_sweep_run_at_the_wrong_theta_is_reported(self, tmp_path):
        d = tmp_path / 'runs' / 'scoreonly_t045'
        d.mkdir(parents=True)
        _recording(d / 'r01.jsonl', sybil_gate=False, rail_enforced=False, theta=0.40)
        _recording(d / 'r02.jsonl', sybil_gate=False, rail_enforced=False)  # no theta
        results = {a: [score_run(a, str(p)) for p in ps]
                   for a, ps in discover(tmp_path / 'runs').items()}
        problems = check_arm_labels(results)
        assert any('ran at theta 0.40' in p for p in problems)
        assert any('records no theta' in p for p in problems)

    def test_what_if_predicts_from_recorded_trust(self, tmp_path):
        d = tmp_path / 'runs' / 'scoreonly'
        d.mkdir(parents=True)
        _recording(d / 'r01.jsonl', sybil_gate=True, rail_enforced=False,
                   theta=0.30, sybil_floor=0.41)
        out = tmp_path / 'out'
        assert main([str(tmp_path / 'runs'), '--out-dir', str(out),
                     '--what-if', '0.40,0.45']) == 0
        text = (out / 'summary.txt').read_text()
        rows = {l.split()[0]: l.split()[1:] for l in text.splitlines()
                if l.strip().startswith(('0.40', '0.45'))}
        assert rows['0.40'] == ['0/1', '0/1']     # srv2 floors at 0.41; honest at 0.8
        assert rows['0.45'] == ['1/1', '0/1']


class TestRailAttribution:
    """The rail a quarantine is credited to decides the paper's central table,
    so the attribution has to survive the two ways it was previously wrong.
    These call the real function the scorer calls, never a copy of its rule."""

    def test_an_unenforced_gate_never_takes_the_credit(self):
        # The score-only arm's grayhole quarantines carry A-bar ~ 1.0 next to
        # T < theta. The gate is switched off there, so the score fired.
        assert attribute_rail(False, 0.2709, 1.0, 0.3, 0.5) == 'score'
        assert attribute_rail(False, 0.2083, 0.9775, 0.3, 0.5) == 'score'

    def test_both_rails_qualifying_is_reported_as_both(self):
        # Crediting the gate here would overstate it: the score would have
        # isolated this node unaided.
        assert attribute_rail(True, 0.105, 0.85, 0.3, 0.5) == 'both'

    def test_the_gate_alone_is_the_sybil_and_onoff_case(self):
        # The measurement the score-floor proposition predicts: quarantined
        # well above theta, so only the gate can have done it.
        assert attribute_rail(True, 0.7028, 0.85, 0.3, 0.5) == 'gate'
        assert attribute_rail(True, 0.8054, 0.85, 0.3, 0.5) == 'gate'

    def test_the_score_alone_is_the_blackhole_case(self):
        assert attribute_rail(True, 0.209, 0.0, 0.3, 0.5) == 'score'

    def test_an_unknown_rail_setting_defaults_to_enforced(self):
        # Recordings predating the flag are the enforced arm.
        assert attribute_rail(None, 0.7, 0.85, 0.3, 0.5) == 'gate'

    def test_a_straddling_sample_is_not_guessed(self):
        assert attribute_rail(True, 0.7, 0.1, 0.3, 0.5) == 'indeterminate'
