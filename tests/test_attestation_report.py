"""evaluation/attestation_report.py against a synthetic recording whose answers
are known: who was admitted when, what was denied before the fleet was in,
which refusals were false, and how much work a misbehaving server was handed
before it was contained."""

import json

from evaluation import attestation_report as ar


def _write(tmp_path, events):
    path = tmp_path / 'r01.jsonl'
    with open(path, 'w') as fh:
        for ts, ev in events:
            fh.write(json.dumps({'ts': 1000.0 + ts, **ev}) + '\n')
    return str(path)


def _server(i, **kw):
    return {'id': f'srv{i}', 'kind': 'server', 'attack': 'none', 'attack_start_s': 0.0, **kw}


def _att(node, verdict, mismatched=()):
    return {'type': 'attestation', 'node': node, 'verdict': verdict, 'detail': '',
            'measurement': '', 'mismatched': list(mismatched), 'verify_ms': 0.3}


def test_scores_admission_refusals_and_exposure(tmp_path):
    nodes = [_server(1), _server(2), _server(3, tampered=True, attack='drop', attack_start_s=30.0)]
    ev = [(0.0, {'type': 'topology', 'graph': {'nodes': nodes}}),
          (4.0, {'type': 'route_denied'}),
          (5.0, _att('srv1', 'attested')),
          (5.5, {'type': 'route_denied'}),
          (6.0, _att('srv3', 'not_in_allowlist', ['simulation/node_agent.py'])),
          (6.5, _att('srv2', 'attested')),
          (7.0, {'type': 'route_denied'}),                 # after the fleet: not counted
          (8.0, {'type': 'route', 'chosen': 'srv1'}),
          (31.0, {'type': 'route', 'chosen': 'srv3'}),     # (impossible live; tests exposure)
          (35.0, {'type': 'route', 'chosen': 'srv3'}),
          (40.0, {'type': 'quarantine', 'node': 'srv3'}),
          (41.0, {'type': 'route', 'chosen': 'srv3'}),
          (50.0, _att('srv2', 'unmeasurable'))]
    r = ar.score(_write(tmp_path, ev), 'x')
    assert r.attesting and r.tampered == ['srv3'] and r.genuine == ['srv1', 'srv2']
    assert r.fleet_admitted_s == 6.5
    assert r.denied_before_fleet == 2 and len(r.denied) == 3
    assert [f[1:3] for f in r.false_refusals] == [('srv2', 'unmeasurable')]
    assert r.contained_s('srv3') == 10.0
    assert r.exposure('srv3') == 2
    text = ar.report({'x': [r]})
    assert "srv3 (tampered image)" in text and "not_in_allowlist ['simulation/node_agent.py']" in text


def test_attestation_off_run_reports_no_admission(tmp_path):
    ev = [(0.0, {'type': 'topology', 'graph': {'nodes': [_server(1)]}}),
          (2.0, {'type': 'route', 'chosen': 'srv1'})]
    r = ar.score(_write(tmp_path, ev), 'off')
    assert not r.attesting and r.fleet_admitted_s is None
    assert 'attestation off' in ar.report({'off': [r]})


def test_counts_quotes_that_arrive_during_a_quarantine(tmp_path):
    """Quarantine drops the server's traffic to the controller, the attester's
    included -- the scorer must be able to show that from a recording."""
    nodes = [_server(1, attack='drop', attack_start_s=30.0)]
    ev = [(0.0, {'type': 'topology', 'graph': {'nodes': nodes}}),
          (5.0, _att('srv1', 'attested')),              # before onset: not counted
          (35.0, _att('srv1', 'attested')),
          (40.0, {'type': 'quarantine', 'node': 'srv1'}),
          (45.0, _att('srv1', 'attested')),             # inside the quarantine
          (50.0, {'type': 'recovered', 'node': 'srv1'}),
          (51.0, _att('srv1', 'attested')),
          (90.0, {'type': 'route', 'chosen': 'srv1'})]  # run ends at 90 s
    r = ar.score(_write(tmp_path, ev), 'x')
    n, inside, frac = r.quotes_vs_quarantine('srv1')
    assert (n, inside) == (3, 1) and abs(frac - 10.0 / 60.0) < 1e-9
    assert 'of which 1 arrived while it was quarantined' in ar.report({'x': [r]})
