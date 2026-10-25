"""evaluation/ledger_report.py against a synthetic recording with known
answers: which rejections are correct, which are false, what is unaccounted."""

import json

from evaluation import ledger_report as lr


def _write(tmp_path, events):
    path = tmp_path / 'r01.jsonl'
    with open(path, 'w') as fh:
        for t, ev in events:
            fh.write(json.dumps({'ts': 1000.0 + t, **ev}) + '\n')
    return str(path)


def _rep(node, charged=True):
    ev = {'type': 'report', 'node': node, 'status': 'success'}
    if not charged:
        ev['charged'] = False
    return ev


def _rej(t, node, reason='after_mismatch'):
    return {'type': 'ledger_rejected', 'node': node, 'reason': reason, 'update_ts': 1000.0 + t}


def test_scores_rejections_against_the_forgery(tmp_path):
    graph = {'nodes': [{'id': 'srv3', 'kind': 'server', 'attack': 'drop', 'attack_start_s': 60}],
             'controller_forgery': {'node': 'srv3', 'mode': 'score', 'start_s': 60},
             'ledger_verify': True}
    ev = [(0, {'type': 'topology', 'graph': graph}),
          (10, _rep('srv3')), (20, _rep('srv1')), (30, _rep('srv1', charged=False)),
          (59.5, _rep('srv3')),                              # ambiguous: within 1 s of onset
          (61, _rep('srv3')), (62, _rep('srv3')), (63, _rep('srv2')),
          (61, _rej(61, 'srv3')), (62, _rej(62, 'srv3')),    # correct
          (59.5, _rej(59.5, 'srv3')),                        # ambiguous: neither
          (63, _rej(63, 'srv2', 'before_mismatch')),         # false
          (64, {'type': 'block', 'accepted': True, 'records': 2, 'commit_ms': 4.0}),
          (65, {'type': 'quarantine', 'node': 'srv3'}),
          (70, {'type': 'witness', 'servers': ['srv3']})]
    r = lr.score(_write(tmp_path, ev), 'x')
    assert r.verify and (r.forged_node, r.forge_mode, r.forge_start) == ('srv3', 'score', 60.0)
    assert len(r.records) == 6                               # the uncharged report wrote none
    assert (r.target_records, r.caught) == (2, 2)
    assert [x[1:] for x in r.false_rejections] == [('srv2', 'before_mismatch')]
    assert r.unaccounted == 6 - 2 - 4
    assert r.contained_s('srv3') == 5.0 and r.witness_s('srv3') == 10.0
    text = lr.report({'x': [r]})
    assert 'forged-server records rejected   : 2/2' in text


def test_no_forgery_no_verification(tmp_path):
    ev = [(0, {'type': 'topology', 'graph': {'nodes': []}}), (5, _rep('srv1')),
          (6, {'type': 'block', 'accepted': True, 'num_updates': 1, 'commit_ms': 3.0})]
    r = lr.score(_write(tmp_path, ev), 'y')
    assert not r.verify and r.forged_node is None and r.unaccounted == 0
    assert 'replicas verify: no' in lr.report({'y': [r]})
