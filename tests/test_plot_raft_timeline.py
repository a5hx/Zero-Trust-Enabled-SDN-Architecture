"""Tests for the analysis behind evaluation/plot_raft_timeline.py.

The multi-process failover run itself is driven by hand
(`python3 -m blockchain.raft_timeline`), same discipline as
tests/test_raft_demo.py. What is tested here is everything that turns the
resulting recording into claims -- because a defect in any of it produces a
figure that is wrong rather than a figure that fails, and a wrong figure is
the one failure mode nobody catches by looking.
"""

import json

from evaluation.plot_raft_timeline import (
    Recording, _series_with_gaps, commit_outage, leader_changes,
    load_recording, phase_latencies, phases, role_runs, summarise,
)


def _status(t, node, role, term=1, chain=0):
    return {'type': 'status', 't': t, 'node': node, 'role': role, 'term': term,
            'leader_id': None, 'commit_index': chain, 'chain_length': chain}


def _rec():
    """A recording shaped like a real run: n2 leads, is killed, n1 takes over."""
    rec = Recording(meta={'node_ids': ['n1', 'n2', 'n3'], 'poll_interval_s': 0.05})
    rec.statuses = [
        _status(0.0, 'n1', 'follower', 2, 10), _status(0.0, 'n2', 'leader', 2, 10),
        _status(0.0, 'n3', 'follower', 2, 10),
        _status(1.0, 'n1', 'follower', 2, 20), _status(1.0, 'n2', 'leader', 2, 20),
        _status(1.0, 'n3', 'follower', 2, 20),
        # n2 killed at t=1.5
        _status(2.0, 'n1', 'leader', 3, 30),
        _status(2.0, 'n2', 'down', None, None),
        _status(2.0, 'n3', 'follower', 3, 30),
        _status(3.0, 'n1', 'leader', 3, 40),
        _status(3.0, 'n2', 'down', None, None),
        _status(3.0, 'n3', 'follower', 3, 40),
    ]
    rec.commits = [
        {'type': 'commit', 't': 1.0, 'ok': True, 'outcome': 'ok', 'latency_ms': 2.0},
        {'type': 'commit', 't': 1.6, 'ok': False, 'outcome': 'unreachable', 'latency_ms': 0.4},
        {'type': 'commit', 't': 2.0, 'ok': True, 'outcome': 'ok', 'latency_ms': 4.0},
        {'type': 'commit', 't': 3.0, 'ok': True, 'outcome': 'ok', 'latency_ms': 6.0},
    ]
    rec.kills = [{'type': 'kill', 't': 1.5, 'node': 'n2', 'signal': 'SIGTERM'}]
    rec.elections = [{'type': 'leader_elected', 't': 1.8, 'node': 'n1',
                      'after_kill_s': 0.3, 'replaced': 'n2'}]
    return rec


def test_load_recording_sorts_rows_into_their_kinds(tmp_path):
    path = tmp_path / 'r.jsonl'
    rows = [{'type': 'meta', 't': 0.0, 'node_ids': ['n1']},
            _status(0.1, 'n1', 'leader'),
            {'type': 'commit', 't': 0.2, 'ok': True, 'latency_ms': 1.0},
            {'type': 'kill', 't': 0.3, 'node': 'n1'},
            {'type': 'leader_elected', 't': 0.4, 'node': 'n1'},
            {'type': 'restart', 't': 0.5, 'node': 'n1'}]
    path.write_text('\n'.join(json.dumps(r) for r in rows) + '\n')

    rec = load_recording(str(path))
    assert rec.meta['node_ids'] == ['n1']
    assert len(rec.statuses) == len(rec.commits) == 1
    assert len(rec.kills) == len(rec.elections) == len(rec.restarts) == 1


def test_role_runs_end_a_run_at_the_next_sample_not_the_last_one_matching():
    # The transition happened somewhere between the two samples; claiming it at
    # the earlier instant would assert precision the polling does not have.
    runs = role_runs(_rec().statuses, 'n2', t_end=3.0)
    leader_run = [r for r in runs if r[2] == 'leader'][0]
    assert leader_run[0] == 0.0
    assert leader_run[1] == 2.0        # the first sample that saw it down
    assert [r[2] for r in runs] == ['leader', 'down']


def test_role_runs_split_when_the_term_changes_under_an_unchanged_role():
    statuses = [_status(0.0, 'n3', 'follower', 2), _status(1.0, 'n3', 'follower', 3)]
    runs = role_runs(statuses, 'n3', t_end=2.0)
    assert [(r[2], r[3]) for r in runs] == [('follower', 2), ('follower', 3)]


def test_series_with_gaps_puts_nan_where_the_node_was_down():
    # The NaN is what stops matplotlib joining the value before the kill to the
    # value after the restart across an interval the node did not exist for.
    xs, ys = _series_with_gaps(_rec().statuses, 'n2', 'chain_length')
    assert xs == [0.0, 1.0, 2.0, 3.0]
    assert ys[:2] == [10.0, 20.0]
    assert all(y != y for y in ys[2:])          # NaN != NaN


def test_leader_changes_reports_each_new_leader_once():
    changes = leader_changes(_rec().statuses)
    assert [(c[1], c[2]) for c in changes] == [('n2', 2), ('n1', 3)]


def test_commit_outage_brackets_the_kill_with_real_commits():
    last_ok, first_ok = commit_outage(_rec().commits, kill_t=1.5)
    assert (last_ok, first_ok) == (1.0, 2.0)


def test_commit_outage_returns_none_rather_than_inventing_a_boundary():
    assert commit_outage([], kill_t=1.0) == (None, None)
    only_before = [{'t': 0.5, 'ok': True}]
    assert commit_outage(only_before, kill_t=1.0) == (0.5, None)


def test_phases_are_named_by_how_many_replicas_were_running():
    rec = _rec()
    rec.restarts = [{'type': 'restart', 't': 2.5, 'node': 'n2'}]
    labels = [label for label, _, _ in phases(rec)]
    assert labels[0].startswith('3 of 3 up')
    assert labels[1].startswith('2 of 3 up')
    assert labels[2].startswith('3 of 3 up')
    assert [t0 for _, t0, _ in phases(rec)] == [0.0, 1.5, 2.5]


def test_phase_latencies_only_count_successful_commits():
    by_label = {label: lat for label, _, _, lat in phase_latencies(_rec())}
    assert by_label['3 of 3 up'] == [2.0]                    # the failed 1.6s attempt
    assert by_label['2 of 3 up (n2 killed)'] == [4.0, 6.0]   # is not a latency


def test_summarise_states_the_failover_and_the_service_gap():
    text = '\n'.join(summarise(_rec()))
    assert 'n2 (SIGTERM) at t=1.50 s' in text
    assert 'n1 after 0.30 s' in text
    assert '+/- 0.05 s polling' in text      # the resolution must be disclosed
    assert 'commit service gap  : 1.00 s' in text
    assert '1 unreachable' in text
