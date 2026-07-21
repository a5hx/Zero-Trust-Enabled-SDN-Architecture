"""Regression tests for dashboard/generate_demo_recording.py.

This generator drives the real TrustState/FlowMonitor with scripted telemetry.
It had silently broken once already (a Week-1 change made _fetch_status return a
StatusProbe, which the scripted monitor did not), and nothing caught it because
there was no test. These assert the recording still produces the events the
dashboard needs: routing, a quarantine, drop rules, and optimizer windows.
"""

import random

from dashboard.generate_demo_recording import Sim


def _run():
    random.seed(7)
    return Sim().run()


def test_recording_tells_the_full_story():
    events = _run()
    kinds = {}
    for e in events:
        kinds[e['type']] = kinds.get(e['type'], 0) + 1
    # The arc: switches connect, traffic is routed, the sybil node is caught and
    # its VIP rules deleted.
    assert kinds.get('route', 0) > 10
    assert kinds.get('quarantine', 0) >= 1
    assert kinds.get('flow_delete', 0) >= 1
    assert kinds.get('node_status', 0) >= 1


def test_recording_emits_drop_rules_for_quarantined_node():
    events = _run()
    drop_rules = [
        r for e in events if e['type'] == 'flow_stats'
        for r in e['rules'] if 'drop' in r.get('actions', '')
    ]
    assert drop_rules, "expected drop rules once a node is quarantined"
    # Drop rules are priority-400, action=drop, and their packet count climbs.
    assert all(r['priority'] == 400 for r in drop_rules)
    counts = [r['packets'] for r in drop_rules]
    assert counts[-1] > counts[0]


def test_recording_emits_optimizer_windows_with_arm_stats():
    events = _run()
    opt = [e for e in events if e['type'] == 'optimizer']
    assert len(opt) > 5, "expected several optimizer windows"
    first = opt[0]
    assert set(first['conditions']) == {
        'mean_trust', 'mean_load', 'mean_latency_ms', 'num_quarantined',
    }
    # Each event is self-contained for the replay panel: all five arms, with the
    # pull counts and mean rewards the dashboard renders.
    assert len(first['arms']) == 5
    assert {'arm', 'weights', 'count', 'mean_reward', 'active'} <= set(first['arms'][0])
    # Exactly one arm is active at a time.
    assert sum(1 for a in opt[-1]['arms'] if a['active']) == 1
    # The bandit actually explored: every arm gets pulled at least once.
    assert all(a['count'] >= 1 for a in opt[-1]['arms'])
