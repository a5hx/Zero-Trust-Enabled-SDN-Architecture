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


# --------------------------------------------------------------------------- #
# Fidelity to the real controller's flow-rule scheme.
#
# The generator hand-writes flow_stats rules that a real run would get from
# OFPFlowStats, so its priorities/cookies/is_vip flags are only as correct as
# whoever typed them. Three separate mistakes were found here at once (2026-08-07),
# each of which silently produced a plausible-looking but wrong chart rather than
# an error:
#
#   * the SERVING VIP rule was emitted at priority 400 -- PRIO_QUARANTINE_DROP --
#     so every consumer that tells serving from dropping by priority read it
#     backwards: throughput was a flat zero and the serving rule's packets were
#     tallied as quarantine drops;
#   * the drop rule was marked is_vip=False, and since every consumer filters on
#     is_vip first, the OpenFlow-drop series was unreachable;
#   * serving and drop rules used different cookie bases (0x51 / 0x5A), which no
#     real run produces -- one cookie per node is the mechanism quarantine uses
#     to delete all of a node's rules at once.
#
# These pin the generator against the REAL constants so it cannot drift again.
# --------------------------------------------------------------------------- #

def _vip_rules(events):
    return [
        (e, r) for e in events if e['type'] == 'flow_stats'
        for r in e.get('rules', [])
    ]


def test_serving_vip_rules_do_not_use_the_quarantine_drop_priority():
    from controller.trust_balancer import TrustBalancerApp

    for _e, r in _vip_rules(_run()):
        if r.get('actions', '').startswith('drop'):
            continue
        if r.get('node') is None:
            continue                     # infrastructure rule (ARP punt)
        assert r['priority'] != TrustBalancerApp.PRIO_QUARANTINE_DROP, (
            'a SERVING rule is advertising itself at the drop priority; '
            'throughput will read as zero and its packets as drops'
        )
        assert r['priority'] == TrustBalancerApp.PRIO_CONNECTION


def test_quarantine_drop_rules_use_the_drop_priority():
    from controller.trust_balancer import TrustBalancerApp

    drops = [r for _e, r in _vip_rules(_run())
             if r.get('actions', '').startswith('drop')]
    assert drops, 'the recording should contain quarantine drop rules'
    for r in drops:
        assert r['priority'] == TrustBalancerApp.PRIO_QUARANTINE_DROP


def test_is_vip_agrees_with_the_real_cookie_test():
    """The strongest pin: the hand-set is_vip flag must match what the real
    FlowStatsPoller would derive from the rule's own cookie."""
    from controller.flow_stats import FlowStatsPoller

    for _e, r in _vip_rules(_run()):
        derived = FlowStatsPoller._is_vip_cookie(r['cookie'])
        assert derived == r['is_vip'], (
            f"rule {r['match']!r} claims is_vip={r['is_vip']} but its cookie "
            f"{r['cookie']:#x} derives {derived}"
        )


def test_a_quarantined_node_produces_countable_openflow_drops():
    """End-to-end: the drop series must be reachable, not silently filtered out.

    Mirrors how evaluation/interval_report.py and the dashboard chart select
    drop rules -- is_vip first, then the drop priority.
    """
    from controller.trust_balancer import TrustBalancerApp

    counted = [
        r for _e, r in _vip_rules(_run())
        if r.get('is_vip') and r['priority'] == TrustBalancerApp.PRIO_QUARANTINE_DROP
    ]
    assert counted, 'quarantine drop rules are being filtered out before counting'
    assert max(r['packets'] for r in counted) > 0
