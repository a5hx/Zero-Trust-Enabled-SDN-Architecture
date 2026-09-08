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


# --------------------------------------------------------------------- #
# Fidelity of the scripted node telemetry                               #
# --------------------------------------------------------------------- #
# Same class of defect as the three flow_stats field mismatches above and in
# panel_fix.md §6.3: a field the generator hand-writes that does not match what
# a real agent sends, producing a plausible-looking wrong result rather than an
# error.

def test_scripted_status_sends_the_same_fields_a_real_agent_does():
    """The scripted /status must carry busy_seconds.

    Every real simulation/node_agent.py sends it. Without it the controller
    silently falls back to comparing the CPU claim against observed_load --
    residence time instead of service time -- which is the documented cause of
    this project's false quarantines (memory/live-run-7-honesty-fallback). The
    recording drove that fallback on every poll until this was fixed.
    """
    random.seed(7)
    sim = Sim()
    status = sim.status_for('srv1')
    for field in ('cpu_load', 'latency_ms', 'concurrency', 'busy_seconds'):
        assert field in status, f'scripted /status is missing {field}'


def test_busy_seconds_is_cumulative_and_monotonic():
    # node_agent.py's _busy_seconds_total is never reset; a consumer that diffs
    # it between polls would read a negative rate if it ever went backwards.
    random.seed(7)
    sim = Sim()
    seen = 0.0
    for _ in range(20):
        sim._pending[('10.0.0.1', len(sim._pending) + 1)] = ('srv1', 99.0)
        sim._accrue_busy(0.25)
        now = sim.status_for('srv1')['busy_seconds']
        assert now >= seen, 'busy_seconds went backwards'
        seen = now
    assert seen > 0.0


def test_the_liar_is_self_consistent():
    """The Sybil's busy_seconds must be derived from its false CPU claim.

    A liar that reported a truthful duty cycle alongside a false CPU load would
    be caught by an arithmetic check no real attacker would fail, which would
    make the detection look far easier than it is. node_agent.py computes
    busy_seconds = uptime * cpu_load * concurrency while armed, and so does the
    generator.
    """
    from dashboard.generate_demo_recording import (
        CONCURRENCY, SYBIL_NODE, SYBIL_START_S,
    )
    random.seed(7)
    sim = Sim()
    sim.clock.t = SYBIL_START_S + 10.0
    # Give the liar real work it does not admit to.
    for k in range(CONCURRENCY):
        sim._pending[('10.0.0.1', k)] = (SYBIL_NODE, 999.0)
    sim._accrue_busy(5.0)

    st = sim.status_for(SYBIL_NODE)
    assert st['cpu_load'] < 0.25, 'the Sybil must claim to be near-idle'
    expected = sim.clock.t * st['cpu_load'] * CONCURRENCY
    assert abs(st['busy_seconds'] - expected) < 1e-6, (
        'busy_seconds must follow the lie, not the real work'
    )


def test_the_liar_is_slow_regardless_of_its_task_load():
    """The latency tell is load-INDEPENDENT (flow_monitor.evaluate_latency_tell:
    a burning CPU replies slowly 'no matter how little task traffic it
    receives'). If the Sybil's RTT tracked its occupancy it would drop back to
    baseline whenever p2c routed around it, the tell would never reach
    latency_liar_persist consecutive strikes, and the recording would contain
    no detection at all."""
    from dashboard.generate_demo_recording import SYBIL_NODE, SYBIL_START_S
    random.seed(7)
    sim = Sim()
    sim.clock.t = SYBIL_START_S + 1.0

    idle = [sim.status_for(SYBIL_NODE)['latency_ms'] for _ in range(30)]
    sim._pending[('10.0.0.1', 1)] = (SYBIL_NODE, 999.0)
    busy = [sim.status_for(SYBIL_NODE)['latency_ms'] for _ in range(30)]

    assert min(idle) > 90.0, 'the Sybil must be slow even with no tasks'
    assert min(busy) > 90.0

    # ...and an honest node must stay near the fleet baseline, or the median
    # the tell measures against rises far enough to mask the liar.
    honest = [sim.status_for('srv1')['latency_ms'] for _ in range(30)]
    assert max(honest) < min(idle), (
        'an honest node must never be as slow as the liar'
    )


def test_only_the_configured_attacker_is_quarantined():
    """No honest node may be quarantined in the demo recording.

    This project has twice shipped a defect whose entire signature was honest
    nodes wrongly quarantined (memory/live-run-cascading-quarantine,
    memory/quarantine-absorbing-state), and a recording that reproduces it
    would put that on a projector as if it were the system working.
    """
    from dashboard.generate_demo_recording import SYBIL_NODE
    events = _run()
    quarantined = {e['node'] for e in events if e['type'] == 'quarantine'}
    assert quarantined == {SYBIL_NODE}, (
        f'expected only {SYBIL_NODE} to be quarantined, got {sorted(quarantined)}'
    )


def test_a_quarantine_re_steers_the_pending_clients():
    """The recording must contain 'reroute' events.

    Without them the routing-reliability chart's "decisions that held" series
    reads a flat 100% on a run where a node was quarantined with work in
    flight -- true of the recording but not of the system it depicts.
    """
    events = _run()
    reroutes = [e for e in events if e['type'] == 'reroute']
    assert reroutes, 'a quarantine with pending dispatches must re-steer them'
    for e in reroutes:
        assert e['from_node'] != e['to_node']
        assert e['to_node'] not in {
            q['node'] for q in events
            if q['type'] == 'quarantine' and q['ts'] <= e['ts']
        }, 'never re-steer onto an already-quarantined node'


def test_topology_links_carries_the_link_parameters():
    """The harness's POST /topology/links, in recorded form.

    'topology' must stay parameter-free (a live controller publishes it from
    config before Mininet exists and cannot know what was built), and the
    later 'topology_links' event must carry delay_ms/bw_mbps.
    """
    events = _run()
    plain = [e for e in events if e['type'] == 'topology']
    enriched = [e for e in events if e['type'] == 'topology_links']
    assert len(plain) == 1 and len(enriched) == 1
    assert plain[0]['ts'] <= enriched[0]['ts']

    assert not any('delay_ms' in lk for lk in plain[0]['graph']['links'])
    links = enriched[0]['graph']['links']
    assert links and all('delay_ms' in lk and 'bw_mbps' in lk for lk in links)

    # The IoT link delay is the one quantity with any spread; a uniform column
    # would make "distance to sink" a constant and say nothing.
    iot_delays = {lk['delay_ms'] for lk in links if lk['kind'] == 'iot_link'}
    assert len(iot_delays) > 1, 'per-device link delay must vary'
