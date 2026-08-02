"""Tests for controller/flow_monitor.py -- the 1Hz anomaly-detection loop.

_fetch_status is monkeypatched in every test here rather than hitting real
HTTP, so these run with no Mininet/network dependency at all.
"""

from controller.flow_monitor import FlowMonitor, StatusProbe
from controller.trust_state import TrustState


def _as_probe(value):
    """Wrap a test's status value into the StatusProbe _fetch_status returns.

    Accepts None (unreachable), a bare payload dict (RTT defaulted), or an
    explicit StatusProbe when a test needs to pin the measured RTT.
    """
    if value is None:
        return StatusProbe(None, None)
    if isinstance(value, StatusProbe):
        return value
    return StatusProbe(value, 30.0)


def _make_monitor(state, statuses, threshold=0.40):
    quarantined = []
    fm = FlowMonitor(
        state=state, node_ids=list(statuses.keys()), agent_port=8000,
        poll_interval_s=1.0, honesty_deviation_threshold=threshold,
        on_quarantine=quarantined.append,
    )
    fm._fetch_status = lambda node_id: _as_probe(statuses[node_id])
    return fm, quarantined


def test_honest_node_stays_clear():
    state = TrustState(node_ids=['srv1'])
    state.set_concurrency('srv1', 4)
    # No dispatches registered -> observed_load is 0.0; an honest node's
    # claim should land close to that, well inside the deviation threshold.
    fm, quarantined = _make_monitor(state, {
        'srv1': {'cpu_load': 0.1, 'latency_ms': 40, 'concurrency': 4},
    })
    fm._poll_once()
    assert state.get_anomaly('srv1') == 0.0
    assert quarantined == []


def test_sybil_liar_deviation_triggers_anomaly_and_quarantine():
    state = TrustState(node_ids=['srv1'], anomaly_gate=0.5, anomaly_lambda=0.85)
    state.set_concurrency('srv1', 4)
    # Controller itself dispatched 4 tasks -> observed_load = 1.0, but the
    # node lies and claims near-idle.
    for port in range(6000, 6004):
        state.register_dispatch('10.0.0.5', port, 'srv1')

    fm, quarantined = _make_monitor(state, {
        'srv1': {'cpu_load': 0.05, 'latency_ms': 10, 'concurrency': 4},
    })
    fm._poll_once()

    assert state.get_anomaly('srv1') > 0.5
    assert quarantined == ['srv1']  # edge-triggered exactly once


def _four_nodes(anomaly_gate=0.5):
    state = TrustState(node_ids=['srv1', 'srv2', 'srv3', 'srv4'],
                       anomaly_gate=anomaly_gate, anomaly_lambda=0.85)
    for nid in state.node_ids:
        state.set_concurrency(nid, 4)
    return state


def test_latency_tell_catches_sybil_under_p2c_with_no_load():
    """The load-independent Sybil tell. srv3 claims to be idle but answers its
    /status poll far slower than the healthy majority (CPU burn), and stays that
    way. It has received NO task traffic (p2c never concentrated load on it), so
    observed_load is 0 and the CPU-honesty deviation check CANNOT fire -- yet
    after `persist` sustained polls it is caught."""
    state = _four_nodes()
    fast = lambda: StatusProbe({'cpu_load': 0.1, 'concurrency': 4}, 20.0)
    statuses = {
        'srv1': fast(), 'srv2': fast(), 'srv4': fast(),
        # claims idle (0.1) but ~7x the fleet median, every poll
        'srv3': StatusProbe({'cpu_load': 0.1, 'concurrency': 4}, 150.0),
    }
    fm, quarantined = _make_monitor(state, statuses)

    # Not caught on the first poll -- persistence guards against a single blip.
    fm._poll_once()
    assert quarantined == []
    # Sustained slowness crosses the strike threshold and quarantines it.
    fm._poll_once()
    fm._poll_once()
    assert state.observed_load('srv3') == 0.0     # honesty check never had a chance
    assert quarantined == ['srv3']                # only the liar, only once
    assert state.get_anomaly('srv3') > 0.5
    assert all(state.get_anomaly(n) == 0.0 for n in ('srv1', 'srv2', 'srv4'))


def test_latency_tell_ignores_fast_idle_nodes():
    """Honest idle nodes all answer quickly -- no fleet outlier, nothing flagged."""
    state = _four_nodes()
    fm, quarantined = _make_monitor(state, {
        'srv1': StatusProbe({'cpu_load': 0.05, 'concurrency': 4}, 18.0),
        'srv2': StatusProbe({'cpu_load': 0.10, 'concurrency': 4}, 22.0),
        'srv3': StatusProbe({'cpu_load': 0.08, 'concurrency': 4}, 25.0),
        'srv4': StatusProbe({'cpu_load': 0.10, 'concurrency': 4}, 20.0),
    })
    for _ in range(5):
        fm._poll_once()
    assert quarantined == []
    assert all(state.get_anomaly(n) == 0.0 for n in state.node_ids)


def test_latency_tell_ignores_transient_jitter():
    """A healthy node that blips slow for one poll, then recovers, must NOT be
    quarantined -- the strike counter resets, so it never reaches persist."""
    state = _four_nodes()
    fast = lambda: StatusProbe({'cpu_load': 0.1, 'concurrency': 4}, 20.0)
    slow = StatusProbe({'cpu_load': 0.1, 'concurrency': 4}, 200.0)
    statuses = {'srv1': fast(), 'srv2': fast(), 'srv3': fast(), 'srv4': fast()}
    fm, quarantined = _make_monitor(state, statuses)

    for i in range(6):
        statuses['srv2'] = slow if i % 2 == 0 else fast()   # slow every other poll
        fm._poll_once()
    assert quarantined == []                 # never 3 in a row -> never flagged
    assert state.get_anomaly('srv2') == 0.0


def test_latency_tell_ignores_slow_node_that_admits_it_is_busy():
    """A genuinely busy, honest node is slow to answer -- but it CLAIMS high CPU,
    so the slowness is consistent, not a lie. The latency tell must not fire (and
    with its load matching its claim, neither does the honesty check)."""
    state = _four_nodes()
    # srv3 really is busy: 3 inflight of 4 -> observed ~0.75, and it claims 0.7.
    for port in range(7000, 7003):
        state.register_dispatch('10.0.0.9', port, 'srv3')
    fast = lambda: StatusProbe({'cpu_load': 0.1, 'concurrency': 4}, 20.0)
    fm, quarantined = _make_monitor(state, {
        'srv1': fast(), 'srv2': fast(), 'srv4': fast(),
        'srv3': StatusProbe({'cpu_load': 0.7, 'concurrency': 4}, 150.0),
    })
    for _ in range(5):
        fm._poll_once()
    assert quarantined == []                 # admits its load -> not a liar
    assert state.get_anomaly('srv3') == 0.0


def test_both_attacks_caught_by_their_own_independent_tell():
    """The params_attacks_demo.yaml scenario, at the detection level. srv3 is a
    Sybil (claims idle, slow /status) and srv4 is a drop attacker (normal /status,
    but its tasks time out). Each is caught by a DIFFERENT signal, and neither
    trips the other's: the Sybil by the latency tell, the dropper by the
    timeout-rate tell. The two healthy nodes stay clear."""
    from contracts.trust_update import TrustUpdate
    state = _four_nodes()
    # srv4 (drop): its recent task outcomes are timeouts -- the only tell it trips.
    for st in ['timeout', 'timeout', 'timeout', 'timeout']:
        state.record_task_outcome(TrustUpdate(
            device_id='iot1', edge_node_id='srv4', task_status=st,
            cpu_usage=0.1, reported_cpu=0.1, latency_ms=2000,
        ))
    fast = lambda cpu=0.1: StatusProbe({'cpu_load': cpu, 'concurrency': 4}, 20.0)
    statuses = {
        'srv1': fast(), 'srv2': fast(),
        # Sybil: claims idle, /status is sustained-slow -> latency tell.
        'srv3': StatusProbe({'cpu_load': 0.1, 'concurrency': 4}, 150.0),
        # Dropper: /status answers normally and honestly -> only the timeout tell.
        'srv4': fast(),
    }
    fm, quarantined = _make_monitor(state, statuses)
    for _ in range(3):        # latency tell needs a few sustained polls
        fm._poll_once()

    assert set(quarantined) == {'srv3', 'srv4'}
    assert state.get_anomaly('srv3') > 0.5 and state.get_anomaly('srv4') > 0.5
    assert state.get_anomaly('srv1') == 0.0 and state.get_anomaly('srv2') == 0.0


def test_packet_drop_tell_uses_timeout_rate_not_cpu_honesty():
    """A drop attacker can self-report CPU honestly -- the deviation check
    alone must NOT catch it. recent_timeout_rate is the separate signal."""
    from contracts.trust_update import TrustUpdate

    state = TrustState(node_ids=['srv1'], anomaly_gate=0.5, anomaly_lambda=0.85)
    state.set_concurrency('srv1', 4)
    for status in ['timeout', 'timeout', 'timeout', 'success']:
        state.record_task_outcome(TrustUpdate(
            device_id='iot1', edge_node_id='srv1', task_status=status,
            cpu_usage=0.1, reported_cpu=0.1, latency_ms=2000,
        ))

    fm, quarantined = _make_monitor(state, {
        # Perfectly honest CPU report -- deviation check alone would clear it.
        'srv1': {'cpu_load': 0.1, 'latency_ms': 10, 'concurrency': 4},
    })
    fm._poll_once()

    assert quarantined == ['srv1']


def test_unreachable_agent_treated_as_anomalous():
    """A node that HAS been seen and then goes silent is anomalous.

    This is the original Sprint 1 finding ("unreachable = anomalous"): a node
    that stops answering is indistinguishable from one that has failed or been
    taken over, so silence must score rather than be skipped. The
    first-contact requirement added for the startup window (see the test
    below) must not weaken this -- hence one healthy poll first, then silence.
    """
    state = TrustState(node_ids=['srv1'], anomaly_gate=0.5, anomaly_lambda=0.85)
    statuses = {'srv1': {'cpu_load': 0.2, 'latency_ms': 20.0, 'concurrency': 4}}
    fm, quarantined = _make_monitor(state, statuses)
    fm._poll_once()                     # seen once, healthy
    assert state.get_anomaly('srv1') < 0.5
    assert quarantined == []

    statuses['srv1'] = None             # now it goes dark
    fm._poll_once()
    assert state.get_anomaly('srv1') > 0.5
    assert quarantined == ['srv1']


def test_never_seen_agent_is_unknown_not_anomalous():
    """A node that has never answered once must not be scored.

    The controller has to be listening before any switch can connect, so it
    necessarily starts seconds before Mininet builds the network and the
    agents inside it. Scoring that window pushed A to 0.85 on the very first
    poll and quarantined all 8 servers at t=0.5s of the 8/40/3 live run --
    before a single agent existed. Absence of evidence is not evidence of
    misbehaviour; a node that never comes up simply never becomes a routing
    candidate.
    """
    state = TrustState(node_ids=['srv1'], anomaly_gate=0.5, anomaly_lambda=0.85)
    fm, quarantined = _make_monitor(state, {'srv1': None})

    for _ in range(5):
        fm._poll_once()

    assert state.get_anomaly('srv1') == 0.0
    assert quarantined == []


def test_measured_rtt_feeds_routing_not_self_reported_latency():
    """A node that lies 'my latency is 1ms' but is actually slow to answer must
    not win the latency term. Routing uses the controller-measured RTT, so the
    liar with a high measured RTT loses to an honest fast node -- even though
    its self-reported latency_ms is far lower.
    """
    state = TrustState(node_ids=['srv1', 'srv2'])
    # Both nodes: equal trust (fresh), equal claimed CPU -> the ONLY thing that
    # can separate them in EdgeScore is the latency term.
    fm, _ = _make_monitor(state, {
        # srv1 lies about latency (1ms) but its reply is genuinely slow (200ms).
        'srv1': StatusProbe({'cpu_load': 0.2, 'latency_ms': 1, 'concurrency': 1}, 200.0),
        # srv2 honest and genuinely fast (10ms measured).
        'srv2': StatusProbe({'cpu_load': 0.2, 'latency_ms': 1, 'concurrency': 1}, 10.0),
    })
    fm._poll_once()

    # The measured RTT, not the self-reported 1ms, is what was stored.
    snap = state.snapshot()
    assert snap['srv1']['latency_ms'] == 200.0
    assert snap['srv2']['latency_ms'] == 10.0

    # And it drives the decision: the genuinely-fast honest node is chosen.
    assert state.choose_edge_node() == 'srv2'


def test_poll_calls_flush_if_stale():
    state = TrustState(node_ids=['srv1'], block_commit_timeout_s=0.0, max_updates_per_block=100)
    from contracts.trust_update import TrustUpdate
    state.record_task_outcome(TrustUpdate(
        device_id='iot1', edge_node_id='srv1', task_status='success',
        cpu_usage=0.2, reported_cpu=0.2, latency_ms=10,
    ))
    fm, _ = _make_monitor(state, {'srv1': {'cpu_load': 0.2, 'latency_ms': 10, 'concurrency': 4}})
    fm._poll_once()
    assert state.commit_backend.chain_length() == 2  # genesis + the flushed block
