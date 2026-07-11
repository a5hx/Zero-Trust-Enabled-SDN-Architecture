"""Tests for controller/flow_monitor.py -- the 1Hz anomaly-detection loop.

_fetch_status is monkeypatched in every test here rather than hitting real
HTTP, so these run with no Mininet/network dependency at all.
"""

from controller.flow_monitor import FlowMonitor
from controller.trust_state import TrustState


def _make_monitor(state, statuses, threshold=0.40):
    quarantined = []
    fm = FlowMonitor(
        state=state, node_ids=list(statuses.keys()), agent_port=8000,
        poll_interval_s=1.0, honesty_deviation_threshold=threshold,
        on_quarantine=quarantined.append,
    )
    fm._fetch_status = lambda node_id: statuses[node_id]
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
    state = TrustState(node_ids=['srv1'], anomaly_gate=0.5, anomaly_lambda=0.85)
    fm, quarantined = _make_monitor(state, {'srv1': None})
    fm._poll_once()
    assert state.get_anomaly('srv1') > 0.5
    assert quarantined == ['srv1']


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
