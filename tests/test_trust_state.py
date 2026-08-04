"""Tests for controller/trust_state.py -- the shared, thread-safe trust and
routing state used by TrustBalancerApp/FlowMonitor/NorthboundAPI.

test_f04_non_degrading_liar_needs_anomaly_gate documents the Sprint 1 design
finding referenced by config/params_trust_demo.yaml's comment: the published
trust formula T = 0.35R + 0.25B + 0.25H - 0.15A cannot, on its own, isolate a
node that lies about its load but still serves tasks well (it floors around
T=0.44, never crossing the 0.3 isolation threshold). The fix is the
independent anomaly-gate quarantine check, which this test exercises through
the real TrustState/TrustCalculator, not a mock.
"""

import time

from contracts.trust_update import TrustUpdate
from controller.trust_state import TrustState
from trust_engine.trust_calculator import TrustCalculator


def _make_state(node_ids=('srv1', 'srv2'), **kwargs) -> TrustState:
    return TrustState(node_ids=list(node_ids), **kwargs)


def test_dispatch_tracks_inflight_and_observed_load():
    state = _make_state()
    state.set_concurrency('srv1', 4)
    assert state.observed_load('srv1') == 0.0

    time.sleep(0.2)  # a little idle history, as any live node has
    state.register_dispatch('10.0.0.5', 5000, 'srv1')
    state.register_dispatch('10.0.0.6', 5001, 'srv1')
    # inflight stays an exact instantaneous count...
    assert state.get_inflight('srv1') == 2
    # ...but observed_load is the time-average of it (Little's Law is a
    # statement about time averages), so two tasks that have only just been
    # dispatched have barely any occupancy behind them yet. Reading 2/4 = 0.5
    # here is what used to brand a truthful idle node a liar: 0.5 against a
    # claimed 0.0 clears the 0.40 honesty threshold on its own.
    assert state.observed_load('srv1') < 0.1

    node = state.complete_dispatch('10.0.0.5', 5000)
    assert node == 'srv1'
    assert state.get_inflight('srv1') == 1


def test_observed_load_averages_over_the_window_not_the_instant():
    """A brief burst must average away; sustained occupancy must not."""
    state = _make_state()
    state.set_concurrency('srv1', 4)
    state.load_window_s = 1.0

    # Brief burst: 4 tasks held for 20ms out of a 1s window.
    for i in range(4):
        state.register_dispatch('10.0.0.5', 6000 + i, 'srv1')
    time.sleep(0.02)
    for i in range(4):
        state.complete_dispatch('10.0.0.5', 6000 + i)
    time.sleep(0.4)
    assert state.observed_load('srv1') < 0.2, 'transient burst must not read as load'

    # Sustained: 4 tasks held for longer than the whole window.
    state2 = _make_state()
    state2.set_concurrency('srv1', 4)
    state2.load_window_s = 0.3
    for i in range(4):
        state2.register_dispatch('10.0.0.6', 7000 + i, 'srv1')
    time.sleep(0.45)
    assert state2.observed_load('srv1') > 0.9, 'sustained saturation must read as load'


def test_complete_dispatch_unknown_flow_returns_none():
    state = _make_state()
    assert state.complete_dispatch('10.0.0.9', 9999) is None


def test_observed_load_clamped_to_one():
    state = _make_state()
    state.set_concurrency('srv1', 2)
    # Occupancy is a *time* average, so five dispatches registered back-to-back
    # have almost no area behind them yet and the ratio is dominated by however
    # the samples happened to be spaced -- this asserted on zero elapsed time
    # and flaked ~2% of runs. Give it a window's worth of history, as the other
    # observed_load tests do.
    state.load_window_s = 0.1
    for port in range(5001, 5006):
        state.register_dispatch('10.0.0.5', port, 'srv1')
    time.sleep(0.15)
    assert state.observed_load('srv1') == 1.0


def test_is_quarantined_by_trust_threshold():
    state = _make_state(isolation_threshold=0.3, anomaly_gate=0.5)
    # Drive srv1's trust down with repeated failures.
    for _ in range(15):
        state.record_task_outcome(TrustUpdate(
            device_id='iot1', edge_node_id='srv1', task_status='failure',
            cpu_usage=0.9, reported_cpu=0.9, latency_ms=600,  # b_raw floors at 0
        ))
    assert state.is_quarantined('srv1')


def test_poll_newly_quarantined_is_edge_triggered():
    state = _make_state(isolation_threshold=0.3, anomaly_gate=0.5)
    assert state.poll_newly_quarantined() == []  # healthy at t=0

    state.set_anomaly_raw('srv1', 1.0)
    newly = state.poll_newly_quarantined()
    assert newly == ['srv1']

    # Second poll while still quarantined must NOT re-fire.
    state.set_anomaly_raw('srv1', 1.0)
    assert state.poll_newly_quarantined() == []


def test_f04_non_degrading_liar_needs_anomaly_gate():
    """Replays the exact scenario from the Sprint 1 design note: a node that
    always succeeds fast (R->1, B->~1) but lies about its CPU load. Honesty
    delta drives H down, but delta=0.15 can only ever subtract 0.15 -- trust
    alone floors well above the 0.3 isolation threshold. The anomaly gate,
    fed by FlowMonitor's honesty-deviation check via set_anomaly_raw, is what
    actually excludes it."""
    calc = TrustCalculator(alpha=0.35, beta=0.25, gamma=0.25, delta=0.15, lambda_decay=0.85)
    state = _make_state(
        node_ids=['srv1'], trust_calculator=calc,
        isolation_threshold=0.3, anomaly_gate=0.5,
    )

    for _ in range(30):
        state.record_task_outcome(TrustUpdate(
            device_id='iot1', edge_node_id='srv1', task_status='success',
            cpu_usage=0.95, reported_cpu=0.05,  # big claimed-vs-actual lie
            latency_ms=5,
        ))

    trust = calc.get_score('srv1')
    assert trust > 0.3, (
        f"expected the formula alone to float above isolation_threshold "
        f"(got {trust:.4f}) -- if this fails the formula itself changed and "
        f"this regression test needs revisiting"
    )
    assert not state.is_quarantined('srv1'), "trust-only check should NOT catch this liar"

    # Now FlowMonitor's honesty-deviation check fires (deviation between
    # claimed 0.05 and controller-observed load would exceed the 0.40
    # threshold for a node this busy).
    state.set_anomaly_raw('srv1', 1.0)
    assert state.is_quarantined('srv1'), "anomaly gate must catch what trust alone cannot"


def test_recent_timeout_rate_none_below_min_samples():
    state = _make_state()
    for _ in range(3):
        state.record_task_outcome(TrustUpdate(
            device_id='iot1', edge_node_id='srv1', task_status='timeout',
            cpu_usage=0.5, reported_cpu=0.5, latency_ms=2000,
        ))
    assert state.recent_timeout_rate('srv1', min_samples=4) is None


def test_recent_timeout_rate_computed_once_enough_samples():
    state = _make_state()
    outcomes = ['timeout', 'timeout', 'timeout', 'success']
    for status in outcomes:
        state.record_task_outcome(TrustUpdate(
            device_id='iot1', edge_node_id='srv1', task_status=status,
            cpu_usage=0.5, reported_cpu=0.5, latency_ms=100,
        ))
    rate = state.recent_timeout_rate('srv1', min_samples=4)
    assert rate == 0.75


def test_flush_if_stale_commits_after_timeout():
    state = _make_state(node_ids=['srv1'], block_commit_timeout_s=0.05, max_updates_per_block=100)
    state.record_task_outcome(TrustUpdate(
        device_id='iot1', edge_node_id='srv1', task_status='success',
        cpu_usage=0.2, reported_cpu=0.2, latency_ms=10,
    ))
    assert state.commit_backend.chain_length() == 1  # genesis only, not yet flushed
    time.sleep(0.06)
    assert state.flush_if_stale() is True
    assert state.commit_backend.chain_length() == 2


def test_choose_edge_node_denies_when_all_quarantined():
    state = _make_state(node_ids=['srv1', 'srv2'])
    state.set_anomaly_raw('srv1', 1.0)
    state.set_anomaly_raw('srv2', 1.0)
    assert state.choose_edge_node() is None


# ------------------------------------------------------------------------- #
# AI weight optimizer wiring                                                 #
# ------------------------------------------------------------------------- #
from controller.edge_selector import EdgeWeights
from trust_engine.ai_optimizer import UCB1WeightOptimizer


def test_optimizer_disabled_by_default_uses_fixed_weights():
    """No optimizer passed -> StaticWeightOptimizer -> edge_weights is the fixed
    configured value and optimizer_tick does nothing (byte-for-byte the old
    behaviour)."""
    fixed = EdgeWeights(0.6, 0.3, 0.1)
    state = _make_state(edge_weights=fixed)
    assert state.edge_weights == fixed
    assert state.optimizer_tick() is None
    assert state.edge_weights == fixed  # never changes


def test_optimizer_window_rollover_swaps_to_a_valid_arm():
    arms = [EdgeWeights(0.50, 0.30, 0.20), EdgeWeights(0.70, 0.20, 0.10)]
    state = _make_state(
        node_ids=['srv1', 'srv2'],
        optimizer=UCB1WeightOptimizer(arms),
        optimizer_window_s=0.05,
    )
    # A window that has not elapsed yet does nothing.
    assert state.optimizer_tick() is None

    # Record some outcomes, wait out the window, then tick.
    for status in ('success', 'success', 'timeout'):
        state.record_task_outcome(TrustUpdate(
            device_id='iot1', edge_node_id='srv1', task_status=status,
            cpu_usage=0.3, reported_cpu=0.3, latency_ms=20,
        ))
    time.sleep(0.06)
    summary = state.optimizer_tick()
    assert summary is not None
    assert summary['outcomes'] == 3
    # The active weights are now one of the configured arms.
    assert state.edge_weights in arms
    # Conditions snapshot (the RF's future feature vector) rides the summary.
    assert set(summary['conditions']) == {
        'mean_trust', 'mean_load', 'mean_latency_ms', 'num_quarantined',
    }


def test_optimizer_never_reenables_a_quarantined_node():
    """Whatever arm the bandit picks, a quarantined node stays excluded -- the
    optimizer tunes the score weights, never the safety gates."""
    arms = [EdgeWeights(0.50, 0.30, 0.20), EdgeWeights(0.70, 0.20, 0.10)]
    state = _make_state(
        node_ids=['srv1', 'srv2'],
        optimizer=UCB1WeightOptimizer(arms),
        optimizer_window_s=0.0,  # every tick closes a window
    )
    state.set_anomaly_raw('srv1', 1.0)  # quarantine srv1 by anomaly
    for _ in range(10):
        state.optimizer_tick()
        assert state.choose_edge_node() == 'srv2'  # never srv1, whatever the arm


def test_claimed_load_averages_the_node_self_report():
    """Both sides of the honesty check must be averaged over the same window.

    node_agent samples active/concurrency the instant its handler runs, so the
    claim series is a quantised step function. Comparing one such sample against
    the controller's windowed occupancy tripped the check in whichever direction
    happened to be ahead -- an idle node caught mid-burst reported claimed 0.50
    against an observed 0.03 and was quarantined for it.
    """
    state = _make_state()
    state.set_concurrency('srv1', 4)
    state.load_window_s = 1.0

    # Mostly idle, with one instantaneous 0.50 spike -- the 18:30:00 pattern.
    for _ in range(8):
        state.report_claimed_status('srv1', 0.0, 30.0)
        time.sleep(0.05)
    state.report_claimed_status('srv1', 0.5, 30.0)

    assert state.get_claimed_cpu('srv1') == 0.5, 'raw claim stays available'
    assert state.claimed_load('srv1') < 0.1, 'windowed claim must ignore the spike'


def test_stale_dispatches_are_reaped_without_new_dispatches():
    """The reap sweep must not be driven only by register_dispatch.

    Once every node is quarantined nothing registers, so a reaper that only ran
    on dispatch froze inflight forever -- pinning observed_load high, which kept
    the honesty check tripping, which kept the nodes quarantined.
    """
    state = _make_state()
    state.set_concurrency('srv1', 4)
    state._dispatch_reap_after_s = 0.05

    state.register_dispatch('10.0.0.5', 5000, 'srv1')
    state.register_dispatch('10.0.0.6', 5001, 'srv1')
    assert state.get_inflight('srv1') == 2

    time.sleep(0.1)
    # No further dispatches -- exactly the all-quarantined case.
    state.reap_stale_dispatches()
    assert state.get_inflight('srv1') == 0, 'stale dispatches must drain on their own'


def test_reassigned_dispatches_keep_their_original_age():
    """Re-steering a flow must not restart the abandonment clock.

    `dispatched_at` answers "has the client given up yet?", and the client's
    own timer is unaffected by the controller re-pointing its flow. Stamping
    `now` on reassignment made every re-dispatch rejuvenate the entry, so
    under quarantine churn -- the only time this path runs -- dispatches never
    aged out at all. The 8/40/3 live run held inflight pinned at 7 for its
    whole length, which kept observed_load at 1.00 against a truthful
    claimed_cpu of 0.00 and re-tripped the honesty check on each survivor the
    load was moved onto.
    """
    state = _make_state()
    state._dispatch_reap_after_s = 0.05

    state.register_dispatch('10.0.0.5', 5000, 'srv1')
    assert state.get_inflight('srv1') == 1

    time.sleep(0.1)  # the client has now given up
    moved = state.reassign_dispatches('srv1', 'srv2')
    assert moved == [('10.0.0.5', 5000)]
    assert state.get_inflight('srv2') == 1

    # Already past the horizon when it was moved, so the very next sweep must
    # drop it rather than granting it a fresh lease on srv2.
    state.reap_stale_dispatches()
    assert state.get_inflight('srv2') == 0, (
        're-dispatch must not rejuvenate an already-abandoned dispatch'
    )


def test_reap_horizon_tracks_the_client_task_timeout():
    """The reaper must not out-live the client's own give-up time.

    A client that times out at task_timeout_s never sends /report at all, so
    every dispatch it abandons keeps counting toward _inflight -- and therefore
    observed_load -- until the reaper drops it. The 8/40/3 live run had a fixed
    30s reaper against a 2s client timeout, so under saturation each node
    carried ~15 cycles of phantom inflight and read observed_load 0.75 while
    genuinely idle; flow_monitor then compared that to a truthful claimed_cpu
    of 0.00 and quarantined five honest nodes. Deriving the horizon from the
    timeout is what makes the two impossible to drift apart again.
    """
    assert _make_state(task_timeout_s=2.0)._dispatch_reap_after_s == 3.0
    assert _make_state(task_timeout_s=10.0)._dispatch_reap_after_s == 15.0
    # Never below a floor, so a pathologically small timeout can't reap a
    # dispatch before the report has any chance to arrive.
    assert _make_state(task_timeout_s=0.01)._dispatch_reap_after_s == 1.0
    # It must stay a small multiple of the client timeout, never the old
    # order-of-magnitude gap.
    assert _make_state(task_timeout_s=2.0)._dispatch_reap_after_s < 2.0 * 5


def test_abandoned_dispatches_do_not_pin_observed_load_on_an_idle_node():
    """End-to-end shape of the live-run failure: clients that time out and
    never report must not leave an honest, idle node reading as loaded."""
    state = _make_state()
    state.set_concurrency('srv1', 4)
    # Both set directly rather than via task_timeout_s: the derived horizon has
    # a 1.0s floor (see test_reap_horizon_tracks_the_client_task_timeout) and
    # the averaging window is 3s, which would make this a multi-second test for
    # no extra coverage. The ratio between them is what matters, and it is
    # preserved: the reaper fires well inside one averaging window.
    state._dispatch_reap_after_s = 0.05
    state.load_window_s = 0.1

    # Four clients dispatch, then all give up without ever reporting.
    for i in range(4):
        state.register_dispatch('10.0.0.5', 8000 + i, 'srv1')
    assert state.get_inflight('srv1') == 4

    time.sleep(0.15)
    # Held for more than a full window, so this much is real occupancy and
    # must read as such -- the fix must not simply blind the load estimate.
    assert state.observed_load('srv1') > 0.9, 'real load must read as load while it is real'

    state.reap_stale_dispatches()
    assert state.get_inflight('srv1') == 0, 'abandoned dispatches must drain'

    # ...and once they have drained, the occupancy estimate must actually fall
    # back to idle. With the old 30s-vs-2s gap it never got here: inflight
    # stayed pinned, so observed_load sat above the 0.40 honesty threshold
    # indefinitely and every honest node looked like it was lying about being
    # idle. One averaging window is all it should take.
    time.sleep(0.15)
    assert state.observed_load('srv1') < 0.40, (
        'abandoned dispatches must not hold load past the honesty threshold'
    )


# --------------------------------------------------------------------- #
# Escaping quarantine                                                    #
#                                                                        #
# Quarantine cuts service traffic, and service traffic is the only source
# of task outcomes -- so every detector reading task outcomes goes blind
# the moment it fires, and every term of T those outcomes feed stops
# moving. The 8/40/3 live run ended with three provably healthy servers
# (anomaly 0.0, 29ms RTT, zero inflight) isolated for its whole length.
# These tests pin both halves of the escape, and just as importantly pin
# that neither half opens a door for an actually-misbehaving node.
# --------------------------------------------------------------------- #

class _Clock:
    """Injectable monotonic clock, so evidence can be aged without sleeping."""

    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def _timeouts(state: TrustState, node_id: str, n: int = 10) -> None:
    for i in range(n):
        state.record_task_outcome(TrustUpdate(
            device_id=f'iot{i}', edge_node_id=node_id, task_status='timeout',
            cpu_usage=0.5, reported_cpu=0.5, latency_ms=2000,
        ))


def test_packet_drop_tell_abstains_once_its_evidence_goes_stale():
    """The window is count-based, so a quarantined node's last verdict would
    otherwise stand forever on evidence that stopped being observed.

    Measured in the 8/40/3 live run: srv5's last real task outcome landed at
    t=9.2s and the controller was still asserting 'timeout rate 0.60 > 0.40'
    against it at t=240.9s -- 231s of anomaly 1.0 from a frozen sample, which
    held a healthy node in quarantine for the rest of the run.
    """
    clock = _Clock()
    state = _make_state(task_timeout_s=4.0, time_source=clock)
    _timeouts(state, 'srv1')

    # Fresh evidence: the tell fires, exactly as it must for a drop attacker.
    assert state.recent_timeout_rate('srv1') == 1.0

    # Still fresh just inside the horizon (3 x task_timeout_s = 12s).
    clock.advance(11.0)
    assert state.recent_timeout_rate('srv1') == 1.0

    # Past it, the detector has no recent evidence and must say so.
    clock.advance(2.0)
    assert state.recent_timeout_rate('srv1') is None, (
        'a detector with no recent evidence must return None, not re-assert '
        'its last verdict forever'
    )


def test_stale_evidence_horizon_tracks_the_client_task_timeout():
    assert _make_state(task_timeout_s=4.0)._timeout_evidence_max_age_s == 12.0
    assert _make_state(task_timeout_s=1.0)._timeout_evidence_max_age_s == 3.0
    # Floored, so a tiny timeout can't make the tell abstain on live evidence.
    assert _make_state(task_timeout_s=0.1)._timeout_evidence_max_age_s == 2.0


def test_a_node_still_receiving_tasks_never_abstains():
    """The staleness rule must not blunt the tell on a node under live traffic:
    a drop attacker is still being routed to, so its evidence stays fresh."""
    clock = _Clock()
    state = _make_state(task_timeout_s=4.0, time_source=clock)
    _timeouts(state, 'srv1', n=4)  # enough to clear min_samples
    for _ in range(6):
        clock.advance(10.0)  # under the 12s horizon, as live traffic would be
        _timeouts(state, 'srv1', n=2)
        assert state.recent_timeout_rate('srv1') == 1.0


def _trust_quarantined(state: TrustState, node_id: str, trust: float) -> None:
    """Put a node below the isolation threshold with its anomaly rail clear."""
    state.trust_calc._scores[node_id] = trust
    state.set_anomaly_raw(node_id, 0.0)


def test_probation_offers_a_trial_to_a_trust_quarantined_node():
    clock = _Clock()
    state = _make_state(node_ids=['srv1'], time_source=clock)
    _trust_quarantined(state, 'srv1', 0.18)
    assert state.is_quarantined('srv1')

    chosen, probation = state.choose_edge_node_ex()
    assert (chosen, probation) == ('srv1', True), (
        'a node quarantined on trust alone can never earn trust back without '
        'a trial task -- nothing else generates the outcomes T is built from'
    )


def test_probation_never_probes_a_node_the_anomaly_rail_has_flagged():
    """The anomaly gate stays an absolute bar. Probation re-tests a stale
    trust verdict; it must not hand traffic to a node under active suspicion."""
    state = _make_state(node_ids=['srv1'])
    state.trust_calc._scores['srv1'] = 0.18
    state.set_anomaly_raw('srv1', 1.0)

    assert state.choose_edge_node_ex() == (None, False)
    assert not state.is_on_probation('srv1')


def test_probation_is_rate_limited_to_one_trial_per_interval():
    """The cost of recoverability is bounded: a genuinely bad node gets one
    task per interval, not a route back into service."""
    clock = _Clock()
    state = _make_state(
        node_ids=['srv1'], time_source=clock, probation_interval_s=5.0,
    )
    _trust_quarantined(state, 'srv1', 0.18)

    assert state.choose_edge_node_ex() == ('srv1', True)
    # Immediately after, and right up to the interval, nothing is offered.
    assert state.choose_edge_node_ex() == (None, False)
    clock.advance(4.9)
    assert state.choose_edge_node_ex() == (None, False)
    clock.advance(0.2)
    assert state.choose_edge_node_ex() == ('srv1', True)


def test_probation_probes_the_closest_to_recovery_first():
    clock = _Clock()
    state = _make_state(
        node_ids=['srv1', 'srv2', 'srv3'], time_source=clock,
    )
    _trust_quarantined(state, 'srv1', 0.10)
    _trust_quarantined(state, 'srv2', 0.28)
    _trust_quarantined(state, 'srv3', 0.20)

    assert state.choose_edge_node_ex() == ('srv2', True)
    assert state.choose_edge_node_ex() == ('srv3', True)
    assert state.choose_edge_node_ex() == ('srv1', True)
    assert state.choose_edge_node_ex() == (None, False)


def test_probation_is_inert_when_nothing_is_quarantined():
    """Normal operation must be byte-for-byte what it was before probation
    existed -- no candidates, so the path never runs."""
    clock = _Clock()
    state = _make_state(node_ids=['srv1', 'srv2'], time_source=clock)

    for _ in range(20):
        chosen, probation = state.choose_edge_node_ex()
        assert chosen in ('srv1', 'srv2')
        assert probation is False
    assert state._last_probation == {}


def test_probation_trials_do_not_displace_ordinary_service():
    """The trial is a trickle alongside service, not instead of it: one due
    trial goes out, then the healthy node takes every other decision until the
    interval comes round again. This is what bounds the cost of probation at
    |nodes| / probation_interval_s decisions per second, whatever the load."""
    clock = _Clock()
    state = _make_state(
        node_ids=['srv1', 'srv2'], time_source=clock, probation_interval_s=5.0,
    )
    _trust_quarantined(state, 'srv1', 0.18)   # quarantined
    state.trust_calc._scores['srv2'] = 0.90   # healthy

    # The one due trial goes out first, then srv2 takes everything else for
    # the rest of the interval.
    assert state.choose_edge_node_ex() == ('srv1', True)
    for _ in range(10):
        assert state.choose_edge_node_ex() == ('srv2', False)


def test_probation_lets_a_recovering_node_rejoin_normally():
    """End to end: trial -> successful outcomes -> trust crosses back over the
    isolation threshold -> the node is chosen by the ordinary path, and stops
    being a probation candidate at all."""
    clock = _Clock()
    state = _make_state(node_ids=['srv1'], time_source=clock)
    _trust_quarantined(state, 'srv1', 0.28)

    chosen, probation = state.choose_edge_node_ex()
    assert (chosen, probation) == ('srv1', True)

    for i in range(10):
        state.record_task_outcome(TrustUpdate(
            device_id=f'iot{i}', edge_node_id='srv1', task_status='success',
            cpu_usage=0.1, reported_cpu=0.1, latency_ms=20,
        ))

    assert not state.is_quarantined('srv1')
    assert not state.is_on_probation('srv1')
    clock.advance(60.0)
    assert state.choose_edge_node_ex() == ('srv1', False)


# --------------------------------------------------------------------- #
# The inflight/dispatch invariant                                        #
#                                                                        #
# sum(_inflight.values()) == len(_dispatches). Every count is owned by    #
# exactly one dict entry, so a count can only be released by removing the #
# entry that owns it. Live run 4 broke this 57 times and left a healthy   #
# srv1 pinned at observed_load 0.50 vs a truthful claimed 0.00 for 976s.  #
# --------------------------------------------------------------------- #

def _assert_invariant(state: TrustState) -> None:
    counted = sum(state._inflight.values())
    held = len(state._dispatches)
    assert counted == held, (
        f'inflight total {counted} != {held} live dispatches -- a count is '
        f'orphaned and nothing will ever release it'
    )


def test_re_registering_a_live_flow_does_not_leak_inflight():
    """A PacketIn for a (client_ip, client_port) that still has an outstanding
    dispatch overwrites the dict entry. The count that entry owned has to be
    released in the same breath, or it is stranded: no dict entry survives for
    the reaper to find, and no completion report will ever reference it.
    """
    state = _make_state(node_ids=['srv1', 'srv2'])

    state.register_dispatch('10.0.0.1', 40778, 'srv1')
    assert state.get_inflight('srv1') == 1
    _assert_invariant(state)

    # Same flow re-dispatched to a different node before the first completed.
    state.register_dispatch('10.0.0.1', 40778, 'srv2')
    assert state.get_inflight('srv1') == 0, (
        "srv1 no longer holds this flow and must not still be counted for it"
    )
    assert state.get_inflight('srv2') == 1
    _assert_invariant(state)

    # And back again, plus a same-node re-registration -- the exact triple seen
    # at t=38.6s in live run 4.
    state.register_dispatch('10.0.0.1', 40778, 'srv1')
    state.register_dispatch('10.0.0.1', 40778, 'srv1')
    assert state.get_inflight('srv1') == 1
    assert state.get_inflight('srv2') == 0
    _assert_invariant(state)

    # One completion clears it entirely -- not "one of the several".
    assert state.complete_dispatch('10.0.0.1', 40778) == 'srv1'
    assert state.get_inflight('srv1') == 0
    _assert_invariant(state)


def test_orphaned_inflight_cannot_survive_the_reaper():
    """The failure mode that made this so damaging: an orphaned count is not
    merely wrong, it is unreachable. The reaper walks _dispatches, so a count
    with no entry behind it is never swept -- srv1 held one for 976s."""
    state = _make_state(node_ids=['srv1', 'srv2'], task_timeout_s=1.0)
    state._dispatch_reap_after_s = 0.05

    state.register_dispatch('10.0.0.1', 40778, 'srv1')
    state.register_dispatch('10.0.0.1', 40778, 'srv2')  # supersedes it

    time.sleep(0.1)
    state.reap_stale_dispatches()

    assert state.get_inflight('srv1') == 0
    assert state.get_inflight('srv2') == 0
    _assert_invariant(state)


def test_invariant_holds_across_reassignment_and_completion():
    """Re-steering moves a count between nodes rather than creating one, and a
    later re-registration of the same key must still balance."""
    state = _make_state(node_ids=['srv1', 'srv2', 'srv3'])

    for port in (5000, 5001, 5002):
        state.register_dispatch('10.0.0.5', port, 'srv1')
    _assert_invariant(state)
    assert state.get_inflight('srv1') == 3

    state.reassign_dispatches('srv1', 'srv2')
    assert state.get_inflight('srv1') == 0
    assert state.get_inflight('srv2') == 3
    _assert_invariant(state)

    # A fresh PacketIn for one of those re-steered flows.
    state.register_dispatch('10.0.0.5', 5001, 'srv3')
    assert state.get_inflight('srv2') == 2
    assert state.get_inflight('srv3') == 1
    _assert_invariant(state)

    state.complete_dispatch('10.0.0.5', 5001)
    state.complete_dispatch('10.0.0.5', 5000)
    state.complete_dispatch('10.0.0.5', 5002)
    assert sum(state._inflight.values()) == 0
    _assert_invariant(state)


def test_a_leaked_dispatch_would_have_tripped_the_honesty_check():
    """Ties the invariant to why it matters. Two stranded dispatches on a
    4-way node read as observed_load 0.50; against a truthful claimed 0.00
    that is over the 0.40 honesty gate, which is precisely how live run 4
    quarantined srv1 707 times while it was behaving perfectly."""
    state = _make_state(node_ids=['srv1', 'srv2'])
    state.set_concurrency('srv1', 4)
    state.load_window_s = 0.1

    for port in (40778, 40779):
        state.register_dispatch('10.0.0.1', port, 'srv1')
        state.register_dispatch('10.0.0.1', port, 'srv2')  # supersede both

    time.sleep(0.15)
    assert state.observed_load('srv1') < 0.40, (
        'a node that holds no live dispatches must not read as loaded'
    )
    _assert_invariant(state)


# ---------------------------------------------------------------------------
# The honesty comparison has TWO consumers, and they must agree
# ---------------------------------------------------------------------------

def test_trust_path_uses_the_windowed_claim_not_the_raw_one():
    """`honesty_delta()` must compare two quantities measured the same way.

    `claimed_load()` was added to fix exactly this, but was only ever wired
    into the anomaly gate (flow_monitor.py). The trust path kept passing the
    raw `get_claimed_cpu()` into `TrustUpdate.reported_cpu`, so the *gate*
    compared like with like and the *trust formula* did not.

    That is not a false-quarantine bug -- this path never gates -- it is a
    steady tax. The agent samples active/concurrency the instant its handler
    runs, so at a small `task_work_ms` it truthfully claims 0.00 almost always:
    live run 5 measured 98.49% of honest samples at 0.00, which makes the
    deviation *equal to* the occupancy (dev/occ = 1.000 in every bin) and
    h_raw = 1 - 2*occupancy. A busy honest node loses trust for being busy --
    the study's Finding 6 (docs/study §7).
    """
    import types
    from controller.trust_balancer import TrustBalancerApp

    state = _make_state()
    state.set_concurrency('srv1', 4)
    state.load_window_s = 1.0

    # Mostly idle with one instantaneous spike, exactly as a real agent reports.
    for _ in range(8):
        state.report_claimed_status('srv1', 0.0, 30.0)
        time.sleep(0.05)
    state.report_claimed_status('srv1', 0.5, 30.0)

    raw = state.get_claimed_cpu('srv1')
    windowed = state.claimed_load('srv1')
    assert raw == 0.5, 'precondition: the raw claim is the spike'
    assert windowed < 0.1, 'precondition: the windowed claim ignores it'

    state.register_dispatch('10.0.0.5', 5000, 'srv1')

    captured = {}

    class _Bus:
        def publish(self, _topic, **kw):
            captured.update(kw)

    class _Backend:
        commit_count = 0

    stub = types.SimpleNamespace(
        state=state, bus=_Bus(), _commit_backend=_Backend(),
    )
    TrustBalancerApp.handle_client_report(
        stub, '10.0.0.5', 5000, 'iot1', 'success', 42.0,
    )

    # The value that reached the trust formula, as recorded on the event bus.
    assert captured['claimed_cpu'] < 0.1, (
        f"the trust path published claimed_cpu={captured['claimed_cpu']}, i.e. the "
        f"raw instantaneous claim ({raw}) rather than the windowed one "
        f"({windowed:.4f}) -- honesty_delta is comparing an instant against an "
        f"integral again"
    )


# ---------------------------------------------------------------------------
# Busy-time honesty: comparing two integrals of the SAME quantity
# ---------------------------------------------------------------------------

class _Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def _busy_fleet(clock, node_ids=('srv1', 'srv2', 'srv3', 'srv4')):
    state = TrustState(node_ids=list(node_ids), time_source=clock)
    for nid in node_ids:
        state.set_concurrency(nid, 4)
    return state


def _drive_fleet(state, clock, specs, seconds, step=1.0):
    """Drive every node in lockstep for `seconds`.

    `specs` maps node_id -> (tasks_per_s, claimed_service_s). Each node reports
    a cumulative busy-second counter of `completions * claimed_service_s`, and
    the controller independently records the completions it saw. A *truthful*
    node uses its real service time; a liar passes a smaller one, which is
    exactly the fabrication the implied-service-time check has to catch.

    All nodes report at the same instants and the clock advances once per step,
    so every node's history spans the same window -- otherwise a node whose
    samples all share one timestamp has zero span and the estimator (correctly)
    abstains.
    """
    busy = {nid: 0.0 for nid in specs}
    for _ in range(int(seconds / step)):
        for nid, (tasks_per_s, service_s) in specs.items():
            completions = int(tasks_per_s * step)
            busy[nid] += completions * service_s
            state.report_claimed_status(nid, 0.0, 30.0, busy_seconds=busy[nid])
            for _ in range(completions):
                state.record_task_outcome(TrustUpdate(
                    device_id='iot1', edge_node_id=nid, task_status='success',
                    cpu_usage=0.0, reported_cpu=0.0, latency_ms=90.0,
                ))
        clock.advance(step)
    return busy


def test_claimed_load_is_a_duty_cycle_not_an_instantaneous_sample():
    """B(t1)-B(t0) over elapsed worker-seconds. 2 tasks/s x 0.015 s of work on
    4 workers is a duty cycle of 0.0075, whatever the residence time is."""
    clock = _Clock()
    state = _busy_fleet(clock)
    _drive_fleet(state, clock, {'srv1': (2, 0.015)}, seconds=10)

    duty = state.claimed_load('srv1')
    assert abs(duty - (2 * 0.015 / 4)) < 0.002, (
        f'duty cycle should be tasks/s * service_s / concurrency, got {duty}'
    )


def test_honest_busy_node_is_not_taxed_for_being_busy():
    """The whole point of Defect 8's second layer.

    The node truthfully reports service time; the controller's own estimate is
    built from its completion count times the fleet median service time. Both
    are duty cycles, so a *busy* honest node shows ~no deviation -- where the
    old residence-time comparison produced |dev| ~= occupancy at every load
    (dev/occ = 1.000 in every bin of live runs 5 and 6).
    """
    clock = _Clock()
    state = _busy_fleet(clock)
    # A genuinely busy fleet: 20 tasks/s each, 15 ms of work, concurrency 4
    # -> duty cycle 0.075. Residence time is irrelevant to both sides now.
    _drive_fleet(state, clock, {
        nid: (20, 0.015) for nid in ('srv1', 'srv2', 'srv3', 'srv4')
    }, seconds=10)

    claimed = state.claimed_load('srv1')
    expected = state.expected_duty_cycle('srv1')
    assert expected is not None, 'fleet has 4 reporting nodes; must have an opinion'
    assert abs(claimed - expected) < 0.05, (
        f'honest busy node still taxed: claimed duty {claimed:.4f} vs expected '
        f'{expected:.4f} -- the two sides are not the same quantity'
    )


def test_sybil_under_reporting_busy_time_is_caught_by_implied_service_time():
    """The attack the new comparison has to survive.

    A liar can fabricate a busy-second counter as easily as a cpu_load. What it
    cannot fabricate is how many tasks the *controller* saw it finish -- so
    under-reporting busy time shows up as an implausibly small service time
    against the fleet median.
    """
    clock = _Clock()
    state = _busy_fleet(clock)
    # Three honest nodes at 0.100 s of work per task; srv1 completes just as
    # many tasks but claims a tenth of the busy time for each.
    _drive_fleet(state, clock, {
        'srv1': (20, 0.010),
        'srv2': (20, 0.100),
        'srv3': (20, 0.100),
        'srv4': (20, 0.100),
    }, seconds=10)

    claimed = state.claimed_load('srv1')
    expected = state.expected_duty_cycle('srv1')
    assert expected is not None
    assert expected - claimed > 0.40, (
        f'liar claimed duty {claimed:.3f} against an expected {expected:.3f}; '
        f'deviation {expected - claimed:.3f} must clear the 0.40 honesty gate'
    )
    assert state.implied_service_time_s('srv1') < state.fleet_service_time_s()


def test_duty_cycle_abstains_rather_than_guessing_without_evidence():
    """No busy-second counter, too short a span, or too small a fleet -> None,
    and callers fall back instead of inventing a comparison."""
    clock = _Clock()
    state = _busy_fleet(clock)
    assert state.expected_duty_cycle('srv1') is None, 'no data yet'

    # One sample is not a difference.
    state.report_claimed_status('srv1', 0.0, 30.0, busy_seconds=1.0)
    assert state.claimed_load('srv1') is not None  # falls back, does not crash
    assert state.expected_duty_cycle('srv1') is None

    # An agent that never sends busy_seconds keeps the old averaged-claim path.
    clock.advance(1.0)
    state.report_claimed_status('srv2', 0.25, 30.0)
    clock.advance(1.0)
    state.report_claimed_status('srv2', 0.25, 30.0)
    assert abs(state.claimed_load('srv2') - 0.25) < 0.01


def test_busy_counter_going_backwards_resets_instead_of_going_negative():
    """A restarted agent replays from zero. Differencing across that step would
    hand the honesty check a negative duty cycle."""
    clock = _Clock()
    state = _busy_fleet(clock)
    for b in (10.0, 20.0, 30.0):
        state.report_claimed_status('srv1', 0.0, 30.0, busy_seconds=b)
        clock.advance(1.0)
    state.report_claimed_status('srv1', 0.0, 30.0, busy_seconds=0.5)
    clock.advance(1.0)
    state.report_claimed_status('srv1', 0.0, 30.0, busy_seconds=1.0)

    duty = state.claimed_load('srv1')
    assert duty >= 0.0, f'duty cycle went negative across an agent restart: {duty}'
