"""The observer measures what the treatment arm measures, and decides nothing.

Two separate properties, both load-bearing for the comparison:

PARITY   -- every number the baseline reports must come from the same code the
            treatment arm uses. If the H term, the occupancy estimator or the
            latency tell diverged, the two trust curves would be measuring
            different things and putting them on one axis would be wrong.

INERTNESS -- nothing the observer computes may change what the baseline does.
            If trust ever reached a routing decision here, the control arm
            would quietly become a weak treatment arm and every result would
            overstate the baseline.

The parity tests deliberately reach into `controller/` private names
(`_MIN_TIMEOUT_SAMPLES`, `_STATUS_TIMEOUT_S`). Pinning them here is the point:
they are constants the two arms must share, and a rename should fail loudly in
this file rather than silently desynchronise the arms.
"""

import inspect

import pytest

from base_model.trust_observer import (
    FORBIDDEN_ENFORCEMENT_API,
    MIN_TIMEOUT_SAMPLES,
    BaselineTrustObserver,
    NoLedgerBackend,
    StatusSample,
)

TRUST_CFG = {
    'alpha': 0.35, 'beta': 0.25, 'gamma': 0.25, 'delta': 0.15,
    'lambda_decay': 0.85, 'initial_score': 0.5,
    'isolation_threshold': 0.3, 'anomaly_gate': 0.5,
}


@pytest.fixture
def observer():
    return BaselineTrustObserver(
        node_ids=[f'srv{i}' for i in range(1, 9)],
        trust_cfg=TRUST_CFG,
        load_window_s=5.0,
        task_timeout_s=4.0,
    )


# ---------------------------------------------------------------------- #
# INERTNESS                                                              #
# ---------------------------------------------------------------------- #
def test_no_enforcement_api_is_exposed():
    BaselineTrustObserver.check_no_enforcement()


@pytest.mark.parametrize('name', FORBIDDEN_ENFORCEMENT_API)
def test_each_forbidden_method_is_absent(name):
    assert not hasattr(BaselineTrustObserver, name), (
        f'BaselineTrustObserver grew {name!r}. The control arm must measure '
        f'trust and never act on it -- if this method is genuinely needed for '
        f'reporting, give it a name that cannot be mistaken for a decision.'
    )


def test_the_forbidden_list_names_real_treatment_methods():
    """Guard against the guard rotting.

    If `TrustState` renames one of these, the entry here would silently protect
    nothing -- `hasattr` would keep returning False for a method that no longer
    exists under that name, while the real one stayed reachable.
    """
    from controller.trust_state import TrustState
    present = [n for n in FORBIDDEN_ENFORCEMENT_API if hasattr(TrustState, n)]
    assert present, (
        'none of FORBIDDEN_ENFORCEMENT_API matches a TrustState method any '
        'more -- the guard list is stale and is protecting nothing'
    )


def test_snapshot_never_reports_a_quarantine(observer):
    for i in range(1, 9):
        observer.record_status(StatusSample(f'srv{i}', True, 0.9, 900.0))
    observer.evaluate_cycle([
        StatusSample(f'srv{i}', True, 0.05, 900.0 if i == 3 else 20.0)
        for i in range(1, 9)
    ])
    snap = observer.snapshot()
    assert all(row['quarantined'] is False for row in snap.values())
    assert all(row['probation'] is False for row in snap.values())


def test_would_quarantine_is_reported_but_not_applied(observer):
    """The baseline's central number: a gate crossed with nothing behind it."""
    samples = [
        StatusSample(f'srv{i}', True, claimed_cpu=0.05,
                     rtt_ms=900.0 if i == 3 else 20.0)
        for i in range(1, 9)
    ]
    # The latency tell is a leaky bucket needing `latency_liar_persist` strikes.
    for _ in range(5):
        observer.record_status(samples[2])
        verdicts = observer.evaluate_cycle(samples)

    srv3 = next(v for v in verdicts if v.node_id == 'srv3')
    assert srv3.reasons, 'srv3 claims idle at 45x the fleet median and was not flagged'
    assert srv3.would_quarantine
    assert observer.detections_unactioned['srv3'] > 0
    assert observer.snapshot()['srv3']['quarantined'] is False


def test_no_ledger_backend_commits_nothing():
    backend = NoLedgerBackend()
    assert backend.commit([]) is None
    assert backend.commit_count == 0
    assert backend.chain_length() == 0


# ---------------------------------------------------------------------- #
# PARITY                                                                 #
# ---------------------------------------------------------------------- #
def test_min_timeout_samples_matches_the_treatment_arm():
    from controller import flow_monitor
    assert MIN_TIMEOUT_SAMPLES == flow_monitor._MIN_TIMEOUT_SAMPLES, (
        'the packet-drop tell needs the same minimum sample count in both arms '
        'or one of them forms an opinion earlier than the other'
    )


def test_status_poll_timeout_matches_the_treatment_arm():
    """A node must read as unreachable at the same instant in both arms."""
    from base_model import baseline_controller
    from controller import flow_monitor
    assert baseline_controller._STATUS_TIMEOUT_S == flow_monitor._STATUS_TIMEOUT_S


def test_cookie_base_matches_the_treatment_arm():
    """FlowStatsPoller resolves a rule to a server from the cookie's low byte.

    A different base would leave every baseline throughput series
    unattributable while still rendering as a plausible chart.
    """
    from controller import flow_stats
    from base_model.baseline_controller import BaselineControllerApp
    src = inspect.getsource(BaselineControllerApp.__init__)
    assert '0x5A00000000000000' in src
    assert flow_stats._VIP_COOKIE_BASE == 0x5A00000000000000


def test_honesty_reference_uses_the_same_call_chain():
    """`expected_duty_cycle` first, `observed_load` only as the fallback.

    Reversing these (or dropping the first) taxes an honest busy node -- the
    project's Finding 6 -- and would rig the comparison against the baseline
    for a reason that has nothing to do with either architecture.
    """
    baseline_src = inspect.getsource(BaselineTrustObserver.record_report)
    from controller.trust_balancer import TrustBalancerApp
    treatment_src = inspect.getsource(TrustBalancerApp.handle_client_report)

    for src, arm in ((baseline_src, 'baseline'), (treatment_src, 'treatment')):
        assert 'expected_duty_cycle' in src, f'{arm} lost the service-time estimator'
        assert 'observed_load' in src, f'{arm} lost the fallback'
        assert 'claimed_load' in src, f'{arm} stopped time-averaging the claim'
        assert src.index('expected_duty_cycle') > src.index('observed_load'), (
            f'{arm}: observed_load must be computed before expected_duty_cycle '
            f'so it can serve as the fallback'
        )


def test_trust_weights_come_from_config_not_defaults():
    obs = BaselineTrustObserver(
        ['srv1'],
        {**TRUST_CFG, 'alpha': 0.40, 'beta': 0.20, 'gamma': 0.25, 'delta': 0.15},
    )
    calc = obs._state.trust_calc
    assert (calc.alpha, calc.beta, calc.gamma, calc.delta) == (0.40, 0.20, 0.25, 0.15)


def test_latency_tell_is_the_treatment_arms_own_function():
    """Imported, not copied -- so the two arms cannot drift apart on it."""
    from base_model import trust_observer
    from controller import flow_monitor
    assert trust_observer.evaluate_latency_tell is flow_monitor.evaluate_latency_tell
    assert trust_observer.fleet_latency_baseline is flow_monitor.fleet_latency_baseline


# ---------------------------------------------------------------------- #
# ACCOUNTING                                                             #
# ---------------------------------------------------------------------- #
def test_inflight_invariant_holds_through_dispatch_and_report(observer):
    """`sum(inflight) == len(dispatches)`.

    The check that separates fabricated occupancy from real load. If it breaks,
    every H value in the run is suspect and the trust curves compare nothing.
    """
    assert observer.inflight_invariant_holds()
    for port in range(40000, 40020):
        observer.register_dispatch('10.0.0.1', port, 'srv1')
        assert observer.inflight_invariant_holds()
    for port in range(40000, 40010):
        observer.record_report('iot1', '10.0.0.1', port, 'success', 50.0)
        assert observer.inflight_invariant_holds()
    observer.reap_stale_dispatches()
    assert observer.inflight_invariant_holds()


def test_unattributable_report_is_refused(observer):
    """A report for a dispatch this controller never made must not move trust.

    Otherwise a device could raise or lower any node's trust by inventing a
    source port -- and while the baseline enforces nothing, its trust series is
    a published measurement and must not be forgeable.
    """
    before = observer.trust('srv1')
    assert observer.record_report('iot1', '10.0.0.1', 59999, 'timeout', 4000.0) is None
    assert observer.trust('srv1') == before


def test_report_payload_marks_the_absent_ledger(observer):
    observer.register_dispatch('10.0.0.2', 41000, 'srv2')
    payload = observer.record_report('iot2', '10.0.0.2', 41000, 'success', 60.0)
    assert payload['committed'] is False
    assert payload['report_ms'] == 0.0


def test_failed_poll_is_missing_evidence_not_an_accusation(observer):
    """An unanswered /status must not raise the baseline's anomaly series.

    The treatment arm scores seen-then-dark as anomalous because it is about to
    act; a control arm that never acts has no reason to convert silence into an
    accusation, and doing so would inflate this arm's own false positives.
    """
    for i in range(1, 9):
        observer.record_status(StatusSample(f'srv{i}', True, 0.1, 20.0))
    samples = [StatusSample(f'srv{i}', True, 0.1, 20.0) for i in range(1, 8)]
    samples.append(StatusSample('srv8', False, rtt_ms=500.0))
    verdicts = observer.evaluate_cycle(samples)
    assert all(v.node_id != 'srv8' for v in verdicts)
    assert observer.snapshot()['srv8']['anomaly'] == 0.0


def test_observe_anomaly_false_keeps_A_out_of_T():
    blind = BaselineTrustObserver(
        [f'srv{i}' for i in range(1, 9)], TRUST_CFG, observe_anomaly=False,
    )
    samples = [
        StatusSample(f'srv{i}', True, claimed_cpu=0.05,
                     rtt_ms=900.0 if i == 3 else 20.0)
        for i in range(1, 9)
    ]
    for _ in range(5):
        verdicts = blind.evaluate_cycle(samples)
    srv3 = next(v for v in verdicts if v.node_id == 'srv3')

    # The detector still has an opinion -- reported, so a blind run can still
    # say what would have been seen...
    assert srv3.anomaly > 0.0
    # ...but it never reached T.
    assert blind.snapshot()['srv3']['anomaly'] == 0.0
    assert blind.snapshot()['srv3']['anomaly_observed'] is False


def test_honesty_reference_split_matches_the_treatment_arm():
    """The three-way split, branch for branch.

    A two-way version here (abstain whenever `expected_duty_cycle` is None)
    would make the baseline's honesty tell strictly less sensitive than the
    treatment arm's, and the comparison would report a detector difference as
    an architecture difference.

    The middle branch is the one worth naming: when a node WITHHOLDS its
    busy-seconds counter, abstaining would let a liar switch the check off by
    omission, so both arms fall back to the degraded residence-time comparison
    and label it as degraded.
    """
    from controller.flow_monitor import FlowMonitor

    baseline_src = inspect.getsource(BaselineTrustObserver.evaluate_cycle)
    treatment_src = inspect.getsource(FlowMonitor._poll_once)

    for src, arm in ((baseline_src, 'baseline'), (treatment_src, 'treatment')):
        assert 'reports_busy_seconds' in src, (
            f'{arm} lost the withheld-counter branch -- an attacker could '
            f'disable the honesty check by omitting busy_seconds'
        )
        assert 'expected duty' in src
        assert 'no busy_seconds' in src


def test_withheld_busy_seconds_falls_back_instead_of_abstaining():
    """A node that sends no busy-seconds is still cross-checked."""
    obs = BaselineTrustObserver([f'srv{i}' for i in range(1, 9)], TRUST_CFG)

    # Claims idle; sends no busy_seconds; the controller has real occupancy on
    # it from its own dispatch accounting.
    for port in range(50000, 50016):
        obs.register_dispatch('10.0.0.1', port, 'srv1')
    for i in range(1, 9):
        obs.record_status(StatusSample(f'srv{i}', True, claimed_cpu=0.0, rtt_ms=20.0))

    verdicts = obs.evaluate_cycle(
        [StatusSample(f'srv{i}', True, claimed_cpu=0.0, rtt_ms=20.0) for i in range(1, 9)]
    )
    srv1 = next(v for v in verdicts if v.node_id == 'srv1')
    assert 'no busy_seconds' in ' '.join(srv1.reasons), (
        f'expected the degraded-reference branch, got {srv1.reasons}'
    )
    assert srv1.signals.get('cpu_honesty') is not None


def test_load_window_matches_the_treatment_arm():
    """Both arms must integrate occupancy over the same window.

    `load_window_s` is the one shared quantity with no counterpart in the
    treatment CONFIG -- the treatment arm never overrides the attribute, so its
    window is `TrustState`'s default. That puts it outside
    test_base_config_parity.py's reach, which is exactly how the baseline
    shipped its first run on a 5 s window against the treatment arm's 3 s.

    It feeds four estimators at once: observed_load's integral, claimed_load's
    time-average, the completion rate behind expected_duty_cycle, and the
    packet-drop tell's stale-evidence horizon (2x this). Two arms on different
    windows do not measure the same H term or the same occupancy.
    """
    import yaml
    from controller.trust_state import TrustState

    treatment_default = TrustState(['srv1']).load_window_s
    with open('base_model/config/params_base_full.yaml') as f:
        configured = float(yaml.safe_load(f)['baseline']['load_window_s'])
    assert configured == treatment_default, (
        f'baseline runs a {configured}s occupancy window against the treatment '
        f"arm's {treatment_default}s. Either match it, or move it into "
        f'SHARED_PATHS and say in the paper that it varied.'
    )


def test_the_observer_actually_applies_the_configured_window():
    """A config key nothing reads would pass the test above and still be wrong."""
    obs = BaselineTrustObserver(['srv1'], TRUST_CFG, load_window_s=7.5)
    assert obs._state.load_window_s == 7.5
