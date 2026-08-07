"""Tests for controller/attack_classifier.py (plan_adv.md Phase 2).

The interesting cases are the two pairs that a single detection cycle cannot
separate -- blackhole/grayhole (magnitude) and sybil/onoff (intermittency) --
plus the abstention rules, which exist so this classifier cannot reintroduce
the absorbing-state bug (memory/quarantine-absorbing-state) in a new shape.
"""

import unittest

from controller.attack_classifier import (
    ATTACK_BAD_CREDENTIALS,
    ATTACK_BLACKHOLE,
    ATTACK_FLOOD,
    ATTACK_GRAYHOLE,
    ATTACK_ONOFF,
    ATTACK_SPOOF,
    ATTACK_SYBIL,
    DEFAULT_BLACKHOLE_MIN_RATE,
    DEFAULT_EVIDENCE_MAX_AGE_S,
    DEFAULT_MIN_CLEAN_RUN,
    NODE_DOWN,
    SIG_AUTH_BAD_RESPONSE,
    SIG_AUTH_IP_PIN,
    SIG_CPU_HONESTY,
    SIG_FLOOD,
    SIG_LATENCY_TELL,
    SIG_PACKET_DROP,
    SIG_UNREACHABLE,
    AttackEvidence,
    Observation,
    classify_client,
    classify_node,
)


def window(pattern, start=0.0, step=1.0):
    """Build a window from a list of signal dicts, one per cycle."""
    return [Observation(start + i * step, sig) for i, sig in enumerate(pattern)]


CLEAN = {}


class TestAbstention(unittest.TestCase):
    def test_empty_window_abstains(self):
        self.assertIsNone(classify_node([]))
        self.assertIsNone(classify_client([]))

    def test_all_clean_abstains_rather_than_declaring_innocence(self):
        self.assertIsNone(classify_node(window([CLEAN] * 20)))

    def test_stale_evidence_abstains_instead_of_reasserting(self):
        w = window([{SIG_LATENCY_TELL: 6.0}] * 10)
        last_t = w[-1].t
        # Fresh: a verdict.
        self.assertIsNotNone(classify_node(w, now=last_t + 1.0))
        # Stale: no opinion. This is the rule from
        # memory/quarantine-absorbing-state -- a detector with no recent
        # evidence must abstain, not re-assert its last verdict.
        self.assertIsNone(
            classify_node(w, now=last_t + DEFAULT_EVIDENCE_MAX_AGE_S + 1.0)
        )

    def test_offline_replay_skips_the_staleness_clock(self):
        w = window([{SIG_LATENCY_TELL: 6.0}] * 10)
        # now=None is what the offline scorer passes: the run is over, so
        # "stale" is not a meaningful question.
        self.assertIsNotNone(classify_node(w, now=None))


class TestSybilVsOnOff(unittest.TestCase):
    def test_sustained_lying_is_sybil(self):
        w = window([CLEAN] * 5 + [{SIG_LATENCY_TELL: 6.0}] * 30)
        result = classify_node(w)
        self.assertEqual(result.attack_type, ATTACK_SYBIL)

    def test_cpu_honesty_alone_is_also_the_sybil_family(self):
        w = window([{SIG_CPU_HONESTY: 0.62}] * 20)
        self.assertEqual(classify_node(w).attack_type, ATTACK_SYBIL)

    def test_intermittent_lying_is_onoff(self):
        bad = [{SIG_LATENCY_TELL: 5.5}] * 8
        good = [CLEAN] * 8
        w = window(bad + good + bad + good + bad)
        result = classify_node(w)
        self.assertEqual(result.attack_type, ATTACK_ONOFF)
        self.assertIn('interrupted by', result.rationale)

    def test_clean_run_shorter_than_the_floor_stays_sybil(self):
        # A gap of DEFAULT_MIN_CLEAN_RUN - 1 clean cycles is jitter, not an
        # off phase. Without this a noisy sybil would be relabelled on-off.
        gap = [CLEAN] * (DEFAULT_MIN_CLEAN_RUN - 1)
        w = window([{SIG_LATENCY_TELL: 6.0}] * 5 + gap + [{SIG_LATENCY_TELL: 6.0}] * 5)
        self.assertEqual(classify_node(w).attack_type, ATTACK_SYBIL)

    def test_clean_run_at_the_floor_is_an_off_phase(self):
        gap = [CLEAN] * DEFAULT_MIN_CLEAN_RUN
        w = window([{SIG_LATENCY_TELL: 6.0}] * 5 + gap + [{SIG_LATENCY_TELL: 6.0}] * 5)
        self.assertEqual(classify_node(w).attack_type, ATTACK_ONOFF)

    def test_leading_and_trailing_clean_cycles_are_not_off_phases(self):
        # Delayed onset (every attack here supports start_s) must not read as
        # an off phase, or every delayed sybil would be labelled on-off.
        w = window([CLEAN] * 20 + [{SIG_LATENCY_TELL: 6.0}] * 10 + [CLEAN] * 20)
        self.assertEqual(classify_node(w).attack_type, ATTACK_SYBIL)

    def test_more_off_phases_raise_confidence(self):
        bad, good = [{SIG_LATENCY_TELL: 5.0}] * 5, [CLEAN] * 5
        one = classify_node(window(bad + good + bad))
        three = classify_node(window((bad + good) * 3 + bad))
        self.assertGreater(three.confidence, one.confidence)


class TestBlackholeVsGrayhole(unittest.TestCase):
    def test_total_drop_is_blackhole(self):
        w = window([{SIG_PACKET_DROP: 1.0}] * 20)
        self.assertEqual(classify_node(w).attack_type, ATTACK_BLACKHOLE)

    def test_partial_drop_is_grayhole(self):
        w = window([{SIG_PACKET_DROP: 0.55}] * 20)
        self.assertEqual(classify_node(w).attack_type, ATTACK_GRAYHOLE)

    def test_boundary_is_the_documented_threshold(self):
        just_under = window([{SIG_PACKET_DROP: DEFAULT_BLACKHOLE_MIN_RATE - 0.01}] * 9)
        just_over = window([{SIG_PACKET_DROP: DEFAULT_BLACKHOLE_MIN_RATE}] * 9)
        self.assertEqual(classify_node(just_under).attack_type, ATTACK_GRAYHOLE)
        self.assertEqual(classify_node(just_over).attack_type, ATTACK_BLACKHOLE)

    def test_median_not_max_so_one_unlucky_sample_cannot_relabel(self):
        # A grayhole's timeout rate is a binomial sample over a short rolling
        # window, so it WILL touch 1.0 occasionally. A max-based rule would
        # call this a blackhole; the median must not.
        rates = [0.5] * 18 + [1.0, 1.0]
        w = window([{SIG_PACKET_DROP: r} for r in rates])
        self.assertEqual(classify_node(w).attack_type, ATTACK_GRAYHOLE)

    def test_marginal_calls_report_lower_confidence(self):
        clear = classify_node(window([{SIG_PACKET_DROP: 1.0}] * 10))
        marginal = classify_node(
            window([{SIG_PACKET_DROP: DEFAULT_BLACKHOLE_MIN_RATE + 0.005}] * 10)
        )
        self.assertGreater(clear.confidence, marginal.confidence)


class TestSignalPrecedence(unittest.TestCase):
    def test_lying_beats_dropping_because_a_slow_liar_also_times_out(self):
        # A CPU-burning sybil really is slow, so it raises the drop tell too.
        # A pure dropper never raises a lying signal. Asymmetric evidence, so
        # the lying signal is the more specific one and must win.
        w = window([{SIG_LATENCY_TELL: 6.0, SIG_PACKET_DROP: 0.9}] * 20)
        self.assertEqual(classify_node(w).attack_type, ATTACK_SYBIL)

    def test_unreachable_alone_is_a_liveness_failure_not_an_attack(self):
        w = window([{SIG_UNREACHABLE: 1.0}] * 10)
        result = classify_node(w)
        self.assertEqual(result.attack_type, NODE_DOWN)

    def test_a_node_that_lied_then_died_is_still_an_attacker(self):
        w = window([{SIG_LATENCY_TELL: 6.0}] * 10 + [{SIG_UNREACHABLE: 1.0}] * 10)
        self.assertEqual(classify_node(w).attack_type, ATTACK_SYBIL)

    def test_blackhole_is_not_confused_with_node_down(self):
        # This project's blackhole agent answers /status perfectly well and
        # drops only /task, so the two are genuinely different failures.
        self.assertEqual(
            classify_node(window([{SIG_PACKET_DROP: 1.0}] * 10)).attack_type,
            ATTACK_BLACKHOLE,
        )


class TestClientClassification(unittest.TestCase):
    def test_ip_pin_denial_is_spoof(self):
        result = classify_client(window([{SIG_AUTH_IP_PIN: 1.0}]))
        self.assertEqual(result.attack_type, ATTACK_SPOOF)
        self.assertEqual(result.confidence, 1.0)

    def test_bad_response_denial_is_bad_credentials(self):
        result = classify_client(window([{SIG_AUTH_BAD_RESPONSE: 1.0}]))
        self.assertEqual(result.attack_type, ATTACK_BAD_CREDENTIALS)

    def test_flood_tell_is_flood(self):
        result = classify_client(window([{SIG_FLOOD: 40.0}] * 3))
        self.assertEqual(result.attack_type, ATTACK_FLOOD)

    def test_auth_verdicts_latch_but_flood_does_not(self):
        # A cryptographic denial is a discrete event that happened and stays
        # true; a request rate is a condition that can stop holding. The
        # asymmetry is deliberate -- see the module docstring.
        stale = 10_000.0
        spoof = window([{SIG_AUTH_IP_PIN: 1.0}])
        flood = window([{SIG_FLOOD: 40.0}] * 3)
        self.assertIsNotNone(classify_client(spoof, now=stale))
        self.assertIsNone(classify_client(flood, now=stale))

    def test_spoof_beats_flood_when_both_are_present(self):
        w = window([{SIG_FLOOD: 40.0}, {SIG_AUTH_IP_PIN: 1.0}])
        self.assertEqual(classify_client(w).attack_type, ATTACK_SPOOF)

    def test_no_evidence_abstains(self):
        self.assertIsNone(classify_client(window([CLEAN] * 5)))


class TestAttackEvidence(unittest.TestCase):
    def test_records_clean_cycles_so_off_phases_stay_visible(self):
        ev = AttackEvidence()
        t = 0.0
        for _ in range(5):
            ev.record_node('srv1', t, {SIG_LATENCY_TELL: 6.0}); t += 1
        for _ in range(5):
            ev.record_node('srv1', t, {}); t += 1
        for _ in range(5):
            ev.record_node('srv1', t, {SIG_LATENCY_TELL: 6.0}); t += 1
        self.assertEqual(
            ev.classify_node('srv1', now=t).attack_type, ATTACK_ONOFF,
        )

    def test_window_is_bounded(self):
        ev = AttackEvidence(window_cycles=10)
        for i in range(100):
            ev.record_node('srv1', float(i), {})
        self.assertEqual(len(ev._nodes['srv1']), 10)

    def test_unknown_subject_abstains(self):
        self.assertIsNone(AttackEvidence().classify_node('nope'))

    def test_node_and_client_namespaces_are_separate(self):
        # Merging them would let a flooding client be scored against the edge
        # node it overwhelmed -- the misattribution flood_detector.py exists
        # to prevent.
        ev = AttackEvidence()
        ev.record_node('srv1', 0.0, {SIG_LATENCY_TELL: 6.0})
        ev.record_client('srv1', 0.0, {SIG_FLOOD: 40.0})
        self.assertEqual(ev.node_subjects(), ['srv1'])
        self.assertEqual(ev.client_subjects(), ['srv1'])
        self.assertEqual(
            ev.classify_node('srv1', now=1.0).attack_type, ATTACK_SYBIL,
        )
        self.assertEqual(
            ev.classify_client('srv1', now=1.0).attack_type, ATTACK_FLOOD,
        )


class TestOnOffDetectabilityFloor(unittest.TestCase):
    def test_floor_matches_the_leaky_bucket_drain_plus_min_clean_run(self):
        # Pins the documented relationship in ONOFF_MIN_GOOD_PHASE_S: the
        # classifier cannot see an off phase shorter than the detector's own
        # reaction time, and simulation/topology.py's onoff default is chosen
        # to clear it. If either side changes, this fails rather than the two
        # drifting apart silently.
        from controller.attack_classifier import ONOFF_MIN_GOOD_PHASE_S
        self.assertEqual(ONOFF_MIN_GOOD_PHASE_S, (1 + DEFAULT_MIN_CLEAN_RUN) * 1.0)

    def test_topology_onoff_default_clears_the_floor(self):
        import re
        from pathlib import Path

        from controller.attack_classifier import ONOFF_MIN_GOOD_PHASE_S

        src = Path('simulation/topology.py').read_text()
        period = float(re.search(r"onoff_period_s', ([\d.]+)\)", src).group(1))
        duty = float(re.search(r"onoff_duty', ([\d.]+)\)", src).group(1))
        good_phase_s = period * (1.0 - duty)
        self.assertGreater(good_phase_s, ONOFF_MIN_GOOD_PHASE_S)


if __name__ == '__main__':
    unittest.main()
