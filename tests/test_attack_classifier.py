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
    DEFAULT_MIN_LYING_SHARE,
    DEFAULT_MIN_QUIET_FRACTION,
    NODE_DOWN,
    SIG_AUTH_BAD_RESPONSE,
    SIG_AUTH_IP_PIN,
    SIG_CPU_HONESTY,
    SIG_FLOOD,
    SIG_LATENCY_TELL,
    SIG_PACKET_DROP,
    SIG_TRUST_COLLAPSE,
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


class TestOnOffNeedsSustainedIntermittency(unittest.TestCase):
    """Incidental quiet polls are not an on-off pattern.

    Live run 8's srv3 is the case these pin: a steady sybil, flagged on 198 of
    250 cycles, whose clean runs were nearly all a single poll of jitter --
    except two that happened to reach exactly DEFAULT_MIN_CLEAN_RUN. Under the
    old `off_phases >= 1` rule that was enough to report a sustained liar as
    intermittent for 165 of its 220 classified cycles. The distinguishing
    quantity is not how many gaps there are but how much of the active span is
    actually quiet: srv3 2.4%, the genuine on-off srv8 64%.
    """

    BAD = {SIG_LATENCY_TELL: 6.0}

    def test_steady_liar_with_two_incidental_gaps_stays_sybil(self):
        # srv3's shape in miniature: a long stretch of lying broken by two
        # floor-length gaps that together are a rounding error of the span.
        gap = [CLEAN] * DEFAULT_MIN_CLEAN_RUN
        w = window([self.BAD] * 60 + gap + [self.BAD] * 60 + gap + [self.BAD] * 60)
        result = classify_node(w)
        self.assertEqual(result.attack_type, ATTACK_SYBIL)
        self.assertIn('sustained misreporting', result.rationale)

    def test_genuinely_intermittent_attacker_is_still_onoff(self):
        # The other half: the same two gaps, but now they are most of the span.
        bad, good = [self.BAD] * 4, [CLEAN] * 8
        result = classify_node(window(bad + good + bad + good + bad))
        self.assertEqual(result.attack_type, ATTACK_ONOFF)
        self.assertIn('sustained intermittency', result.rationale)

    def test_many_sub_floor_gaps_cannot_accumulate_to_the_bar(self):
        # A noisy liar that clears for one or two polls constantly would reach
        # the quiet fraction on raw clean-cycle count alone. Gaps shorter than
        # min_clean_run are the detector's own drain time, so they must not
        # count toward quiet time any more than they count as off phases.
        jitter = [self.BAD] + [CLEAN] * (DEFAULT_MIN_CLEAN_RUN - 1)
        w = window(jitter * 40 + [self.BAD])
        self.assertEqual(classify_node(w).attack_type, ATTACK_SYBIL)

    def test_the_boundary_is_the_documented_fraction(self):
        # 3 clean cycles inside a 13-cycle span = 23%, over the 20% bar;
        # 3 inside 21 = 14%, under it. Same gap, same off-phase count -- only
        # the share of the span differs, which is exactly the rule's claim.
        gap = [CLEAN] * DEFAULT_MIN_CLEAN_RUN
        over = window([self.BAD] * 5 + gap + [self.BAD] * 5)
        under = window([self.BAD] * 9 + gap + [self.BAD] * 9)
        self.assertEqual(classify_node(over).attack_type, ATTACK_ONOFF)
        self.assertEqual(classify_node(under).attack_type, ATTACK_SYBIL)
        # The two spans above straddle 20%; if the constant moves, they stop
        # testing the boundary and this says so rather than passing quietly.
        self.assertEqual(DEFAULT_MIN_QUIET_FRACTION, 0.20)


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


class TestTrustRailEvidence(unittest.TestCase):
    """The trust rail establishes the drop FAMILY and never the magnitude.

    Live run 8's srv6: a blackhole quarantined 9.7s after onset on the trust
    rail with anomaly 0.0, three task outcomes in the whole run, and not one
    flagged cycle in 250 -- so the classifier abstained on a perfectly
    contained attack. SIG_TRUST_COLLAPSE is how the label gets to exist.
    """

    def test_trust_collapse_alone_establishes_the_drop_family(self):
        w = window([{SIG_TRUST_COLLAPSE: 1.0}] * 10)
        result = classify_node(w)
        self.assertEqual(result.attack_type, ATTACK_GRAYHOLE)
        self.assertIn('magnitude is not', result.rationale)

    def test_it_reports_the_weaker_claim_when_the_magnitude_is_unmeasured(self):
        # Even at a 100% post-collapse failure rate -- which is what a
        # blackhole looks like -- the label stays grayhole, because the rate is
        # over a handful of probation trials and cannot carry the split. The
        # safe direction is understating the attack, not the uncertainty.
        result = classify_node(window([{SIG_TRUST_COLLAPSE: 1.0}] * 10))
        self.assertEqual(result.attack_type, ATTACK_GRAYHOLE)
        self.assertLess(result.confidence, 0.5)

    def test_a_measured_rate_still_decides_the_magnitude(self):
        # When the drop tell HAS enough samples, nothing about the trust rail
        # weakens it: a real blackhole is still a blackhole.
        w = window([{SIG_PACKET_DROP: 1.0, SIG_TRUST_COLLAPSE: 1.0}] * 10)
        self.assertEqual(classify_node(w).attack_type, ATTACK_BLACKHOLE)

    def test_trust_collapse_cannot_promote_a_grayhole_to_a_blackhole(self):
        """THE REASON THE MAGNITUDE IS NOT TAKEN FROM THE TRUST RAIL.

        Measured on live run 8: srv1 was a true grayhole, and its first two
        post-collapse outcomes were both timeouts -- 2/2 = 1.00, identical to
        the blackhole srv6's reading. Every sample bar that keeps srv1 correct
        excludes srv6 entirely, because a blackhole fails everything, so it is
        isolated fastest, so it yields the fewest outcomes to characterise it.
        Containment quality and magnitude evidence are in direct tension, and
        the resolution is to let only the measured rate split the pair.
        """
        w = window([{SIG_PACKET_DROP: 0.55}] * 20
                   + [{SIG_TRUST_COLLAPSE: 1.0}] * 5)
        self.assertEqual(classify_node(w).attack_type, ATTACK_GRAYHOLE)

    def test_it_does_not_dilute_the_lying_weighing(self):
        # A liar that also collapses on trust must stay in the sybil family:
        # the lying share is measured over family-bearing cycles, so extra
        # drop-side cycles cannot quietly push a real liar under the bar.
        w = window([{SIG_LATENCY_TELL: 6.0}] * 12
                   + [{SIG_LATENCY_TELL: 6.0, SIG_TRUST_COLLAPSE: 1.0}] * 8)
        self.assertEqual(classify_node(w).attack_type, ATTACK_SYBIL)


class TestSignalPrecedence(unittest.TestCase):
    def test_lying_beats_dropping_because_a_slow_liar_also_times_out(self):
        # A CPU-burning sybil really is slow, so it raises the drop tell too.
        # It raises the lying signal on essentially every flagged cycle
        # (measured 95-96% in live run 8), so it still wins outright.
        w = window([{SIG_LATENCY_TELL: 6.0, SIG_PACKET_DROP: 0.9}] * 20)
        self.assertEqual(classify_node(w).attack_type, ATTACK_SYBIL)

    def test_a_minority_of_lying_cycles_cannot_outweigh_the_drops(self):
        # THE RUN-7 DEFECT. The old rule promoted a subject out of the drop
        # family on ANY lying signal, on the premise that a pure dropper never
        # raises one. Live run 7 disproved the premise: the honesty check's
        # biased fallback fired on droppers, and srv1 (grayhole) was reported
        # as a sybil, srv6 (blackhole) as an on-off, off a handful of spurious
        # cycles against dozens of true ones.
        w = window([{SIG_PACKET_DROP: 0.55}] * 18
                   + [{SIG_PACKET_DROP: 0.55, SIG_CPU_HONESTY: 0.9}] * 2)
        result = classify_node(w)
        self.assertEqual(result.attack_type, ATTACK_GRAYHOLE)
        self.assertIn('too thin to outweigh the drops', result.rationale)

    def test_the_boundary_is_the_documented_share(self):
        drop_only = {SIG_PACKET_DROP: 0.55}
        both = {SIG_PACKET_DROP: 0.55, SIG_CPU_HONESTY: 0.9}
        # Exactly at the share: the lying family takes it.
        at = window([both] * 10 + [drop_only] * 10)
        self.assertEqual(classify_node(at).attack_type, ATTACK_SYBIL)
        # One cycle under: it stays a dropper.
        under = window([both] * 9 + [drop_only] * 11)
        self.assertEqual(classify_node(under).attack_type, ATTACK_GRAYHOLE)
        self.assertEqual(DEFAULT_MIN_LYING_SHARE, 0.5)

    def test_lying_with_no_drops_at_all_is_still_the_sybil_family(self):
        # The weighing rule must not create a hole for a liar that never times
        # a task out -- p2c can starve a quarantined liar of traffic entirely,
        # so "no drop evidence" is a routine state, not an exonerating one.
        w = window([CLEAN] * 30 + [{SIG_CPU_HONESTY: 0.9}] * 2)
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
