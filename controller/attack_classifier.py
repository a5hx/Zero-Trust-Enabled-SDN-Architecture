"""Attack classification -- detector signals in, one discrete attack label out.
plan_adv.md Phase 2.

The detectors this project already had answer "is this subject misbehaving?"
They do it well, but they answer it as free-text `reasons` prose attached to an
`anomaly` event, so the recording says *"anomaly, and here is a sentence about
why"* and never `attack_type: sybil`. mam's second ask was the discrete label
and a real confusion matrix behind it. This module is the label.

Deliberately a pure function over an evidence window -- no I/O, no locks, no
TrustState -- for the same reason `evaluate_latency_tell` and
`evaluate_flood_tell` are: the live controller and the offline scorer
(`evaluation/attack_report.py`) must reach the *same* verdict from the same
evidence, and the only way to guarantee that is to have one implementation
they both call rather than two that drift.

Why a WINDOW and not a single detection cycle
---------------------------------------------
Two of the six attacks are simply not separable from one cycle's signals, and
pretending otherwise would produce a confusion matrix that looks good by
collapsing the distinctions it was built to measure:

  * blackhole vs. grayhole fire the *same* signal (the packet-drop timeout
    tell). They differ only in MAGNITUDE -- a blackhole drops everything, a
    grayhole drops a fraction. One cycle cannot tell you which.
  * sybil vs. on-off fire the *same* signals (the latency tell, and the CPU
    honesty check once load accumulates). They differ only in INTERMITTENCY --
    an on-off attacker goes genuinely, measurably honest between phases, which
    is the whole point of it. One cycle cannot tell you which either.

So a cycle's worth of signals is an `Observation`, and classification reads a
sequence of them.

Abstention
----------
A window whose newest observation is stale returns None, and a window with no
flagged cycle at all returns None. Neither is "this subject is innocent" -- it
is "this classifier has no current opinion", which is the rule established by
memory/quarantine-absorbing-state: *a detector with no recent evidence must
abstain, not re-assert its last verdict*. Deciding what an abstention means
for a score belongs to the scorer, not here.

One exception, and it is a real distinction rather than a convenience: the
auth-layer signals are LATCHING, the load/traffic signals are not. "This
device presented a correct response for another device's identity at t=5" is a
historical fact that stays true; "this node is currently slow while claiming
to be idle" is a condition that can stop being true. Re-asserting the first
after it goes stale is a record, not a stale verdict. Re-asserting the second
would be exactly the absorbing-state bug in a new shape.

node_down is not an attack
--------------------------
A node that stops answering /status is scored `node_down`, never folded into
blackhole. They are genuinely different: this project's blackhole agent
answers /status perfectly well and drops only /task (see
simulation/node_agent.py), so "silent on /status" is a liveness failure, not
one of the six attacks. Labelling a crashed node as an attacker would inflate
exactly the detection numbers this module exists to measure honestly -- the
same "correctly isolated attacker vs. wrongly blamed honest party" discipline
as memory/edgescore-fanout-starvation and
memory/live-run-cascading-quarantine.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Mapping, NamedTuple, Optional, Sequence

# --------------------------------------------------------------------------- #
# Signal keys. Emitted as a structured dict alongside (never instead of) the
# human-readable `reasons` prose the dashboard renders -- classification must
# not depend on regexing sentences that were written to be read by people.
# --------------------------------------------------------------------------- #
SIG_CPU_HONESTY = 'cpu_honesty'      # value: |claimed - reference| deviation
SIG_LATENCY_TELL = 'latency_tell'    # value: measured RTT / fleet median
SIG_PACKET_DROP = 'packet_drop'      # value: recent timeout rate, 0..1
SIG_UNREACHABLE = 'unreachable'      # value: 1.0 (presence is the signal)
SIG_FLOOD = 'flood'                  # value: measured rate / expected rate
SIG_AUTH_IP_PIN = 'auth_ip_pin'      # value: 1.0 -- correct key, wrong source
SIG_AUTH_BAD_RESPONSE = 'auth_bad_response'   # value: 1.0 -- key not held
SIG_TRUST_COLLAPSE = 'trust_collapse'  # value: post-collapse failure rate, 0..1

# Signals that say "this subject is lying about its own load". A pure dropper
# reports its CPU honestly and answers /status at fleet speed, so it never
# raises either of these -- which is what lets the drop family be told apart
# from the sybil family at all.
_LYING_SIGNALS = (SIG_CPU_HONESTY, SIG_LATENCY_TELL)
_AUTH_SIGNALS = (SIG_AUTH_IP_PIN, SIG_AUTH_BAD_RESPONSE)

#: Signals that say "this subject loses the work it is given". Both put a
#: subject in the drop family, but only SIG_PACKET_DROP carries a timeout rate
#: measured over enough samples to split blackhole from grayhole --
#: SIG_TRUST_COLLAPSE deliberately does not. See _split_drop_family.
_DROP_SIGNALS = (SIG_PACKET_DROP, SIG_TRUST_COLLAPSE)

# --------------------------------------------------------------------------- #
# Labels
# --------------------------------------------------------------------------- #
ATTACK_SYBIL = 'sybil'
ATTACK_BLACKHOLE = 'blackhole'
ATTACK_GRAYHOLE = 'grayhole'
ATTACK_ONOFF = 'onoff'
ATTACK_FLOOD = 'flood'
ATTACK_SPOOF = 'spoof'
ATTACK_BAD_CREDENTIALS = 'bad_credentials'
NODE_DOWN = 'node_down'
NO_ATTACK = 'none'

#: Every label the classifier can emit, plus NO_ATTACK for the scorer's benefit.
#: Ordered so a confusion matrix's axes come out in a stable, readable order
#: rather than whatever a set iteration happens to give.
ALL_LABELS = (
    ATTACK_SYBIL,
    ATTACK_BLACKHOLE,
    ATTACK_GRAYHOLE,
    ATTACK_ONOFF,
    ATTACK_FLOOD,
    ATTACK_SPOOF,
    ATTACK_BAD_CREDENTIALS,
    NODE_DOWN,
    NO_ATTACK,
)

#: Label -> family. Two of the six attacks are separable from their sibling
#: only by MAGNITUDE (blackhole/grayhole) and two only by INTERMITTENCY
#: (sybil/onoff), and both distinctions need evidence the defence sometimes
#: prevents from ever accumulating -- see _split_drop_family and
#: ONOFF_MIN_GOOD_PHASE_S. Scoring the family alongside the exact label
#: separates "the system had no idea" from "the system knew what kind of attack
#: this was but could not resolve which of the pair", which are very different
#: results and were previously both reported as a plain miss.
ATTACK_FAMILIES = {
    ATTACK_SYBIL: 'load-dishonesty',
    ATTACK_ONOFF: 'load-dishonesty',
    ATTACK_BLACKHOLE: 'dropping',
    ATTACK_GRAYHOLE: 'dropping',
    ATTACK_FLOOD: 'flooding',
    ATTACK_SPOOF: 'identity',
    ATTACK_BAD_CREDENTIALS: 'identity',
    NODE_DOWN: 'liveness',
    NO_ATTACK: 'none',
}


def family_of(label: str) -> str:
    """The family a label belongs to; unknown labels are their own family."""
    return ATTACK_FAMILIES.get(label, label)


#: The config `attack` strings used in simulation/*.yaml and surfaced as ground
#: truth on the `topology` event, mapped to this module's labels. 'drop' is what
#: node_agent.py has always called its always-drop mode; 'blackhole' is the
#: standard name a panel will expect (plan_adv.md §4 chose to rename it in
#: reporting only, leaving the agent's CLI value alone).
GROUND_TRUTH_ALIASES = {
    'drop': ATTACK_BLACKHOLE,
    'blackhole': ATTACK_BLACKHOLE,
    'sybil': ATTACK_SYBIL,
    'grayhole': ATTACK_GRAYHOLE,
    'onoff': ATTACK_ONOFF,
    'flood': ATTACK_FLOOD,
    'spoof': ATTACK_SPOOF,
    'bad_credentials': ATTACK_BAD_CREDENTIALS,
    'none': NO_ATTACK,
}

# --------------------------------------------------------------------------- #
# Tunables
# --------------------------------------------------------------------------- #
#: Median timeout rate at or above which a dropper is called a blackhole rather
#: than a grayhole. The MEDIAN over flagged cycles, not the max: a grayhole's
#: rate is a binomial sample over a short rolling window
#: (TrustState._recent_statuses is 10 deep), so given enough cycles it WILL
#: touch 1.0 by chance and a max-based rule would relabel it a blackhole on one
#: unlucky draw. The median needs the subject to drop everything *typically*.
DEFAULT_BLACKHOLE_MIN_RATE = 0.85

#: Consecutive clean cycles that count as a genuine "off" phase. The latency
#: tell's leaky bucket drains one strike per clean poll from a trip level of 3,
#: so a subject that has genuinely stopped misbehaving needs ~3 clean polls to
#: fall silent. Requiring 3 means ordinary single-poll jitter can never be read
#: as an off phase, so a steady sybil is not relabelled on-off by noise.
DEFAULT_MIN_CLEAN_RUN = 3

#: THE ON-OFF DETECTABILITY FLOOR -- a real limit, stated rather than hidden.
#:
#: Separating on-off from sybil requires actually OBSERVING a quiet stretch, so
#: the attacker's good phase has to outlast the detector's own reaction time.
#: After a bad->good switch the latency tell's bucket sits at persist+1 (4) and
#: drains one per poll, so it keeps flagging for ~1 more poll before going
#: quiet, and only then can min_clean_run clean polls accumulate:
#:
#:     good_phase_s  >~  (1 + DEFAULT_MIN_CLEAN_RUN) * poll_interval_s   ~= 4 s
#:
#: An attacker that toggles faster than that is still caught -- it trips the
#: same tells and is quarantined exactly like a sybil -- but it is *classified*
#: as sybil, because at that timescale its intermittency is genuinely below the
#: 1 Hz sampling resolution and no amount of tuning here recovers it. That is a
#: sampling limit, not a bug, and it is the honest thing to report: the label is
#: wrong while the defence is not. simulation/topology.py's default
#: onoff_period_s is set to clear this floor with margin so the distinction is
#: actually demonstrable; a deliberately faster attacker is the interesting
#: adversarial case to measure against it, not something to tune away.
ONOFF_MIN_GOOD_PHASE_S = (1 + DEFAULT_MIN_CLEAN_RUN) * 1.0

#: How old the newest observation may be before the classifier abstains,
#: expressed in seconds. Mirrors DEFAULT_TIMEOUT_EVIDENCE_AGE_FACTOR's role in
#: TrustState.recent_timeout_rate -- same rule, same reason.
DEFAULT_EVIDENCE_MAX_AGE_S = 15.0

#: Cycles retained per subject by AttackEvidence.
#:
#: This is the SECOND on-off resolution constraint, and it bites independently
#: of ONOFF_MIN_GOOD_PHASE_S above. Naming an attacker on-off requires the
#: window to hold a bad phase, a full good phase, AND the resumption after it.
#: A window narrower than a whole on-off period mostly contains one phase at a
#: time, so it sees sustained misbehaviour and correctly-by-its-own-lights
#: reports sybil. Measured directly in tests/test_attack_report.py: a 10-cycle
#: window over a 12-cycle period yields a sybil verdict for most of the run.
#:
#:     window_cycles  >~  2 * onoff_period_s / poll_interval_s
#:
#: 120 at the 1 Hz poll rate is two minutes, i.e. six periods at
#: simulation/topology.py's 20s onoff default -- comfortably clear.
DEFAULT_WINDOW_CYCLES = 120

#: Fraction of the subject's ACTIVE SPAN that must fall inside qualifying off
#: phases before the on-off label is used.
#:
#: Live run 8 measured why counting off phases is not enough. srv3, a steady
#: sybil, flagged on 198 of 250 cycles and its clean runs were almost all a
#: single poll of jitter -- but two of them happened to reach exactly
#: min_clean_run, so `off_phases >= 1` fired and a sustained liar was reported
#: as intermittent for 165 of its 220 classified cycles. Requiring two off
#: phases does not separate them either: srv3 had exactly two.
#:
#: What does separate them is how much of the span is actually quiet, and it is
#: not a close call:
#:
#:     srv3 (true sybil): 6 quiet cycles / 250 span  =  2.4%
#:     srv8 (true onoff): ~145 quiet cycles / 227 span = 64%
#:
#: The threshold is derived rather than fitted. An on-off attacker with duty
#: cycle d is quiet for (1 - d) of its period, less the detector's own reaction
#: lag -- the same (1 + min_clean_run) cycles that ONOFF_MIN_GOOD_PHASE_S is
#: built from -- eaten off the front of every good phase:
#:
#:     quiet_fraction  ~=  (1 - d) - (1 + min_clean_run) / period_cycles
#:
#: At topology.py's defaults (d = 0.5, period 20 s, 1 Hz polling) that is
#: 0.5 - 0.2 = 0.30. Setting the bar at 0.20 accepts attackers up to d ~= 0.6
#: while sitting an order of magnitude above the incidental-gap case. A faster
#: or busier on-off attacker falls back to `sybil`, which is the same honest
#: degradation ONOFF_MIN_GOOD_PHASE_S already documents: the attacker is still
#: caught and quarantined, only the label loses resolution.
#:
#: A minimum off-phase COUNT was tried alongside this and deliberately dropped.
#: "Two gaps make a rhythm, one makes an interruption" sounds right, but srv3
#: had exactly two, so it does not separate the measured cases -- and requiring
#: two full off phases inside the window would raise the window constraint
#: below from 2x the on-off period to 3x, and delay every on-off verdict by a
#: phase, to buy nothing the quiet fraction was not already buying. One derived
#: rule beats two, and `quiet_fraction >= x > 0` already implies at least one
#: qualifying off phase.
DEFAULT_MIN_QUIET_FRACTION = 0.20

#: Share of a subject's flagged cycles that must carry a lying signal before it
#: is judged as a liar rather than as a dropper. See the weighing rule in
#: classify_node -- this replaced an absolute precedence whose premise ("a pure
#: dropper never raises a lying signal") live run 7 disproved.
DEFAULT_MIN_LYING_SHARE = 0.5


class Observation(NamedTuple):
    """One detection cycle's evidence about one subject.

    An Observation with empty `signals` is a CLEAN CYCLE -- positive evidence
    that the subject was checked and found fine. That is not the same as no
    observation at all, and the on-off rule depends entirely on the difference:
    without recorded clean cycles there is no way to see an attacker go quiet.
    """

    t: float
    signals: Mapping[str, float]


@dataclass(frozen=True)
class Classification:
    """A verdict about one subject.

    confidence is an evidence-strength heuristic in [0, 1] -- more flagged
    cycles and a wider margin from the deciding threshold give a higher number.
    It is deliberately NOT presented as a calibrated probability, because
    nothing here was fitted to produce one; it exists to rank verdicts and to
    let a reader see which calls were marginal.
    """

    attack_type: str
    confidence: float
    rationale: str
    evidence_cycles: int
    first_flagged_t: Optional[float] = None


def _flagged(window: Sequence[Observation]) -> list:
    return [o for o in window if o.signals]


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


class OffPhases(NamedTuple):
    """How intermittent a subject's misbehaviour was, over its active span.

    `count` alone is not enough to call something on-off -- see
    DEFAULT_MIN_QUIET_FRACTION, where a steady sybil produced two qualifying
    gaps out of 198 flagged cycles. `quiet_fraction` is what says whether the
    quiet is the subject's normal condition or a couple of stray polls.
    """

    count: int
    quiet_cycles: int
    span_cycles: int

    @property
    def quiet_fraction(self) -> float:
        return self.quiet_cycles / self.span_cycles if self.span_cycles else 0.0


def _measure_off_phases(
    window: Sequence[Observation], min_clean_run: int,
) -> OffPhases:
    """Measure the quiet stretches the subject took between misbehaving.

    Only the span from the first flagged cycle to the last is considered: clean
    cycles before a subject ever misbehaves are its honest pre-onset life (every
    attack in this project supports a delayed `start_s`), and clean cycles after
    the last flag are either recovery or the end of the recording. Neither is an
    "off phase" -- an off phase is bounded by misbehaviour on both sides, which
    is precisely the on-off signature and precisely what a steady sybil never
    produces.

    Gaps shorter than min_clean_run are NOT counted toward `quiet_cycles`
    either. They are the detector's own drain time and ordinary poll jitter, and
    letting them accumulate would let a subject with a hundred single-poll gaps
    reach the quiet-fraction bar without ever having gone genuinely quiet once.
    """
    indices = [i for i, o in enumerate(window) if o.signals]
    if len(indices) < 2:
        return OffPhases(0, 0, len(indices))

    count = 0
    quiet = 0
    for a, b in zip(indices, indices[1:]):
        gap = b - a - 1          # clean cycles strictly between two flagged ones
        if gap >= min_clean_run:
            count += 1
            quiet += gap
    return OffPhases(count, quiet, indices[-1] - indices[0] + 1)


def classify_node(
    window: Sequence[Observation],
    now: Optional[float] = None,
    blackhole_min_rate: float = DEFAULT_BLACKHOLE_MIN_RATE,
    min_clean_run: int = DEFAULT_MIN_CLEAN_RUN,
    evidence_max_age_s: float = DEFAULT_EVIDENCE_MAX_AGE_S,
    min_quiet_fraction: float = DEFAULT_MIN_QUIET_FRACTION,
    min_lying_share: float = DEFAULT_MIN_LYING_SHARE,
) -> Optional[Classification]:
    """Label an edge node from its recent detection cycles.

    Args:
        window: observations oldest-first, including clean cycles (see
            Observation -- the on-off rule cannot work without them).
        now: current time, for the staleness check. None skips the check, which
            is what the offline scorer wants when replaying a finished
            recording (there, "stale" is meaningless -- the run is over).

    Returns:
        A Classification, or None to abstain. None is never "innocent"; see the
        module docstring.
    """
    if not window:
        return None
    if now is not None and (now - window[-1].t) > evidence_max_age_s:
        # Stale evidence: abstain rather than re-assert the last verdict.
        return None

    flagged = _flagged(window)
    if not flagged:
        return None

    first_flagged_t = flagged[0].t
    n_flagged = len(flagged)

    lying = [o for o in flagged if any(s in o.signals for s in _LYING_SIGNALS)]
    dropping = [o for o in flagged if any(s in o.signals for s in _DROP_SIGNALS)]
    unreachable = [o for o in flagged if SIG_UNREACHABLE in o.signals]
    # Only the packet-drop tell's rate is a rate: it is measured over at least
    # _MIN_TIMEOUT_SAMPLES outcomes. See _split_drop_family.
    rated = [float(o.signals[SIG_PACKET_DROP]) for o in flagged
             if SIG_PACKET_DROP in o.signals]
    # The weighing below is lying-vs-dropping, so it is measured over the cycles
    # that carry one of those two families and no others. An unreachable-only
    # cycle is evidence for neither and must not dilute either side.
    n_family = sum(
        1 for o in flagged
        if any(s in o.signals for s in _LYING_SIGNALS)
        or any(s in o.signals for s in _DROP_SIGNALS)
    )

    # --- Liveness failure, checked first and never merged into an attack ---
    # Only when nothing else EVER fired in the window. A node that lied and
    # then died is still an attacker; a node that only ever went silent is a
    # node that went silent. See the module docstring.
    if unreachable and not lying and not dropping:
        return Classification(
            attack_type=NODE_DOWN,
            confidence=min(1.0, len(unreachable) / 5.0),
            rationale=(
                f'/status unreachable on {len(unreachable)} of {len(window)} '
                f'cycles, with no honesty, latency or drop signal ever raised '
                f'-- liveness failure, not one of the modelled attacks'
            ),
            evidence_cycles=n_flagged,
            first_flagged_t=first_flagged_t,
        )

    # --- Sybil family: the subject lied about its own load -------------------
    # This used to be an outright precedence -- ANY lying signal promoted the
    # subject out of the drop family -- justified by "a pure dropper never
    # raises a lying signal, since it reports its load honestly and answers
    # /status at fleet speed". Live run 7 disproved that premise against real
    # telemetry: the honesty check's biased fallback fired on droppers, and the
    # precedence turned srv1 (grayhole) into a sybil and srv6 (blackhole) into
    # an on-off. One spurious cycle was enough to overrule dozens of true ones.
    #
    # The asymmetry the rule was built on is real and worth keeping -- a
    # CPU-burning liar genuinely does time tasks out too, so it raises both
    # families and must not be filed as a mere dropper. What was wrong was
    # treating it as absolute rather than as evidence to be weighed. A real
    # liar lies on essentially every cycle it is flagged on (live run 8: srv3
    # 188/198 = 95%, srv8 55/57 = 96%); a dropper with contaminated telemetry
    # lies on a minority. Requiring the lying signal to carry at least half the
    # flagged cycles sits ~0.45 clear of both populations, so it is a wide gap
    # rather than a fitted line.
    lying_share = len(lying) / n_family if n_family else 0.0
    if lying and (lying_share >= min_lying_share or not dropping):
        off = _measure_off_phases(window, min_clean_run)
        # Intermittency has to be SUSTAINED to name the attack on-off, not just
        # present. See DEFAULT_MIN_QUIET_FRACTION: a steady sybil throws off a
        # qualifying gap now and then by chance, and a single-gap rule read
        # 165 of srv3's 220 classified cycles as on-off in live run 8.
        if off.quiet_fraction >= min_quiet_fraction:
            return Classification(
                attack_type=ATTACK_ONOFF,
                confidence=min(1.0, 0.5 + 0.25 * off.count),
                rationale=(
                    f'load-dishonesty signals on {len(lying)} cycle(s), '
                    f'interrupted by {off.count} clean run(s) of >= '
                    f'{min_clean_run} cycles accounting for '
                    f'{off.quiet_fraction:.0%} of its active span -- '
                    f'sustained intermittency, not steady misbehaviour'
                ),
                evidence_cycles=n_flagged,
                first_flagged_t=first_flagged_t,
            )
        return Classification(
            attack_type=ATTACK_SYBIL,
            confidence=min(1.0, len(lying) / 10.0),
            rationale=(
                f'load-dishonesty signals on {len(lying)} cycle(s), quiet for '
                f'only {off.quiet_fraction:.0%} of its active span across '
                f'{off.count} clean run(s) of >= {min_clean_run} cycles -- '
                f'sustained misreporting of its own load'
            ),
            evidence_cycles=n_flagged,
            first_flagged_t=first_flagged_t,
        )

    # --- Drop family: honest about load, loses the work ----------------------
    if dropping:
        contested = (
            '' if not lying else
            f', against load-dishonesty on only {len(lying)} of '
            f'{n_family} family cycle(s) ({lying_share:.0%}, under '
            f'{min_lying_share:.0%}) -- too thin to outweigh the drops'
        )
        label, confidence, why = _split_drop_family(
            dropping, rated, blackhole_min_rate,
        )
        return Classification(
            attack_type=label,
            confidence=confidence,
            rationale=why + contested + ' -- loses the work it is given',
            evidence_cycles=n_flagged,
            first_flagged_t=first_flagged_t,
        )

    return None


def _split_drop_family(
    dropping: Sequence[Observation],
    rated: Sequence[float],
    blackhole_min_rate: float,
) -> tuple:
    """Blackhole or grayhole -- and what to do when only one of those is knowable.

    Blackhole and grayhole differ only in MAGNITUDE, so splitting them needs a
    timeout RATE, and a rate needs samples. The packet-drop tell supplies one
    measured over at least _MIN_TIMEOUT_SAMPLES outcomes. SIG_TRUST_COLLAPSE
    does not, and must not be allowed to pretend otherwise.

    Live run 8 measured why, and the result was the opposite of what
    plan_adv.md predicted. Feeding the trust rail's own post-collapse failure
    rate into this split does name srv6 (a true blackhole, 3 outcomes all run)
    correctly -- but it also renames srv1 (a true grayhole) a blackhole, because
    srv1's first two post-collapse outcomes were both timeouts and 2/2 is 1.00.
    Every sample bar that keeps srv1 right excludes srv6 entirely. That is not
    a tuning problem to be solved, it is the shape of the evidence:

        A blackhole fails everything, so it is isolated fastest, so it yields
        the fewest outcomes to characterise it. Containment quality and
        magnitude evidence are in direct tension.

    So the trust rail establishes the FAMILY and is not consulted on the
    magnitude. With no rate available the call degrades to grayhole -- the
    weaker of the two claims, understating the attack rather than the system's
    knowledge of it, the same safe direction as reporting detection latency as
    an upper bound. Confidence is floored to say the call is thin, and the
    rationale names the reason so no reader mistakes it for a measurement.
    """
    if not rated:
        return (
            ATTACK_GRAYHOLE,
            0.25,
            f'trust-rail isolation on {len(dropping)} cycle(s) with no '
            f'packet-drop tell to measure a timeout rate -- the drop family is '
            f'established but its magnitude is not, so this reports the weaker '
            f'of blackhole/grayhole',
        )

    median_rate = _median(rated)
    is_blackhole = median_rate >= blackhole_min_rate
    # Confidence falls off as the measured rate approaches the threshold from
    # either side -- a grayhole configured at 0.84 genuinely is a marginal call
    # and should read as one rather than as a confident blackhole-or-not.
    margin = abs(median_rate - blackhole_min_rate)
    return (
        ATTACK_BLACKHOLE if is_blackhole else ATTACK_GRAYHOLE,
        min(1.0, 0.5 + margin * 2.0),
        f'packet-drop tell on {len(rated)} cycle(s), median timeout rate '
        f'{median_rate:.2f} {">=" if is_blackhole else "<"} '
        f'{blackhole_min_rate:.2f}',
    )


def classify_client(
    window: Sequence[Observation],
    now: Optional[float] = None,
    evidence_max_age_s: float = DEFAULT_EVIDENCE_MAX_AGE_S,
) -> Optional[Classification]:
    """Label an IoT device/client from its recent evidence.

    A separate function from classify_node, not a mode of it, because the
    subject is a different kind of thing: the signals differ, and blaming an
    edge node for a client-side attack is the specific mistake
    controller/flood_detector.py's docstring exists to prevent.

    The auth signals LATCH and the flood signal does not -- see the module
    docstring for why that asymmetry is correct rather than convenient.
    """
    if not window:
        return None

    flagged = _flagged(window)
    if not flagged:
        return None

    first_flagged_t = flagged[0].t

    # Auth denials first, and exempt from the staleness check: a cryptographic
    # denial is a discrete event that happened, not a condition that might have
    # stopped holding. It also needs no persistence filter -- unlike every
    # statistical tell here, it cannot fire by chance.
    ip_pin = [o for o in flagged if SIG_AUTH_IP_PIN in o.signals]
    if ip_pin:
        return Classification(
            attack_type=ATTACK_SPOOF,
            confidence=1.0,
            rationale=(
                f'{len(ip_pin)} auth denial(s) for a device_id already pinned '
                f'to a different source IP -- a correct response from the wrong '
                f'host, which is possession of the fleet key without ownership '
                f'of the identity'
            ),
            evidence_cycles=len(flagged),
            first_flagged_t=first_flagged_t,
        )

    bad_key = [o for o in flagged if SIG_AUTH_BAD_RESPONSE in o.signals]
    if bad_key:
        return Classification(
            attack_type=ATTACK_BAD_CREDENTIALS,
            confidence=1.0,
            rationale=(
                f'{len(bad_key)} auth denial(s) on a wrong response -- the '
                f'device does not hold the fleet key and was refused at '
                f'admission, before any routing or trust logic saw it'
            ),
            evidence_cycles=len(flagged),
            first_flagged_t=first_flagged_t,
        )

    if now is not None and (now - window[-1].t) > evidence_max_age_s:
        return None

    flood = [o for o in flagged if SIG_FLOOD in o.signals]
    if flood:
        ratios = [float(o.signals[SIG_FLOOD]) for o in flood]
        peak = max(ratios)
        return Classification(
            attack_type=ATTACK_FLOOD,
            confidence=min(1.0, 0.5 + len(flood) / 10.0),
            rationale=(
                f'sustained request-rate tell on {len(flood)} sample(s), peak '
                f'{peak:.1f}x the configured per-device rate'
            ),
            evidence_cycles=len(flagged),
            first_flagged_t=first_flagged_t,
        )

    return None


@dataclass
class AttackEvidence:
    """Bounded per-subject observation history for the live controller path.

    The offline scorer builds its windows straight from the recording and does
    not need this; it exists so the controller can classify continuously
    without growing a list per node for the length of a run.
    """

    window_cycles: int = DEFAULT_WINDOW_CYCLES
    _nodes: Dict[str, Deque[Observation]] = field(default_factory=dict)
    _clients: Dict[str, Deque[Observation]] = field(default_factory=dict)

    def _bucket(self, store: Dict[str, Deque[Observation]], key: str) -> Deque[Observation]:
        if key not in store:
            store[key] = deque(maxlen=self.window_cycles)
        return store[key]

    def record_node(self, node_id: str, t: float, signals: Mapping[str, float]) -> None:
        """Record one poll cycle for a node. Call this EVERY cycle, including
        clean ones -- passing an empty dict is how an off phase becomes
        visible, and the on-off rule cannot fire without it."""
        self._bucket(self._nodes, node_id).append(Observation(t, dict(signals)))

    def record_client(self, client: str, t: float, signals: Mapping[str, float]) -> None:
        self._bucket(self._clients, client).append(Observation(t, dict(signals)))

    def classify_node(self, node_id: str, now: Optional[float] = None, **kwargs):
        return classify_node(list(self._nodes.get(node_id, ())), now=now, **kwargs)

    def classify_client(self, client: str, now: Optional[float] = None, **kwargs):
        return classify_client(list(self._clients.get(client, ())), now=now, **kwargs)

    def node_subjects(self) -> list:
        return list(self._nodes)

    def client_subjects(self) -> list:
        return list(self._clients)
