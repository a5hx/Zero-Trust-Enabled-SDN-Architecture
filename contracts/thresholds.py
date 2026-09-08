"""Shared decision thresholds for trust-based node exclusion.

These are the fallbacks used when a caller does not supply a value from
``config/*.yaml`` (key ``trust.isolation_threshold`` / ``trust.anomaly_gate``).
They live here rather than being duplicated across metrics, plots, the demo
runner, and the controller.
"""

# Trust score below which a node is excluded from routing.
DEFAULT_ISOLATION_THRESHOLD = 0.3

# Smoothed anomaly level (Ā) at or above which a node is quarantined regardless
# of its trust score.
#
# This gate is not part of the published trust formula. It is necessary because
# the formula cannot isolate a node that lies about its load but still serves
# tasks well: such a node holds R̄→1 and B̄→0.96, so
#
#     T = 0.35(1.0) + 0.25(0.96) + 0.25(0.0) - 0.15(1.0) = 0.44
#
# which never crosses DEFAULT_ISOLATION_THRESHOLD, because δ only ever subtracts
# 0.15. Dishonesty alone can drive H̄ to 0 and Ā to 1 and still leave the node
# comfortably above the isolation line. Continuous verification therefore needs
# an anomaly gate alongside the score.
DEFAULT_ANOMALY_GATE = 0.5

# --- Graduated response bands (Sprint 2) --------------------------------------
#
# Zero Trust is not binary trust/no-trust: a node that is merely *suspect* --
# below full trust but not yet over the quarantine line -- gets a proportional
# response rather than either full service or none. A node in the middle band
# still receives traffic, but its flows are rate-limited by an OpenFlow meter,
# so a degrading or mildly-anomalous node cannot absorb full load while the
# controller decides whether it is failing.
#
#   trust >= RATE_LIMIT_TRUST  and  anomaly < ANOMALY_WARN   -> full service
#   ISOLATION <= trust < RATE_LIMIT_TRUST, or                -> rate-limited
#       ANOMALY_WARN <= anomaly < ANOMALY_GATE
#   trust < ISOLATION  or  anomaly >= ANOMALY_GATE           -> quarantined
#
# The gates (ISOLATION, ANOMALY_GATE) stay as the hard safety rails; these two
# thresholds only carve the "suspect" band out of the region above them.
DEFAULT_RATE_LIMIT_TRUST = 0.5
DEFAULT_ANOMALY_WARN = 0.25

# --- Client task timeout ------------------------------------------------------
#
# How long an IoT client waits for a task before giving up (simulation/
# iot_client.py --timeout-s, config `agents.task_timeout_s`). It lives here,
# next to the thresholds, because the *controller* needs it too: a client that
# times out never sends /report, so TrustState must stop counting that dispatch
# as inflight at about the same time the client stops waiting for it. Any
# controller-side reap horizon materially larger than this manufactures phantom
# load on honest nodes under saturation -- see TrustState._dispatch_reap_after_s
# for the failure this actually caused in the 8/40/3 live run.
DEFAULT_TASK_TIMEOUT_S = 2.0

# --- Escaping quarantine -------------------------------------------------- #
#
# Quarantine cuts a node's service traffic, and service traffic is the only
# thing that produces task outcomes. So every detector that reads task outcomes
# goes blind the instant it fires, and every term of T that task outcomes feed
# stops moving. Unless something is done about that, quarantine is an absorbing
# state: the 8/40/3 live run ended with srv1/srv4/srv7 sitting at anomaly 0.0,
# 29ms RTT, zero inflight -- provably healthy -- and permanently isolated,
# because trust had fallen to ~0.18 and nothing could raise it again.
#
# Two constants below break that, one per rail.

# ANOMALY RAIL. How stale the packet-drop tell's evidence may be before it
# abstains. TrustState._recent_statuses is a count-based window (last 10
# outcomes), so with no new outcomes arriving it never turns over: the live run
# kept scoring srv5 anomalous at t=240.9s from a sample last updated at t=9.2s.
# A detector with no recent evidence must report "I don't know" (None), not keep
# re-asserting its last verdict. Multiple of task_timeout_s: under normal
# traffic a node's outcomes arrive far faster than this, so a healthy node's
# tell never abstains and the drop attacker is still caught.
DEFAULT_TIMEOUT_EVIDENCE_AGE_FACTOR = 3.0

# TRUST RAIL. Minimum gap between successive probation probes to one node.
# A node quarantined on trust alone -- Ā already back below the gate -- is
# offered a single trial task at most this often, so it can earn trust back.
# This is the half-open state of a circuit breaker: the anomaly gate remains an
# absolute bar (a node above it is never probed), and the cost of the trial is
# bounded at one task per node per interval, so a genuinely bad node cannot be
# handed meaningful traffic by this path.
DEFAULT_PROBATION_INTERVAL_S = 5.0

# HONESTY, BUSY-TIME FORM. Minimum span between the two busy-second samples
# being differenced. Below this the quotient is dominated by poll jitter: at a
# 1 s poll interval a 50 ms scheduling wobble is 5% of the window, which lands
# straight on the duty cycle. Half a poll interval is the floor at which the
# ratio is meaningful; under it, the estimator returns None and the check
# abstains rather than guessing.
DEFAULT_MIN_BUSY_SPAN_S = 0.5

# Nodes that must have usable busy-time evidence before the fleet median
# service time is trusted as a baseline. The median tolerates a minority of
# liars (threat model: 3 malicious of 8), but only if enough honest nodes are
# actually contributing -- with two samples the "median" is just an average of
# whoever answered. See TrustState.fleet_service_time_s.
DEFAULT_MIN_FLEET_SERVICE_SAMPLES = 3
