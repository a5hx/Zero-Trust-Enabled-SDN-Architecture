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
