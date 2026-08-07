"""Tests for controller/flood_detector.py -- the client request-rate
flood/DDoS tell (plan_adv.md Phase 1). Pure-function tests, same style as
test_flow_monitor.py's evaluate_latency_tell coverage: no server/state
needed."""

from controller.flood_detector import evaluate_flood_tell


class TestEvaluateFloodTell:
    def test_normal_rate_never_trips(self):
        strikes = 0
        for _ in range(10):
            tell = evaluate_flood_tell(rate_hz=1.0, expected_rate_hz=1.0, strikes=strikes)
            strikes = tell.strikes
            assert not tell.tripped

    def test_sustained_flood_trips_after_persist_strikes(self):
        strikes = 0
        results = []
        for _ in range(5):
            tell = evaluate_flood_tell(
                rate_hz=50.0, expected_rate_hz=1.0, strikes=strikes, flood_persist=3,
            )
            strikes = tell.strikes
            results.append(tell.tripped)
        # Not tripped on the first two strikes -- persistence guards a blip --
        # but tripped by the third and stays tripped.
        assert results == [False, False, True, True, True]

    def test_single_burst_does_not_trip(self):
        tell = evaluate_flood_tell(rate_hz=50.0, expected_rate_hz=1.0, strikes=0, flood_persist=3)
        assert not tell.tripped
        assert tell.strikes == 1

    def test_transient_burst_drains_back_to_zero(self):
        strikes = 0
        for _ in range(2):  # two strikes, still under persist=3
            tell = evaluate_flood_tell(rate_hz=50.0, expected_rate_hz=1.0, strikes=strikes)
            strikes = tell.strikes
        assert strikes == 2
        for _ in range(2):  # back to normal -- drains, doesn't jump straight to 0
            tell = evaluate_flood_tell(rate_hz=1.0, expected_rate_hz=1.0, strikes=strikes)
            strikes = tell.strikes
        assert strikes == 0
        assert not tell.tripped

    def test_floor_guards_a_fleet_with_a_tiny_expected_rate(self):
        # expected_rate_hz=0.01 -> ratio alone would trip on any real traffic;
        # the absolute floor stops that.
        tell = evaluate_flood_tell(
            rate_hz=1.0, expected_rate_hz=0.01, strikes=0, flood_floor_hz=3.0,
        )
        assert tell.strikes == 0  # never counted as fast at all

    def test_ratio_is_measured_over_expected(self):
        tell = evaluate_flood_tell(rate_hz=25.0, expected_rate_hz=5.0, strikes=0)
        assert tell.ratio == 5.0

    def test_ratio_is_none_when_expected_rate_is_zero(self):
        tell = evaluate_flood_tell(rate_hz=25.0, expected_rate_hz=0.0, strikes=0)
        assert tell.ratio is None
        assert not tell.tripped  # can't be "fast" against an undefined baseline

    def test_strikes_never_run_negative(self):
        tell = evaluate_flood_tell(rate_hz=1.0, expected_rate_hz=1.0, strikes=0)
        assert tell.strikes == 0

    def test_strikes_cap_just_above_persist(self):
        strikes = 0
        for _ in range(10):
            tell = evaluate_flood_tell(
                rate_hz=50.0, expected_rate_hz=1.0, strikes=strikes, flood_persist=3,
            )
            strikes = tell.strikes
        assert strikes == 4  # flood_persist + 1, doesn't grow unbounded
