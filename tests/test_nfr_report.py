"""Tests for evaluation/nfr_report.py -- the live full-scale demo's NFR
validation report (Project Plan Step 3). All synthetic-event tests; no
Mininet/root required (that's the whole point of computing this from an
events.jsonl recording rather than during the run itself)."""

import json

import pytest

from evaluation.nfr_report import (
    BLOCKCHAIN_OVERHEAD_TARGET_PCT,
    ISOLATION_TARGET_MS,
    ROUTING_TARGET_MS,
    blockchain_overhead_nfr,
    build_report,
    format_report,
    isolation_nfr,
    load_events,
    raft_commit_nfr,
    routing_decision_nfr,
)


def _route(decision_ms: float):
    return {'type': 'route', 'decision_ms': decision_ms}


def _reroute(resteer_ms: float):
    return {'type': 'reroute', 'resteer_ms': resteer_ms}


def _report(report_ms: float, committed: bool):
    return {'type': 'report', 'report_ms': report_ms, 'committed': committed}


def _task(latency_ms: float, status: str = 'success'):
    return {'type': 'report', 'status': status, 'latency_ms': latency_ms}


def _block(commit_ms: float, num_updates: int = 10):
    return {'type': 'block', 'commit_ms': commit_ms, 'num_updates': num_updates}


class TestRoutingDecisionNfr:
    def test_passes_when_well_under_target(self) -> None:
        events = [_route(ms) for ms in [10, 15, 20, 12, 18]]
        result = routing_decision_nfr(events)
        assert result.passed is True
        assert result.n == 5

    def test_fails_when_p95_over_target(self) -> None:
        events = [_route(ms) for ms in [10] * 18 + [ROUTING_TARGET_MS + 50] * 2]
        result = routing_decision_nfr(events)
        assert result.passed is False

    def test_no_data_returns_none_verdict(self) -> None:
        result = routing_decision_nfr([])
        assert result.passed is None
        assert result.measured is None

    def test_ignores_other_event_types(self) -> None:
        events = [_route(10.0), _reroute(5.0), {'type': 'quarantine'}]
        result = routing_decision_nfr(events)
        assert result.n == 1


class TestIsolationNfr:
    def test_passes_when_well_under_target(self) -> None:
        events = [_reroute(ms) for ms in [50, 80, 120]]
        result = isolation_nfr(events)
        assert result.passed is True

    def test_fails_when_max_over_target(self) -> None:
        events = [_reroute(ms) for ms in [50, ISOLATION_TARGET_MS + 500]]
        result = isolation_nfr(events)
        assert result.passed is False

    def test_poll_interval_is_folded_into_the_bound(self) -> None:
        # 2900ms resteer alone passes; +1000ms poll interval pushes it over.
        events = [_reroute(2900.0)]
        assert isolation_nfr(events).passed is True
        assert isolation_nfr(events, poll_interval_s=1.0).passed is False

    def test_no_data_returns_none_verdict(self) -> None:
        result = isolation_nfr([])
        assert result.passed is None


class TestBlockchainOverheadNfr:
    def test_passes_when_commit_is_cheap_against_task_latency(self) -> None:
        # 0.4ms commit / 10 updates = 0.04ms per task, against 240ms tasks.
        events = [_block(0.4) for _ in range(4)] + [_task(240.0) for _ in range(50)]
        result = blockchain_overhead_nfr(events)
        assert result.passed is True

    def test_fails_when_commit_is_a_large_share_of_task_latency(self) -> None:
        # 50ms commit / 10 updates = 5ms per task, against 10ms tasks = 50%.
        events = [_block(50.0) for _ in range(4)] + [_task(10.0) for _ in range(50)]
        result = blockchain_overhead_nfr(events)
        assert result.passed is False

    def test_amortises_over_the_actual_batch_size_not_an_assumed_one(self) -> None:
        # Same commit cost, but batches of 1 rather than 10 -> 10x the per-task
        # cost, which is what flips this from passing to failing.
        latencies = [_task(10.0) for _ in range(50)]
        assert blockchain_overhead_nfr(
            [_block(10.0, num_updates=10) for _ in range(4)] + latencies).passed is True
        assert blockchain_overhead_nfr(
            [_block(10.0, num_updates=1) for _ in range(4)] + latencies).passed is False

    def test_a_tiny_uncommitted_baseline_does_not_inflate_the_result(self) -> None:
        """Regression: the first cut of this metric divided the commit cost by
        an uncommitted /report's handling time (tens of microseconds), which
        reported a 0.4ms commit on 240ms tasks as ~2000% overhead -- a FAIL on
        a system that spends 0.017% of a task in the ledger."""
        events = (
            [_block(0.424) for _ in range(40)]
            + [_task(243.7) for _ in range(350)]
            + [_report(0.022, committed=False) for _ in range(350)]
            + [_report(0.499, committed=True) for _ in range(38)]
        )
        result = blockchain_overhead_nfr(events)
        assert result.passed is True
        assert result.measured is not None and result.measured.startswith('0.0')

    def test_no_data_without_blocks(self) -> None:
        assert blockchain_overhead_nfr([_task(10.0)]).passed is None

    def test_no_data_without_task_latencies(self) -> None:
        assert blockchain_overhead_nfr([_block(1.0)]).passed is None

    def test_empty_is_no_data(self) -> None:
        assert blockchain_overhead_nfr([]).passed is None


class TestRaftCommitNfr:
    def test_reports_the_isolated_measurement_and_passes(self) -> None:
        result = raft_commit_nfr()
        assert result.passed is True
        assert '500 ms' in result.target


class TestBuildAndFormatReport:
    def test_build_report_returns_four_results(self) -> None:
        results = build_report([])
        assert len(results) == 4
        assert {r.name for r in results} == {
            'Routing decision', 'Isolation (re-dispatch)', 'Blockchain overhead', 'RAFT commit',
        }

    def test_format_report_marks_no_data_and_pass_fail(self) -> None:
        events = [_route(10.0)] * 5
        results = build_report(events)
        text = format_report(results)
        assert 'NO DATA' in text  # isolation/blockchain have nothing to measure
        assert 'PASS' in text  # routing and RAFT do


class TestLoadEvents:
    def test_parses_valid_jsonl(self, tmp_path) -> None:
        path = tmp_path / 'events.jsonl'
        path.write_text('\n'.join(json.dumps(e) for e in [_route(1.0), _reroute(2.0)]) + '\n')
        events = load_events(str(path))
        assert len(events) == 2

    def test_skips_blank_and_malformed_lines(self, tmp_path) -> None:
        path = tmp_path / 'events.jsonl'
        path.write_text('\n' + json.dumps(_route(1.0)) + '\nnot json\n')
        events = load_events(str(path))
        assert events == [_route(1.0)]
