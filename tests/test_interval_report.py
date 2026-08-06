"""Tests for evaluation/interval_report.py -- the metric-vs-simulation-time
binning module (plan_adv.md Phase 0). All synthetic-event tests, same style
and rationale as tests/test_nfr_report.py: no Mininet/root required."""

import pytest

from evaluation.interval_report import (
    PRIO_QUARANTINE_DROP,
    IntervalMetrics,
    bucket_events,
    format_table,
    jain_fairness_index,
    server_node_ids,
    to_csv_rows,
)


def _topology(servers):
    return {
        'type': 'topology', 'ts': 0.0,
        'graph': {'nodes': [{'id': s, 'kind': 'server'} for s in servers]},
    }


def _route(ts, chosen, decision_ms=10.0):
    return {'type': 'route', 'ts': ts, 'chosen': chosen, 'decision_ms': decision_ms}


def _route_denied(ts):
    return {'type': 'route_denied', 'ts': ts}


def _report(ts, status='success', latency_ms=20.0):
    return {'type': 'report', 'ts': ts, 'status': status, 'latency_ms': latency_ms}


def _quarantine(ts, node):
    return {'type': 'quarantine', 'ts': ts, 'node': node}


def _recovered(ts, node):
    return {'type': 'recovered', 'ts': ts, 'node': node}


def _flow_stats(ts, rules):
    return {'type': 'flow_stats', 'ts': ts, 'rules': rules}


def _vip_rule(dpid, cookie, packets, bps, priority=100, table=1, match='m'):
    return {
        'dpid': dpid, 'table': table, 'priority': priority, 'cookie': cookie,
        'match': match, 'is_vip': True, 'packets': packets, 'bps': bps,
    }


def _drop_rule(dpid, cookie, packets, table=1, match='m'):
    return _vip_rule(
        dpid, cookie, packets, bps=0.0, priority=PRIO_QUARANTINE_DROP, table=table,
        match=match,
    )


class TestJainFairnessIndex:
    def test_perfectly_even_is_1(self):
        assert jain_fairness_index([10, 10, 10, 10]) == 1.0

    def test_one_node_takes_everything_is_1_over_n(self):
        assert jain_fairness_index([40, 0, 0, 0]) == 0.25

    def test_no_traffic_is_none_not_zero(self):
        assert jain_fairness_index([0, 0, 0]) is None

    def test_no_nodes_is_none(self):
        assert jain_fairness_index([]) is None


class TestServerNodeIds:
    def test_reads_the_server_roster_from_topology_event(self):
        events = [_topology(['srv2', 'srv1', 'srv3']), _route(1.0, 'srv1')]
        assert server_node_ids(events) == ['srv1', 'srv2', 'srv3']

    def test_empty_without_a_topology_event(self):
        assert server_node_ids([_route(1.0, 'srv1')]) == []


class TestBucketEventsBasics:
    def test_empty_events_gives_empty_buckets(self):
        assert bucket_events([]) == []

    def test_events_land_in_the_right_bucket(self):
        events = [
            _topology(['srv1']),
            _route(0.0, 'srv1'), _route(5.0, 'srv1'),   # bucket 0 (t=0-10)
            _route(11.0, 'srv1'),                          # bucket 1 (t=10-20)
        ]
        buckets = bucket_events(events, bucket_s=10.0)
        assert len(buckets) == 2
        assert buckets[0].served == 2
        assert buckets[1].served == 1


class TestPdr:
    def test_pdr_is_success_over_completed(self):
        events = [
            _topology(['srv1']),
            _report(1.0, 'success'), _report(2.0, 'success'),
            _report(3.0, 'timeout'), _report(4.0, 'failure'),
        ]
        buckets = bucket_events(events, bucket_s=10.0)
        assert buckets[0].task_success == 2
        assert buckets[0].task_timeout == 1
        assert buckets[0].task_failure == 1
        assert buckets[0].pdr == 0.5

    def test_no_completed_tasks_is_none_not_zero(self):
        events = [_topology(['srv1']), _route(1.0, 'srv1')]
        buckets = bucket_events(events, bucket_s=10.0)
        assert buckets[0].pdr is None


class TestRoutingShareAndFairness:
    def test_starved_node_pulls_fairness_down_even_with_zero_traffic(self):
        # srv2 gets nothing all bucket -- must still count against Jain's
        # index (the exact failure mode memory/edgescore-fanout-starvation
        # documents), not be silently absent from the denominator.
        events = [
            _topology(['srv1', 'srv2']),
            *[_route(t, 'srv1') for t in range(1, 9)],
        ]
        buckets = bucket_events(events, bucket_s=10.0)
        assert buckets[0].routing_share == {'srv1': 8}
        assert buckets[0].jain_fairness == 0.5  # 1/n for n=2, one node takes all

    def test_even_split_is_close_to_1(self):
        events = [
            _topology(['srv1', 'srv2']),
            *[_route(t, 'srv1') for t in range(1, 5)],
            *[_route(t, 'srv2') for t in range(5, 9)],
        ]
        buckets = bucket_events(events, bucket_s=10.0)
        assert buckets[0].jain_fairness == 1.0

    def test_offered_includes_denials(self):
        events = [
            _topology(['srv1']),
            _route(1.0, 'srv1'), _route_denied(2.0), _route_denied(3.0),
        ]
        buckets = bucket_events(events, bucket_s=10.0)
        assert buckets[0].offered == 3
        assert buckets[0].served == 1


class TestQuarantineTracking:
    def test_quarantine_then_recovered_updates_the_roster(self):
        events = [
            _topology(['srv1', 'srv2']),
            _quarantine(1.0, 'srv1'),
            _route(2.0, 'srv2'),      # still in bucket 0, srv1 quarantined
            _recovered(11.0, 'srv1'),  # bucket 1
        ]
        buckets = bucket_events(events, bucket_s=10.0)
        assert buckets[0].quarantined_nodes == ['srv1']
        assert buckets[1].quarantined_nodes == []


class TestFlowStatsDerivedMetrics:
    def test_throughput_sums_serving_vip_rules_not_drop_rules(self):
        events = [
            _topology(['srv1']),
            _flow_stats(1.0, [
                _vip_rule(1, cookie=1, packets=100, bps=500.0),
                _vip_rule(1, cookie=1, packets=90, bps=300.0, match='return'),
                _drop_rule(1, cookie=2, packets=5),
            ]),
        ]
        buckets = bucket_events(events, bucket_s=10.0)
        assert buckets[0].throughput_bps == 800.0  # drop rule's bps=0 excluded anyway

    def test_quarantine_drop_packets_is_a_delta_not_a_running_total(self):
        events = [
            _topology(['srv1']),
            _flow_stats(1.0, [_drop_rule(1, cookie=2, packets=10)]),
            _flow_stats(5.0, [_drop_rule(1, cookie=2, packets=25)]),
        ]
        buckets = bucket_events(events, bucket_s=10.0)
        # First sighting establishes the baseline (no prior poll to diff
        # against -- can't invent drops from before the recording starts);
        # second sighting reports the 15-packet delta.
        assert buckets[0].quarantine_drop_packets == 15

    def test_quiet_bucket_forward_fills_throughput_not_zero(self):
        events = [
            _topology(['srv1']),
            _flow_stats(1.0, [_vip_rule(1, cookie=1, packets=100, bps=500.0)]),
            _report(15.0, 'success'),  # bucket 1: no flow_stats event of its own
        ]
        buckets = bucket_events(events, bucket_s=10.0)
        assert buckets[1].throughput_bps == 500.0


class TestPrioQuarantineDropStaysPinnedToTheRealConstant:
    def test_matches_trust_balancer(self):
        # interval_report.py deliberately duplicates this constant instead of
        # importing controller.trust_balancer (which pulls in os_ken) --
        # nfr_report.py does the same for the same reason. Catches drift if
        # the real value ever changes.
        os_ken = pytest.importorskip('os_ken')
        del os_ken
        from controller.trust_balancer import TrustBalancerApp
        assert PRIO_QUARANTINE_DROP == TrustBalancerApp.PRIO_QUARANTINE_DROP


class TestReportingHelpers:
    def test_format_table_and_csv_do_not_crash_on_a_real_bucket_set(self):
        events = [
            _topology(['srv1', 'srv2']),
            _route(1.0, 'srv1'), _report(1.5, 'success'),
            _flow_stats(2.0, [_vip_rule(1, cookie=1, packets=10, bps=100.0)]),
        ]
        buckets = bucket_events(events, bucket_s=10.0)
        text = format_table(buckets)
        assert 'PDR' in text
        rows = to_csv_rows(buckets)
        assert rows[0][0] == 't_start_s'
        assert len(rows) == len(buckets) + 1
