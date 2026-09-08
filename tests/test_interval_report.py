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


# --------------------------------------------------------------------- #
# Routing reliability, trust and service availability                    #
# --------------------------------------------------------------------- #
def _topology_gt(honest, attackers):
    """A topology carrying ground truth, the way trust_balancer emits it."""
    return {
        'type': 'topology', 'ts': 0.0,
        'graph': {'nodes': (
            [{'id': s, 'kind': 'server', 'attack': 'none'} for s in honest]
            + [{'id': s, 'kind': 'server', 'attack': 'sybil'} for s in attackers]
        )},
    }


def _route_kv(ts, chosen, ip='10.0.0.1', port=1):
    return {'type': 'route', 'ts': ts, 'chosen': chosen,
            'client_ip': ip, 'client_port': port, 'decision_ms': 1.0}


def _reroute(ts, ip='10.0.0.1', port=1, frm='srv1', to='srv2'):
    return {'type': 'reroute', 'ts': ts, 'client_ip': ip, 'client_port': port,
            'from_node': frm, 'to_node': to, 'resteer_ms': 12.0}


def _node_status(ts, nodes):
    return {'type': 'node_status', 'ts': ts, 'nodes': nodes}


class TestRoutingReliability:
    def test_reliability_is_decisions_that_were_never_resteered(self):
        events = [_topology(['srv1', 'srv2'])]
        # all inside bucket 0 (0-10s)
        events += [_route_kv(1.0 + i * 0.5, 'srv1', port=i) for i in range(10)]
        events += [_reroute(7.0, port=0), _reroute(7.0, port=1)]
        b = bucket_events(events)[0]
        assert b.served == 10
        assert b.resteers == 2
        assert b.routing_reliability == pytest.approx(0.8)

    def test_a_resteer_is_charged_to_the_bucket_its_route_was_taken_in(self):
        """Charging it where it LANDS lets a quarantine burst exceed that
        bucket's route count and drive reliability negative."""
        events = [_topology(['srv1', 'srv2'])]
        # 5 routes in bucket 0, 1 route in bucket 1 ...
        events += [_route_kv(1.0 + i, 'srv1', port=i) for i in range(5)]
        events.append(_route_kv(11.0, 'srv1', port=99))
        # ... and every one of the bucket-0 dispatches is re-steered at t=12,
        # which lands in bucket 1.
        events += [_reroute(12.0, port=i) for i in range(5)]

        b0, b1 = bucket_events(events)
        assert b0.resteers == 5 and b0.routing_reliability == pytest.approx(0.0)
        assert b1.resteers == 0 and b1.routing_reliability == pytest.approx(1.0)

    def test_reliability_can_never_go_negative(self):
        events = [_topology(['srv1'])]
        events += [_route_kv(1.0 + i, 'srv1', port=i) for i in range(3)]
        events += [_reroute(12.0, port=i) for i in range(3)]
        for b in bucket_events(events):
            if b.routing_reliability is not None:
                assert 0.0 <= b.routing_reliability <= 1.0

    def test_one_decision_resteered_twice_counts_once(self):
        # A dispatch re-steered twice is still ONE decision that failed to
        # hold; counting the events would push resteers past served.
        events = [_topology(['srv1'])]
        events += [_route_kv(1.0, 'srv1', port=7)]
        events += [_reroute(2.0, port=7), _reroute(3.0, port=7)]
        b = bucket_events(events)[0]
        assert b.resteers == 1
        assert b.routing_reliability == pytest.approx(0.0)

    def test_a_resteer_with_no_matching_route_is_ignored(self):
        events = [_topology(['srv1']), _route_kv(1.0, 'srv1', port=1),
                  _reroute(2.0, port=4242)]
        assert bucket_events(events)[0].resteers == 0

    def test_admitted_ratio_is_served_over_offered(self):
        events = [_topology(['srv1'])]
        events += [_route_kv(1.0 + i, 'srv1', port=i) for i in range(9)]
        events.append(_route_denied(2.0))
        b = bucket_events(events)[0]
        assert b.admitted_ratio == pytest.approx(0.9)

    def test_a_bucket_with_no_decisions_has_no_opinion(self):
        # None, not 1.0 (nothing failed) and not 0.0 (nothing succeeded).
        events = [_topology(['srv1']), _route_kv(1.0, 'srv1'),
                  _route_kv(25.0, 'srv1', port=2)]
        mid = bucket_events(events)[1]
        assert mid.served == 0
        assert mid.routing_reliability is None
        assert mid.admitted_ratio is None


class TestTrustAndAvailabilitySeries:
    def test_trust_is_split_by_ground_truth(self):
        events = [
            _topology_gt(['srv1', 'srv2'], ['srv3']),
            _node_status(1.0, {
                'srv1': {'trust': 0.9, 'quarantined': False},
                'srv2': {'trust': 0.7, 'quarantined': False},
                'srv3': {'trust': 0.1, 'quarantined': True},
            }),
        ]
        b = bucket_events(events)[0]
        assert b.mean_trust_honest == pytest.approx(0.8)
        assert b.mean_trust_attacker == pytest.approx(0.1)

    def test_serving_and_containment_are_never_the_same_number(self):
        """They must move in OPPOSITE directions when the system works, which
        is exactly why availability_report.py forbids averaging them."""
        events = [
            _topology_gt(['srv1', 'srv2'], ['srv3', 'srv4']),
            _node_status(1.0, {
                'srv1': {'trust': 0.9, 'quarantined': False},
                'srv2': {'trust': 0.9, 'quarantined': False},
                'srv3': {'trust': 0.1, 'quarantined': True},
                'srv4': {'trust': 0.2, 'quarantined': False},
            }),
        ]
        b = bucket_events(events)[0]
        assert b.honest_serving_fraction == pytest.approx(1.0)
        assert b.attacker_contained_fraction == pytest.approx(0.5)

    def test_an_honest_quarantine_shows_up_as_lost_availability(self):
        events = [
            _topology_gt(['srv1', 'srv2'], ['srv3']),
            _node_status(1.0, {
                'srv1': {'trust': 0.9, 'quarantined': True},
                'srv2': {'trust': 0.9, 'quarantined': False},
                'srv3': {'trust': 0.1, 'quarantined': True},
            }),
        ]
        b = bucket_events(events)[0]
        assert b.honest_serving_fraction == pytest.approx(0.5)

    def test_absent_attackers_are_none_not_zero(self):
        """"No attackers configured" must not read as "total enforcement
        failure" -- the rule availability_report.py states for absent groups."""
        events = [
            _topology_gt(['srv1', 'srv2'], []),
            _node_status(1.0, {
                'srv1': {'trust': 0.9, 'quarantined': False},
                'srv2': {'trust': 0.9, 'quarantined': False},
            }),
        ]
        b = bucket_events(events)[0]
        assert b.honest_serving_fraction == pytest.approx(1.0)
        assert b.mean_trust_attacker is None
        assert b.attacker_contained_fraction is None

    def test_a_bucket_with_no_status_polls_is_none(self):
        events = [_topology_gt(['srv1'], ['srv2']), _route_kv(1.0, 'srv1')]
        b = bucket_events(events)[0]
        assert b.mean_trust_honest is None
        assert b.honest_serving_fraction is None

    def test_values_are_time_averaged_across_the_buckets_polls(self):
        # Availability is a time integral, not the last sample: srv1 is
        # quarantined for 2 of 4 polls in the bucket.
        events = [_topology_gt(['srv1'], [])]
        for i, q in enumerate([False, False, True, True]):
            events.append(_node_status(1.0 + i, {
                'srv1': {'trust': 0.5, 'quarantined': q}}))
        b = bucket_events(events)[0]
        assert b.honest_serving_fraction == pytest.approx(0.5)


class TestNewFieldsReachTheOutputs:
    def test_csv_carries_every_new_column(self):
        events = [
            _topology_gt(['srv1'], ['srv2']),
            _route_kv(1.0, 'srv1'), _reroute(2.0),
            _node_status(1.0, {'srv1': {'trust': 0.9, 'quarantined': False},
                               'srv2': {'trust': 0.2, 'quarantined': True}}),
        ]
        rows = to_csv_rows(bucket_events(events))
        header = rows[0]
        for col in ('resteers', 'routing_reliability', 'admitted_ratio',
                    'mean_trust_honest', 'mean_trust_attacker',
                    'honest_serving_fraction', 'attacker_contained_fraction'):
            assert col in header
        assert all(len(r) == len(header) for r in rows[1:])

    def test_reliability_table_renders_and_never_prints_a_combined_figure(self):
        from evaluation.interval_report import format_reliability_table
        events = [
            _topology_gt(['srv1'], ['srv2']),
            _route_kv(1.0, 'srv1'),
            _node_status(1.0, {'srv1': {'trust': 0.9, 'quarantined': False},
                               'srv2': {'trust': 0.2, 'quarantined': True}}),
        ]
        out = format_reliability_table(bucket_events(events))
        assert 'held' in out and 'serving' in out and 'contain' in out
        # separate columns, and the reason spelled out
        assert 'Never averaged together' in out

    def test_absent_values_render_blank_not_zero(self):
        from evaluation.interval_report import format_reliability_table
        events = [_topology_gt(['srv1'], []), _route_denied(1.0)]
        buckets = bucket_events(events)
        out = format_reliability_table(buckets)
        data = [ln for ln in out.splitlines() if ln.strip().startswith('0')][0]

        header = out.splitlines()[0]

        def col(name, width):
            i = header.index(name)
            return data[i:i + width]

        # Nothing was served, so "held" has no opinion and must be blank.
        assert buckets[0].routing_reliability is None
        assert col('held', 4).strip() == '', 'held should be blank'

        # "admit" is a different question and DOES have an answer here: one
        # request was offered and none admitted, which is a real 0.00.
        assert buckets[0].admitted_ratio == 0.0

        # No status polls at all -> every ground-truth column blank. The
        # re-steer COUNT is deliberately not among them: zero re-steers is a
        # real observation, not a missing one.
        assert buckets[0].mean_trust_honest is None
        assert data[header.index('T honest'):].strip() == ''
        assert col('re-st', 5).strip() == '0'
