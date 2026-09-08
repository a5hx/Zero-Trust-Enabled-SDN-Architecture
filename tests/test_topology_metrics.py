"""Tests for evaluation/topology_metrics.py.

Every figure here is a graph traversal, so a mistake in edge bookkeeping gives
a plausible wrong number rather than a crash -- the same reason
tests/test_availability_report.py checks its arithmetic against hand-computed
timelines. The graphs below are hand-built and small enough to verify by eye.
"""

import unittest

from evaluation.topology_metrics import (
    DEFAULT_SINK,
    distance_to_sink,
    format_report,
    node_degree,
    topology_graph,
)


def _graph():
    """The shape simulation/topology.py builds, at 2 edge nodes / 3 devices.

    iot3's link deliberately carries NO delay_ms -- the case where the harness
    never reported (or reported partially), which must read as "not measured".
    """
    return {
        'nodes': [
            {'id': 's0', 'kind': 'core_switch'},
            {'id': 's1', 'kind': 'edge_switch'},
            {'id': 's2', 'kind': 'edge_switch'},
            {'id': 'srv1', 'kind': 'server'},
            {'id': 'srv2', 'kind': 'server'},
            {'id': 'iot1', 'kind': 'iot'},
            {'id': 'iot2', 'kind': 'iot'},
            {'id': 'iot3', 'kind': 'iot'},
        ],
        'links': [
            {'a': 's1', 'b': 'srv1', 'kind': 'server_link', 'delay_ms': 2.0},
            {'a': 's0', 'b': 's1', 'kind': 'core_link', 'delay_ms': 5.0},
            {'a': 's2', 'b': 'srv2', 'kind': 'server_link', 'delay_ms': 2.0},
            {'a': 's0', 'b': 's2', 'kind': 'core_link', 'delay_ms': 5.0},
            {'a': 'iot1', 'b': 's1', 'kind': 'iot_link', 'delay_ms': 9.0},
            {'a': 'iot2', 'b': 's2', 'kind': 'iot_link', 'delay_ms': 3.0},
            {'a': 'iot3', 'b': 's1', 'kind': 'iot_link'},
        ],
    }


class TestNodeDegree(unittest.TestCase):
    def test_degree_counts_incident_links(self):
        deg = node_degree(_graph())
        # s1: core + srv1 + iot1 + iot3;  s2: core + srv2 + iot2
        self.assertEqual(deg['s1'], 4)
        self.assertEqual(deg['s2'], 3)
        self.assertEqual(deg['s0'], 2)

    def test_leaf_nodes_have_degree_one(self):
        deg = node_degree(_graph())
        for leaf in ('srv1', 'srv2', 'iot1', 'iot2', 'iot3'):
            self.assertEqual(deg[leaf], 1, leaf)

    def test_an_isolated_node_is_reported_as_zero_not_dropped(self):
        # Dropping it would hide exactly the case worth seeing.
        g = _graph()
        g['nodes'].append({'id': 'orphan', 'kind': 'iot'})
        deg = node_degree(g)
        self.assertIn('orphan', deg)
        self.assertEqual(deg['orphan'], 0)

    def test_links_naming_unknown_nodes_are_ignored(self):
        g = _graph()
        g['links'].append({'a': 'srv1', 'b': 'ghost', 'kind': 'iot_link'})
        self.assertEqual(node_degree(g)['srv1'], 1)

    def test_self_loops_do_not_count(self):
        g = _graph()
        g['links'].append({'a': 'srv1', 'b': 'srv1'})
        self.assertEqual(node_degree(g)['srv1'], 1)


class TestDistanceToSink(unittest.TestCase):
    def test_hop_counts(self):
        d = distance_to_sink(_graph())
        self.assertEqual(d['s0']['hops'], 0)
        self.assertEqual(d['s1']['hops'], 1)
        self.assertEqual(d['srv1']['hops'], 2)
        self.assertEqual(d['iot1']['hops'], 2)

    def test_delay_sums_along_the_path(self):
        d = distance_to_sink(_graph())
        self.assertEqual(d['s1']['delay_ms'], 5.0)          # core link
        self.assertEqual(d['srv1']['delay_ms'], 7.0)        # 5 + 2
        self.assertEqual(d['iot1']['delay_ms'], 14.0)       # 5 + 9
        self.assertEqual(d['iot2']['delay_ms'], 8.0)        # 5 + 3

    def test_per_device_delay_actually_varies(self):
        # The whole reason this metric is worth reporting: hop count alone is a
        # constant here, so a uniform delay column would say nothing.
        d = distance_to_sink(_graph())
        self.assertNotEqual(d['iot1']['delay_ms'], d['iot2']['delay_ms'])

    def test_an_unreported_link_makes_the_path_delay_none_not_zero(self):
        # "Not measured" and "zero delay" are different claims. A run where the
        # harness never POSTed /topology/links must show a dash, not a
        # plausible-looking 0.0 that would silently flatter every distance.
        d = distance_to_sink(_graph())
        self.assertIsNone(d['iot3']['delay_ms'])
        self.assertEqual(d['iot3']['hops'], 2, 'hops are still knowable')

    def test_a_graph_with_no_link_params_at_all_reports_none(self):
        g = {'nodes': [{'id': 's0'}, {'id': 'srv1'}],
             'links': [{'a': 's0', 'b': 'srv1'}]}
        d = distance_to_sink(g)
        self.assertEqual(d['srv1']['hops'], 1)
        self.assertIsNone(d['srv1']['delay_ms'])

    def test_unreachable_nodes_report_none(self):
        g = _graph()
        g['nodes'].append({'id': 'orphan', 'kind': 'iot'})
        d = distance_to_sink(g)
        self.assertIsNone(d['orphan']['hops'])
        self.assertIsNone(d['orphan']['delay_ms'])

    def test_missing_sink_yields_no_distances(self):
        g = _graph()
        g['nodes'] = [n for n in g['nodes'] if n['id'] != 's0']
        d = distance_to_sink(g)
        self.assertTrue(all(v['hops'] is None for v in d.values()))

    def test_equal_hop_paths_tie_break_on_lowest_delay(self):
        # A stated tie-break, not whichever edge the iteration reached first.
        g = {
            'nodes': [{'id': 's0'}, {'id': 'a'}, {'id': 'b'}, {'id': 'x'}],
            'links': [
                {'a': 's0', 'b': 'a', 'delay_ms': 1.0},
                {'a': 's0', 'b': 'b', 'delay_ms': 1.0},
                {'a': 'a', 'b': 'x', 'delay_ms': 50.0},
                {'a': 'b', 'b': 'x', 'delay_ms': 2.0},
            ],
        }
        d = distance_to_sink(g)
        self.assertEqual(d['x']['hops'], 2)
        self.assertEqual(d['x']['delay_ms'], 3.0)

    def test_a_known_delay_beats_an_unknown_one_at_equal_hops(self):
        g = {
            'nodes': [{'id': 's0'}, {'id': 'a'}, {'id': 'b'}, {'id': 'x'}],
            'links': [
                {'a': 's0', 'b': 'a', 'delay_ms': 1.0},
                {'a': 's0', 'b': 'b'},                      # unreported
                {'a': 'b', 'b': 'x', 'delay_ms': 2.0},
                {'a': 'a', 'b': 'x', 'delay_ms': 2.0},
            ],
        }
        self.assertEqual(distance_to_sink(g)['x']['delay_ms'], 3.0)

    def test_the_sink_default_is_the_core_switch(self):
        self.assertEqual(DEFAULT_SINK, 's0')


class TestTopologyGraphRecovery(unittest.TestCase):
    def test_prefers_the_enriched_topology_links_event(self):
        # 'topology' is published from config before Mininet exists and cannot
        # carry link parameters; 'topology_links' is the harness reporting what
        # it actually built.
        events = [
            {'type': 'topology', 'ts': 1, 'graph': {'nodes': [], 'links': [
                {'a': 's0', 'b': 's1'}]}},
            {'type': 'route', 'ts': 2},
            {'type': 'topology_links', 'ts': 3, 'graph': {'nodes': [], 'links': [
                {'a': 's0', 'b': 's1', 'delay_ms': 5.0}]}},
        ]
        graph = topology_graph(events)
        self.assertEqual(graph['links'][0]['delay_ms'], 5.0)

    def test_falls_back_to_the_plain_topology_event(self):
        events = [{'type': 'topology', 'ts': 1,
                   'graph': {'nodes': [{'id': 's0'}], 'links': []}}]
        self.assertIsNotNone(topology_graph(events))

    def test_returns_none_when_there_is_no_topology_at_all(self):
        self.assertIsNone(topology_graph([{'type': 'route', 'ts': 1}]))


class TestReport(unittest.TestCase):
    def test_report_renders_and_marks_unmeasured_delays(self):
        out = format_report(_graph())
        self.assertIn('TOPOLOGY STRUCTURE', out)
        self.assertIn('srv1', out)
        self.assertIn('7.0 ms', out)
        # iot3's delay is unknown and must render as a dash.
        iot3 = [ln for ln in out.splitlines() if ln.startswith('iot3')][0]
        self.assertIn('-', iot3)
        self.assertNotIn('0.0 ms', iot3)

    def test_report_says_so_when_no_delays_were_reported(self):
        g = {'nodes': [{'id': 's0', 'kind': 'core_switch'},
                       {'id': 'srv1', 'kind': 'server'}],
             'links': [{'a': 's0', 'b': 'srv1'}]}
        self.assertIn('NOT REPORTED', format_report(g))

    def test_report_never_calls_the_delay_a_measurement(self):
        # It is a configured input, not an observed RTT. The end-to-end delay
        # the system experiences is a different metric entirely.
        self.assertIn('CONFIGURED', format_report(_graph()))

    def test_servers_are_listed_before_devices(self):
        body = format_report(_graph()).split('-' * 60)[-1]
        ids = [ln.split()[0] for ln in body.splitlines() if ln.strip()]
        self.assertLess(ids.index('srv1'), ids.index('iot1'))
        self.assertLess(ids.index('s1'), ids.index('iot1'))


if __name__ == '__main__':
    unittest.main()
