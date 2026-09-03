"""Tests for the dashboard's time-series charts (plan_adv.md Phase 5).

The charts bin live SSE events in the browser while `evaluation/interval_report.py`
bins the recorded JSONL offline. Two implementations of one definition is exactly
the drift this project guards against elsewhere (`evaluate_latency_tell` is shared
between the live monitor and the offline harness for the same reason), and here
they genuinely cannot share code -- one is JS in a browser, the other is Python on
a box that may not even have the controller installed. So the constants and the
metric definitions are pinned across the boundary instead.

These read dashboard/index.html as text. That is deliberate: the file is a
single self-contained page with no build step (no pip, no CDN -- see
northbound_api.py), so there is nothing to import and the source IS the artifact.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from evaluation.interval_report import DEFAULT_BUCKET_S, PRIO_QUARANTINE_DROP
from evaluation.topology_metrics import (
    DEFAULT_SINK, distance_to_sink, node_degree,
)

HTML = Path('dashboard/index.html')


def source():
    return HTML.read_text()


class TestConstantsMatchTheOfflineReport(unittest.TestCase):
    def test_bucket_width_matches_interval_report(self):
        src = source()
        js_bucket = float(re.search(r'const BUCKET_S = ([\d.]+);', src).group(1))
        self.assertEqual(
            js_bucket, DEFAULT_BUCKET_S,
            'dashboard bucket width drifted from interval_report.DEFAULT_BUCKET_S; '
            'the live chart and the offline report would disagree',
        )

    def test_quarantine_drop_priority_matches(self):
        src = source()
        js_prio = int(
            re.search(r'const PRIO_QUARANTINE_DROP = (\d+);', src).group(1)
        )
        self.assertEqual(js_prio, PRIO_QUARANTINE_DROP)

    def test_priority_constant_agrees_with_the_controller_itself(self):
        # interval_report duplicates it too; make sure the whole chain agrees
        # rather than just the two copies furthest from the source of truth.
        tb = Path('controller/trust_balancer.py').read_text()
        real = int(re.search(r'PRIO_QUARANTINE_DROP\s*=\s*(\d+)', tb).group(1))
        self.assertEqual(real, PRIO_QUARANTINE_DROP)


class TestChartPalette(unittest.TestCase):
    """The series colors are validated categorical slots, not eyeballed hues.

    Checked against the dark-mode slots 1 and 2, which were run through the
    palette validator against THIS panel's surface (#161b22) and passed the
    lightness band, chroma floor, adjacent CVD separation, normal-vision
    separation and 3:1 contrast. A future edit that swaps in a hand-picked
    colour should fail here and be re-validated rather than merged on taste.
    """

    SLOT_1 = '#3987e5'
    SLOT_2 = '#d95926'

    def test_series_colors_are_the_validated_slots(self):
        src = source()
        self.assertIn(f"const SERIES_1 = '{self.SLOT_1}'", src)
        self.assertIn(f"const SERIES_2 = '{self.SLOT_2}'", src)

    def test_no_chart_defines_more_than_two_series(self):
        # Two slots is all that was validated for this surface, and every chart
        # here is designed to stay within it. A third series would need the
        # validator re-run before it could ship.
        src = source()
        block = src[src.index('const CHART_DEFS'):src.index('function niceCeil')]
        for defn in re.findall(r'series: \[(.*?)\]\s*\}', block, re.S):
            self.assertLessEqual(
                defn.count('color:'), 2,
                'a chart grew a third series without the palette being '
                're-validated for it',
            )

    def test_series_colors_are_not_the_topology_colors(self):
        # --accent and --vip already mean "request" and "reply" on the topology
        # map. Reusing them in the charts would say two different things with
        # one hue on the same screen.
        src = source()
        block = src[src.index('const SERIES_1'):src.index('function niceCeil')]
        self.assertNotIn('var(--accent)', block)
        self.assertNotIn('var(--vip)', block)


class TestChartAntiPatterns(unittest.TestCase):
    """Guards against the specific chart mistakes that are easy to reintroduce."""

    def chart_css(self):
        src = source()
        return src[src.index('/* ---------- time-series charts'):
                   src.index('/* ---------- trust panel ---------- */')]

    def test_gridlines_and_axes_are_solid_not_dashed(self):
        # Dashing reads as "threshold" or "projection" when it is only a grid.
        css = self.chart_css()
        grid = re.search(r'\.gridline \{([^}]*)\}', css).group(1)
        axis = re.search(r'\.axisline \{([^}]*)\}', css).group(1)
        self.assertNotIn('dasharray', grid)
        self.assertNotIn('dasharray', axis)

    def test_lines_are_2px_with_round_caps(self):
        css = self.chart_css()
        line = re.search(r'\.sline \{([^}]*)\}', css).group(1)
        self.assertIn('stroke-width: 2', line)
        self.assertIn('round', line)

    def test_end_markers_carry_a_surface_ring_not_a_border(self):
        css = self.chart_css()
        dot = re.search(r'\.sdot \{([^}]*)\}', css).group(1)
        self.assertIn('var(--panel)', dot)     # ring in the SURFACE colour
        self.assertIn('stroke-width: 2', dot)

    def test_axis_and_label_text_use_text_tokens_not_series_colors(self):
        css = self.chart_css()
        for rule in ('.tick', '.endlab'):
            body = re.search(re.escape(rule) + r' \{([^}]*)\}', css).group(1)
            self.assertNotIn('#3987e5', body)
            self.assertNotIn('#d95926', body)

    def test_only_the_endpoint_is_directly_labelled(self):
        # Never a number on every point. The end label is emitted once, guarded
        # on the first series only.
        src = source()
        block = src[src.index('const paths = def.series.map'):
                    src.index('// A legend for two or more series')]
        self.assertIn("si === 0", block)
        self.assertEqual(block.count('class="endlab"'), 1)

    def test_no_svg_stretches_its_aspect_ratio(self):
        # preserveAspectRatio="none" scales x and y independently, which
        # distorts stroke width and turns the end dots into ellipses.
        self.assertNotIn('preserveAspectRatio="none"', source())


class TestChartStructure(unittest.TestCase):
    def test_the_panel_and_host_element_exist(self):
        src = source()
        self.assertIn('Metrics over time', src)
        self.assertIn('id="charts"', src)

    def test_every_metric_the_advisor_asked_for_has_a_chart(self):
        src = source()
        block = src[src.index('const CHART_DEFS'):src.index('function niceCeil')]
        for key in ('thr', 'del', 'pdr', 'jain', 'load', 'drop',
                    # Trust value, routing reliability and the network-lifetime
                    # analogue (service availability).
                    'trust', 'rel', 'life'):
            self.assertIn(f"key: '{key}'", block)

    def test_task_loss_and_openflow_drops_stay_separate_series(self):
        """The packet-drop discipline, in chart form.

        Task-level loss (work that did not get done) and quarantine drop-rule
        hits (zero-trust enforcement working) are different things and must
        never be summed into one "drops" line -- the same rule
        interval_report.py keeps for the offline report.
        """
        src = source()
        block = src[src.index("key: 'drop'"):src.index('function niceCeil')]
        self.assertIn('tasks lost', block)
        self.assertIn('quarantine drops', block)

    def test_a_legend_is_rendered_only_for_multi_series_charts(self):
        # >=2 series always get a legend; a single series needs none, since the
        # title already names what is plotted.
        src = source()
        self.assertIn('def.series.length > 1', src)

    def test_charts_ingest_before_the_per_panel_switch(self):
        # The panels ignore 'report' events, which is where PDR and delay come
        # from, so binning has to run ahead of (and independently of) them.
        src = source()
        handle = src[src.index('function handle(ev) {'):src.index('function setConn')]
        self.assertLess(handle.index('chartIngest(ev)'), handle.index('switch (ev.type)'))

    def test_rendering_is_throttled(self):
        # A sustained flood is hundreds of events/sec; rebuilding six SVGs per
        # event would let the attack traffic slow the dashboard down.
        src = source()
        self.assertIn('scheduleChartRender', src)
        self.assertIn('_chartTimer', src)


class TestChartTimelineAnchor(unittest.TestCase):
    """The chart timeline is anchored to the RUN, not to when the page connected.

    The controller is the same process that serves this page, so it routinely
    outlives several topologies. Anchoring on the first event the browser ever
    saw put `t0` hours in the past on a long-lived page, which broke three
    things at once -- an absolute x axis reading "16770s" 40 seconds into a run,
    attack bands drawn ~1600 buckets off-screen so the shaded onsets never
    rendered at all, and the previous run's flow-rule state forward-filling a
    flat throughput line for rules that no longer existed.
    """

    def test_the_topology_event_reanchors_and_resets(self):
        src = source()
        ingest = src[src.index('function chartIngest(ev)'):src.index('function pct(')]
        self.assertIn("if (ev.type === 'topology') { resetCharts(ts); return; }", ingest)

    def test_the_reset_clears_every_carry_over_across_runs(self):
        """Anything that survives a reset silently mixes two runs.

        `vipBps` forward-fills throughput, and `prevDropPkts` holds cumulative
        counter baselines -- both are meaningless once the switch's rules are
        torn down and rebuilt.
        """
        src = source()
        body = src[src.index('function resetCharts(ts)'):src.index('function chartIngest(ev)')]
        for field in ('CH.buckets', 'CH.vipBps', 'CH.prevDropPkts',
                      'CH.lastBps', 'CH.lastBpsByNode', 'CH.t0'):
            self.assertIn(field, body, f'{field} survives a re-anchor')

    def test_reanchoring_happens_before_the_bucket_is_allocated(self):
        # Otherwise the topology event itself lands in a bucket on the OLD
        # timeline and the new run starts at index 1, not 0.
        src = source()
        ingest = src[src.index('function chartIngest(ev)'):src.index('function pct(')]
        self.assertLess(ingest.index('resetCharts(ts)'), ingest.index('bucketFor(ts)'))

    def test_the_anchor_agrees_with_the_offline_report(self):
        """Re-anchoring makes the live panel AGREE with interval_report.py.

        The offline report anchors on the first event of the recording; a
        recording's first event is its topology event. So both now bin from the
        same instant, where before the live panel could be hours adrift. If a
        future change stops emitting topology first, the two diverge silently
        and this fails instead.
        """
        import random
        from dashboard.generate_demo_recording import Sim
        random.seed(7)
        events = Sim().run()
        self.assertEqual(events[0]['type'], 'topology')
        self.assertEqual(
            events[0]['ts'], min(e['ts'] for e in events),
            'topology must also be the EARLIEST event, not merely the first '
            'written -- interval_report anchors on ordered[0]',
        )
        src = Path('evaluation/interval_report.py').read_text()
        self.assertIn("t0 = ordered[0].get('ts'", src)


class TestEmptyChartsKeepTheirFrame(unittest.TestCase):
    def test_a_metric_with_no_data_still_renders_a_chart(self):
        """Returning '' dropped the chart out of the grid entirely.

        Six charts silently became four, and a reader cannot tell "nothing
        reported yet" from "this chart was removed". Delay and PDR both hit
        this, since both come only from `report` events.
        """
        src = source()
        start = src.index('const flat = cols.flat()')
        block = src[start:src.index('const top =', start)]
        self.assertNotIn("return '';", block)
        self.assertIn('cempty', block)
        self.assertIn('no data in this window yet', block)

    def test_the_placeholder_holds_the_same_height_as_a_plot(self):
        # Or the surviving charts reflow around the gap every time one fills in.
        src = source()
        css = re.search(r'\.cempty \{([^}]*)\}', src).group(1)
        self.assertIn('height: 118px', css)


class TestClusterCharts(unittest.TestCase):
    """The per-cluster panel: the same buckets, aggregated by node group.

    It is a different SELECTION of series over the same evidence, not a second
    charting implementation -- so most of what needs guarding here is that it
    stayed that way, and that the split does not quietly claim attribution the
    events cannot support.
    """

    def cluster_block(self):
        src = source()
        return src[src.index('const CLUSTER_CHART_DEFS'):
                   src.index('function niceCeil')]

    def test_the_panel_and_host_element_exist(self):
        src = source()
        self.assertIn('Metrics over time — by cluster', src)
        self.assertIn('id="clusterCharts"', src)

    def test_every_fleet_metric_has_a_cluster_counterpart(self):
        block = self.cluster_block()
        for key in ('cthr', 'cdel', 'cpdr', 'cjain', 'cload', 'cdrop', 'cqdrop'):
            self.assertIn(f"key: '{key}'", block)

    def test_exactly_two_clusters_because_two_slots_were_validated(self):
        """One colour per cluster, held across every chart in the panel.

        That fixes the series budget at two, which is exactly the two validated
        categorical slots this surface has. A third cluster is not a config
        change -- it needs the palette validator re-run first.
        """
        src = source()
        defs = src[src.index('function clusterDefs()'):src.index('// Sum one per-node field')]
        self.assertEqual(defs.count("key: 'A'"), 1)
        self.assertEqual(defs.count("key: 'B'"), 1)
        self.assertIn('color: SERIES_1', defs)
        self.assertIn('color: SERIES_2', defs)
        # No third hue smuggled in.
        self.assertNotIn('SERIES_3', src)

    def test_cluster_membership_comes_from_the_topology_roster(self):
        # Not a hardcoded srv1..srv4 list: the roster is whatever the run
        # actually built, so the panel works at any fleet size and cannot
        # silently omit a node the config added.
        src = source()
        defs = src[src.index('function clusterDefs()'):src.index('// Sum one per-node field')]
        self.assertIn('serverRoster()', defs)
        for hardcoded in ("'srv1'", "'srv4'", "'srv5'", "'srv8'"):
            self.assertNotIn(hardcoded, defs)

    def test_task_loss_and_quarantine_drops_get_a_chart_each(self):
        """The packet-drop discipline, held harder rather than relaxed.

        The fleet panel keeps them as two series on one plot. Here both series
        slots are spent on the clusters, so they cannot share a plot at all --
        and the answer is two charts, never one summed "drops" line.
        """
        block = self.cluster_block()
        self.assertIn("key: 'cdrop'", block)
        self.assertIn("key: 'cqdrop'", block)
        drop = block[block.index("key: 'cdrop'"):block.index("key: 'cqdrop'")]
        self.assertNotIn('dropPkts', drop)   # task loss only
        qdrop = block[block.index("key: 'cqdrop'"):]
        self.assertNotIn("'timeout'", qdrop)  # enforcement only

    def test_offered_load_is_not_attributed_to_a_cluster(self):
        """`route_denied` carries no chosen node, so offered load has no cluster.

        Plotting it per cluster would mean inventing an attribution the event
        stream does not have. The chart plots requests ROUTED and says so.
        """
        block = self.cluster_block()
        self.assertIn("title: 'Requests routed'", block)
        self.assertNotIn("'offered'", block)
        self.assertNotIn('b.offered', block)
        src = source()
        ingest = src[src.index("case 'route_denied':"):src.index("case 'flow_stats':")]
        self.assertNotIn('nodeSlot', ingest)

    def test_both_panels_share_one_renderer(self):
        # Two drawing paths would drift, which is the argument this file's
        # binning rules already answer that way.
        src = source()
        self.assertEqual(src.count('host.innerHTML = defs.map'), 1)
        self.assertIn("renderCharts('clusterCharts', defs)", src)

    def test_hover_is_scoped_to_the_panel_it_drew(self):
        # document.querySelectorAll would re-wire the other panel's charts
        # against the wrong series list on every redraw.
        src = source()
        start = src.index('function wireChartHover(')
        hover = src[start:src.index('function setConn', start)]
        self.assertIn('host.querySelectorAll', hover)
        self.assertNotIn("document.querySelectorAll('.chart')", hover)

    def test_binning_uses_the_node_fields_the_events_actually_carry(self):
        """No controller change was needed, and this pins why.

        `route.chosen`, `report.node` and `flow_stats.rules[].node` are all
        already published. If a future edit starts binning on something the
        recording does not carry, the cluster panel would go silently empty
        rather than error.
        """
        src = source()
        ingest = src[src.index('function chartIngest(ev)'):src.index('function pct(')]
        self.assertIn('nodeSlot(b, ev.chosen)', ingest)
        self.assertIn('nodeSlot(b, ev.node)', ingest)
        self.assertIn('nodeSlot(b, r.node)', ingest)

    def test_throughput_forward_fills_per_node_too(self):
        # A quiet bucket is not a zero-throughput bucket -- the rule the fleet
        # series already follows. Applied per node, or a quiet cluster reads as
        # a dead one.
        src = source()
        self.assertIn('bpsByNode: { ...CH.lastBpsByNode }', src)
        self.assertIn('lastBpsByNode', src)

    def test_the_split_is_labelled_as_positional_not_physical(self):
        """One server per edge switch here, so the halves are a convention.

        A reader must not be able to infer a locality, rack or failure domain
        that the topology does not have. It is said on the panel itself, not
        only in a comment.
        """
        src = source()
        self.assertIn('positional split, not a physical one', src)
        self.assertIn('id="clusterKey"', src)

    def test_cluster_membership_is_rendered_not_inferred(self):
        # Which node sits in which cluster has to be readable off the panel.
        src = source()
        self.assertIn('c.members.join', src)


class TestScalingPanel(unittest.TestCase):
    """The one panel whose x axis is a node count instead of elapsed time.

    Its data cannot come from a run -- a run has one roster -- so it is
    pre-computed by evaluation/scale_compare.py and served over
    /api/scale_compare. The properties worth pinning are the ones a reader
    would be misled by if they silently broke: that it is marked as not live,
    that time-only decoration does not leak onto a non-time axis, and that the
    two rows are not quietly collapsed into one.
    """

    def scale_block(self):
        src = source()
        return src[src.index('const SCALE_SERIES'):
                   src.index('function renderScaleCharts')]

    def test_the_panel_and_its_row_host_exist(self):
        src = source()
        self.assertIn('Client load — 20→40 IoT devices', src)
        self.assertIn('id="scaleCharts"', src)
        # Row hosts are built from the payload's row keys, not hardcoded, so
        # pin the template that produces them.
        self.assertIn('id="scale_${row.key}"', src)

    def test_no_fleet_size_row_is_reintroduced_without_a_live_run(self):
        """The removed row swept 20-40 edge SERVERS against a live topology of
        8, projecting five fleet sizes past anything ever instantiated. A
        projection on the same page as live charts is a claim this project
        cannot defend, so its absence is pinned rather than left to memory.

        The capability itself was not lost: scalability_sweep.py still sweeps N
        on the CLI, where the number reads as the simulation output it is.
        """
        gen = Path('evaluation/scale_compare.py').read_text()
        self.assertIn("'key': 'clients'", gen)
        self.assertNotIn("'key': 'fleet'", gen)
        # The roster is the fixed quantity, not a swept one.
        self.assertIn('SERVERS = 8', gen)
        self.assertIn('DEVICE_COUNTS', gen)
        # scalability_sweep.py keeps the N axis.
        sweep = Path('evaluation/scalability_sweep.py').read_text()
        self.assertIn("'--ns'", sweep)

    def test_the_page_renders_whatever_rows_it_is_given(self):
        # Not a hardcoded single row: if a second sweep is ever added it is a
        # generator change, not a dashboard one.
        self.assertIn('payload.rows.map', source())

    def test_every_metric_needed_for_both_failure_modes_has_a_chart(self):
        """Saturation shows in throughput/PDR/delay; starvation shows in Jain
        and the starved count. A panel carrying only the first three would
        show argmax and p2c agreeing on the client-load row."""
        block = self.scale_block()
        for key in ('sthr', 'sdel', 'spdr', 'sjain', 'sstarve', 'sdec'):
            self.assertIn(f"key: '{key}'", block)

    def test_the_panel_is_marked_as_not_live(self):
        """Every other panel on this page reports the current run. This one
        does not, and on a live dashboard that has to be visible on the panel
        rather than only true in a docstring.

        The note must also say what is real (the selector) and what is not (the
        servers, the network) -- 'simulation' alone invites a reader to assume
        the routing logic was modelled too, when it is the shipping function.
        """
        src = source()
        self.assertIn('<b>Not live — simulation.</b>', src)
        self.assertIn('sweepNote', src)
        note = src[src.index('sweepNote"><b>Not live'):src.index('scale_compare</code>')]
        self.assertIn('select_edge_node', note)
        self.assertIn('network is not modelled', note)

    def test_attack_bands_are_suppressed_on_the_node_count_axis(self):
        """Bands mark a moment in TIME. Drawn against a node count they would
        shade an unrelated run's arming second at "node 30" -- a nonsense claim
        made with the authority of a shaded region."""
        src = source()
        self.assertIn('bands: false', src)
        renderer = src[src.index('function renderCharts('):
                       src.index('function wireChartHover')]
        self.assertIn("opts.bands === false ? [] : attackOnsets()", renderer)

    def test_there_is_still_exactly_one_renderer(self):
        """The scaling panel is a different x QUANTITY, not a second chart
        implementation. A fork would drift in units, tick precision or
        empty-state handling, which is the same argument the cluster panel
        already answers this way."""
        src = source()
        self.assertEqual(src.count('function renderCharts('), 1)
        self.assertEqual(src.count('function wireChartHover('), 1)
        # ...and the scaling panel reaches it through the shared entry point.
        self.assertIn('renderCharts(`scale_${row.key}`', src)

    def test_the_scaling_panel_introduces_no_new_hue(self):
        """Two series again (p2c vs argmax), so this panel spends the same two
        validated palette slots the cluster panel does. A third strategy needs
        the validator re-run, not a hand-picked colour."""
        block = self.scale_block()
        self.assertIn('color: SERIES_1', block)
        self.assertIn('color: SERIES_2', block)
        self.assertNotIn('SERIES_3', source())
        # Exactly two strategies plotted.
        self.assertEqual(block.count("name: 'p2c'"), 1)
        self.assertEqual(block.count("name: 'argmax'"), 1)

    def test_rows_are_pivoted_by_x_value_not_by_position(self):
        """The two sweep rows emit their points in different orders --
        strategy-major for the fleet row, x-major for the client row, because
        one calls run_sweep once and the other once per device count. Pairing
        by position would put p2c's numbers under argmax's name in one of them.
        """
        src = source()
        pivot = src[src.index('function scaleRows('):src.index('function scaleChartDefs')]
        self.assertIn('row.x[i]', pivot)
        self.assertIn('byX.get(xv)[p.strategy] = p', pivot)


class TestScaleComparePayload(unittest.TestCase):
    """Shape checks on what the generator hands the panel.

    The browser code cannot be executed here (no JS runtime on this box, and
    the page has no build step -- see the module docstring), so the pivot the
    panel depends on is verified against the real payload in Python instead.
    """

    def payload(self):
        import json
        p = Path('data/scale_compare.json')
        if not p.exists():
            self.skipTest('no sweep generated; run python3 -m evaluation.scale_compare')
        return json.loads(p.read_text())

    def test_every_x_value_carries_both_strategies(self):
        """What scaleRows() assumes: pivoting by x yields one row per node
        count with both strategies present. A hole would render as a gap in
        one line, which reads as a dip rather than as missing data."""
        for row in self.payload()['rows']:
            by_x = {}
            for x, pt in zip(row['x'], row['points']):
                by_x.setdefault(x, set()).add(pt['strategy'])
            self.assertTrue(by_x, f"row {row['key']} has no points")
            for x, strategies in sorted(by_x.items()):
                self.assertEqual(
                    strategies, {'argmax', 'p2c'},
                    f"row {row['key']} x={x} is missing a strategy: {strategies}",
                )

    def test_the_roster_is_held_at_the_deployed_size(self):
        """The variable is the DEVICE count. If the server count ever moves
        with it the panel silently becomes a fleet-size projection again --
        the exact thing that was removed."""
        payload = self.payload()
        clients = next(r for r in payload['rows'] if r['key'] == 'clients')
        self.assertEqual({pt['n'] for pt in clients['points']}, {8})
        # 8 is not a number chosen here: it is what the shipped config deploys.
        import yaml
        with open('config/params.yaml') as f:
            cfg = yaml.safe_load(f)
        self.assertEqual(cfg['simulation']['num_edge_nodes'], 8)

    def test_the_sweep_ends_at_the_deployed_device_count(self):
        """40 is config/params.yaml's num_iot_devices. Ending there is what
        keeps both axes inside the topology the project actually builds."""
        import yaml
        with open('config/params.yaml') as f:
            cfg = yaml.safe_load(f)
        payload = self.payload()
        self.assertEqual(max(payload['meta']['device_counts']),
                         cfg['simulation']['num_iot_devices'])

    def test_offered_load_rises_with_the_device_count(self):
        payload = self.payload()
        clients = next(r for r in payload['rows'] if r['key'] == 'clients')
        loads = {}
        for x, pt in zip(clients['x'], clients['points']):
            loads[x] = pt['load_factor']
        xs = sorted(loads)
        self.assertEqual([loads[x] for x in xs], sorted(loads[x] for x in xs))
        self.assertGreater(loads[xs[-1]], loads[xs[0]])

    def test_pdr_is_stored_as_the_percent_the_chart_plots(self):
        # The chart caps this axis at max: 100. A 0-1 fraction here would draw
        # every PDR as a flat line on the floor.
        for row in self.payload()['rows']:
            for pt in row['points']:
                self.assertLessEqual(pt['pdr'], 100.0)
                self.assertGreaterEqual(pt['pdr'], 0.0)


if __name__ == '__main__':
    unittest.main()


class TestGroundTruthSplitCharts(unittest.TestCase):
    """Trust, routing reliability and service availability.

    All three are split honest-vs-attacker and must never be averaged into one
    series: quarantine downtime means opposite things for the two groups, so a
    combined figure is a mean over two quantities that should move in opposite
    directions. This is evaluation/availability_report.py's central rule
    (see its "THE RULE THIS MODULE EXISTS TO ENFORCE" section), carried into
    chart form the same way the packet-drop discipline was.
    """

    def _defs(self):
        src = source()
        return src[src.index('const CHART_DEFS'):src.index('function niceCeil')]

    def test_trust_is_split_by_ground_truth(self):
        block = self._defs()
        chunk = block[block.index("key: 'trust'"):block.index("key: 'rel'")]
        self.assertIn('honest', chunk)
        self.assertIn('attacker', chunk)

    def test_availability_keeps_serving_and_containment_apart(self):
        block = self._defs()
        chunk = block[block.index("key: 'life'"):]
        self.assertIn('honest serving', chunk)
        self.assertIn('attackers contained', chunk)

    def test_an_absent_group_is_null_never_zero(self):
        # "No attackers configured" must not render as "no attacker contained",
        # which would read as total enforcement failure on every clean run.
        src = source()
        gt = src[src.index('function serverGroundTruth'):src.index('function attackOnsets')]
        self.assertIn('return null', gt)
        # mean() over an empty sample is null, not 0.
        mean = src[src.index('function mean(xs)'):src.index('function serverGroundTruth')]
        self.assertIn('null', mean)

    def test_reliability_charges_a_resteer_to_its_originating_bucket(self):
        """Charging a re-steer where it LANDS lets a quarantine burst exceed
        that bucket's route count and drive reliability negative -- which would
        then need a clamp, and a clamp that hides an out-of-range value is the
        kind of knob this project removes rather than adds."""
        src = source()
        self.assertIn('routeOrigin', src)
        # Scoped to chartIngest: handle()'s own switch has same-named cases
        # earlier in the file.
        body = src[src.index('function chartIngest'):src.index('function pct(')]
        ingest = body[body.index("case 'reroute'"):body.index("case 'node_status'")]
        # looked up by the dispatch key, and counted once per DECISION
        self.assertIn('CH.routeOrigin.get', ingest)
        self.assertIn('origin.counted', ingest)

    def test_the_resteer_origin_map_is_bounded(self):
        # A long run must not grow it without limit.
        src = source()
        self.assertIn('MAX_ROUTE_ORIGIN', src)
        self.assertIn('CH.routeOrigin.delete', src)


class TestStructuralMetricsMatchThePythonImplementation(unittest.TestCase):
    """Node degree and distance to sink exist twice -- JS in the browser,
    Python in evaluation/topology_metrics.py -- for the same reason BUCKET_S
    does: the panel draws live while the offline module must run on a box with
    no controller installed. They cannot share code, so they are pinned.
    """

    def test_the_sink_constant_matches(self):
        self.assertIn(f"const SINK = '{DEFAULT_SINK}'", source())

    def test_an_unreported_delay_is_null_not_zero_on_both_sides(self):
        src = source()
        fn = src[src.index('function distanceToSink'):src.index('const KIND_ORDER')]
        self.assertIn('null', fn)
        # and the table must render it as something other than a number
        self.assertIn('class="na"', src)

    def test_the_two_implementations_agree_on_a_real_graph(self):
        """Actually run the browser code and compare, rather than trusting that
        two hand-written traversals stayed in step."""
        node = shutil.which('node')
        if node is None:                      # pragma: no cover
            self.skipTest('node not available to execute the dashboard JS')

        src = source()
        js = src[src.index('const SINK ='):src.index('const KIND_ORDER')]

        graph = {
            'nodes': [
                {'id': 's0', 'kind': 'core_switch'},
                {'id': 's1', 'kind': 'edge_switch'},
                {'id': 's2', 'kind': 'edge_switch'},
                {'id': 'srv1', 'kind': 'server'},
                {'id': 'srv2', 'kind': 'server'},
                {'id': 'iot1', 'kind': 'iot'},
                {'id': 'iot2', 'kind': 'iot'},
                {'id': 'iot3', 'kind': 'iot'},
                {'id': 'orphan', 'kind': 'iot'},
            ],
            'links': [
                {'a': 's1', 'b': 'srv1', 'delay_ms': 2.0},
                {'a': 's0', 'b': 's1', 'delay_ms': 5.0},
                {'a': 's2', 'b': 'srv2', 'delay_ms': 2.0},
                {'a': 's0', 'b': 's2', 'delay_ms': 5.0},
                {'a': 'iot1', 'b': 's1', 'delay_ms': 9.0},
                {'a': 'iot2', 'b': 's2', 'delay_ms': 3.0},
                {'a': 'iot3', 'b': 's1'},              # never reported
                {'a': 'srv1', 'b': 'ghost'},           # unknown endpoint
                {'a': 'srv2', 'b': 'srv2'},            # self-loop
            ],
        }
        driver = (
            js
            + f'\nconst g = {json.dumps(graph)};\n'
            + 'console.log(JSON.stringify({'
              'degree: nodeDegree(g), dist: distanceToSink(g)}));\n'
        )
        with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False) as fh:
            fh.write(driver)
            path = fh.name
        try:
            out = subprocess.run(
                [node, path], capture_output=True, text=True, timeout=30,
            )
        finally:
            os.unlink(path)
        self.assertEqual(out.returncode, 0, out.stderr)
        got = json.loads(out.stdout)

        self.assertEqual(got['degree'], node_degree(graph))

        want = distance_to_sink(graph)
        self.assertEqual(sorted(got['dist']), sorted(want))
        for nid, exp in want.items():
            self.assertEqual(
                got['dist'][nid]['hops'], exp['hops'],
                f'hops disagree for {nid}',
            )
            self.assertEqual(
                got['dist'][nid]['delay_ms'], exp['delay_ms'],
                f'delay disagrees for {nid}',
            )


class TestNodeStructurePanel(unittest.TestCase):
    def test_the_panel_exists(self):
        src = source()
        self.assertIn('Node structure', src)
        self.assertIn('id="nodestruct"', src)

    def test_it_says_the_delay_is_configured_not_measured(self):
        # It is an input handed to tc, not an observed RTT. End-to-end delay is
        # a different metric and already has its own chart.
        src = source()
        panel = src[src.index('Node structure'):src.index('id="nodestruct"')]
        self.assertIn('configured', panel.lower())

    def test_it_names_the_sink(self):
        src = source()
        panel = src[src.index('Node structure'):src.index('id="nodestruct"')]
        self.assertIn('s0', panel)

    def test_link_parameters_arrive_over_their_own_event(self):
        # Re-publishing 'topology' would give dashboard/replay.py two competing
        # graphs -- it reads the head-of-recording one as authoritative.
        src = source()
        self.assertIn("case 'topology_links'", src)
