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

import re
import unittest
from pathlib import Path

from evaluation.interval_report import DEFAULT_BUCKET_S, PRIO_QUARANTINE_DROP

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
        for key in ('thr', 'del', 'pdr', 'jain', 'load', 'drop'):
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


if __name__ == '__main__':
    unittest.main()
