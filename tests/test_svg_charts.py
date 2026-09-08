"""Tests for evaluation/svg_charts.py.

These assert on the emitted markup, which is the whole reason the analysis
page renders server-side. The live dashboard's charts had three defects that
the palette validator could not see and that only surfaced when a human read
the generated SVG (panel_fix.md 6.3): y-ticks at three different precisions on
one axis, an endpoint label running past the viewBox, and
`preserveAspectRatio="none"` stretching strokes. Each of those is an ordinary
assertion here.
"""

import re
import unittest

from evaluation.svg_charts import (
    BAD, DIM, GOOD, S1, S2, SEQ, SURFACE,
    empty_figure, fmt_tick, fmt_val, forest_plot, hbar, heatmap, legend,
    line_chart, nice_ceil, stat_tile, table, text_w,
)


def _viewbox(svg: str):
    m = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
    assert m, 'no viewBox'
    return float(m.group(1)), float(m.group(2))


class TestNumberFormatting(unittest.TestCase):
    def test_nice_ceil_rounds_to_clean_numbers(self):
        for v, want in [(0.9, 1), (1.1, 2), (2.1, 2.5), (3, 5), (7, 10), (85, 100)]:
            self.assertEqual(nice_ceil(v), want, v)

    def test_nice_ceil_handles_zero_and_negative(self):
        self.assertEqual(nice_ceil(0), 1.0)
        self.assertEqual(nice_ceil(-5), 1.0)

    def test_tick_precision_comes_from_the_axis_top_not_the_tick(self):
        # The defect this exists to prevent: '0.00 / 50.0 / 100' -- three
        # precisions for three numbers on one scale.
        top = 100.0
        ticks = [fmt_tick(f * top, top) for f in (0.0, 0.5, 1.0)]
        self.assertEqual(ticks, ['0', '50', '100'])
        decimals = {t.split('.')[1] if '.' in t else '' for t in ticks}
        self.assertEqual(len(decimals), 1, f'mixed precision on one axis: {ticks}')

    def test_tick_precision_is_uniform_on_a_fractional_axis(self):
        ticks = [fmt_tick(f * 1.0, 1.0) for f in (0.0, 0.5, 1.0)]
        self.assertEqual(ticks, ['0.0', '0.5', '1.0'])

    def test_none_renders_as_an_em_dash_never_zero(self):
        self.assertEqual(fmt_val(None), '—')
        self.assertNotEqual(fmt_val(None), '0')


class TestLineChart(unittest.TestCase):
    def _series(self, values, name='a', color=S1):
        return {'name': name, 'color': color, 'values': values}

    def test_renders_a_path_per_series(self):
        out = line_chart('T', '', [self._series([1, 2, 3]), self._series([3, 2, 1], 'b', S2)],
                         [(0, '0s')])
        self.assertEqual(out.count('class="sline"'), 2)

    def test_a_gap_breaks_the_path_rather_than_bridging_it(self):
        """Interpolating across a None would draw a straight line through a
        window where nothing was measured, which reads as data."""
        out = line_chart('T', '', [self._series([1, None, 3])], [(0, '0s')])
        d = re.search(r'class="sline" d="([^"]+)"', out).group(1)
        # Two move commands => the pen lifted at the gap.
        self.assertEqual(d.count('M'), 2, f'path did not break at the gap: {d}')

    def test_an_all_none_series_is_an_empty_state_not_a_flat_zero_line(self):
        out = line_chart('T', '', [self._series([None, None])], [(0, '0s')])
        self.assertIn('fig-empty', out)
        self.assertNotIn('class="sline"', out)

    def test_only_the_endpoint_is_directly_labelled(self):
        # A value on every point is chaos and goes unread.
        out = line_chart('T', '', [self._series([1, 2, 3, 4, 5])], [(0, '0s')])
        self.assertEqual(out.count('class="endlab"'), 1)

    def test_labels_stay_inside_the_viewbox(self):
        """Measures where each label ENDS, not where it starts.

        The defect that shipped was an endpoint label whose text ran past the
        box and overhung the next chart in the grid -- its x was comfortably
        inside. A start-only check passes on that bug, so it would have been a
        test that could never fail.
        """
        for values, unit in (([88.888, 99.999], '%'),
                             ([1.0, 88888.8], 'kbps'),
                             ([0.001, 0.002], '')):
            out = line_chart('T', '', [self._series(values)], [(0, '0s')], unit=unit)
            w, _ = _viewbox(out)
            for m in re.finditer(r'<text[^>]*\bx="([\d.]+)"[^>]*>([^<]*)<', out):
                x, txt = float(m.group(1)), m.group(2)
                end = x + text_w(txt)
                self.assertLessEqual(
                    end, w + 0.5,
                    f'label {txt!r} ends at {end:.1f} past viewBox width {w}')

    def test_a_wider_endpoint_label_widens_the_margin(self):
        # The mechanism behind the test above: the margin is measured from the
        # label, not fixed. A long value must push the plot area left.
        narrow = line_chart('T', '', [self._series([1.0, 2.0])], [(0, '0s')])
        wide = line_chart('T', '', [self._series([1.0, 88888.8])], [(0, '0s')], unit='kbps')
        end_narrow = float(re.search(r'class="endlab" x="([\d.]+)"', narrow).group(1))
        end_wide = float(re.search(r'class="endlab" x="([\d.]+)"', wide).group(1))
        self.assertLess(end_wide, end_narrow)

    def test_aspect_ratio_is_never_stretched(self):
        out = line_chart('T', '', [self._series([1, 2])], [(0, '0s')])
        self.assertNotIn('preserveAspectRatio="none"', out)
        self.assertIn('preserveAspectRatio="xMidYMid meet"', out)

    def test_gridlines_are_solid_never_dashed(self):
        # Dashing reads as "threshold" or "projection" when it is only a grid.
        out = line_chart('T', '', [self._series([1, 2])], [(0, '0s')])
        self.assertNotIn('stroke-dasharray', out)

    def test_a_legend_appears_for_two_series_and_not_for_one(self):
        one = line_chart('T', '', [self._series([1, 2])], [(0, '0s')])
        two = line_chart('T', '', [self._series([1, 2]), self._series([2, 1], 'b', S2)], [(0, '0s')])
        self.assertNotIn('class="legend"', one)
        self.assertIn('class="legend"', two)

    def test_attack_bands_are_drawn_and_labelled(self):
        out = line_chart('T', '', [self._series([1, 2, 3])], [(0, '0s')],
                         bands=[(1, 'srv3 sybil')])
        self.assertIn('class="band"', out)
        self.assertIn('srv3 sybil', out)

    def test_a_band_beyond_the_window_is_clamped_inside_it(self):
        out = line_chart('T', '', [self._series([1, 2, 3])], [(0, '0s')],
                         bands=[(999, 'late')])
        w, _ = _viewbox(out)
        for x in [float(m) for m in re.findall(r'<rect class="band" x="([\d.]+)"', out)]:
            self.assertLessEqual(x, w)


class TestHbar(unittest.TestCase):
    ROWS = [('zt_sdn', 0.0984), ('no_trust', 0.1159), ('least_conn', 0.2780)]

    def test_the_subject_gets_the_hue_and_the_rest_get_the_gray(self):
        """The emphasis form. Six categorical hues for six routing strategies
        would bury the one series the reader is here for."""
        out = hbar('m', '', self.ROWS, highlight='zt_sdn')
        self.assertEqual(out.count(f'fill="{S1}"'), 1)
        self.assertEqual(out.count(f'fill="{DIM}"'), 2)

    def test_a_missing_value_is_a_dash_not_a_zero_length_bar(self):
        out = hbar('m', '', [('a', 1.0), ('b', None)])
        self.assertIn('class="rowval na"', out)
        self.assertEqual(out.count('class="bar"'), 1)

    def test_every_bar_is_labelled_with_its_value(self):
        out = hbar('m', '', self.ROWS, highlight='zt_sdn')
        self.assertEqual(out.count('class="rowval"'), 3)

    def test_the_direction_of_better_is_stated(self):
        # A comparison chart that does not say which way is better is a chart
        # the reader has to guess at.
        self.assertIn('lower is better', hbar('m', '', self.ROWS))
        self.assertIn('higher is better', hbar('m', '', self.ROWS, lower_is_better=False))

    def test_bars_are_capped_and_do_not_fill_their_row(self):
        out = hbar('m', '', self.ROWS, row_h=22)
        heights = {float(h) for h in re.findall(r'<rect class="bar"[^>]*height="([\d.]+)"', out)}
        self.assertTrue(all(h <= 14 for h in heights), heights)

    def test_no_rows_is_an_empty_state(self):
        self.assertIn('fig-empty', hbar('m', '', []))

    def test_values_never_exceed_the_axis(self):
        out = hbar('m', '', [('a', 5.0)], x_max=1.0)
        widths = [float(w) for w in re.findall(r'<rect class="bar"[^>]*width="([\d.]+)"', out)]
        self.assertTrue(all(w <= 420 for w in widths))


class TestForestPlot(unittest.TestCase):
    def test_significance_is_carried_by_shape_as_well_as_colour(self):
        """Hollow when not significant, so the distinction survives print and
        full colour-vision deficiency -- never colour alone."""
        out = forest_plot('i', '', [
            {'label': 'a', 'value': 15.0, 'significant': True},
            {'label': 'b', 'value': -10.0, 'significant': False},
        ])
        self.assertIn(f'fill="{GOOD}"', out)
        self.assertIn('fill="none"', out)

    def test_a_loss_is_drawn_on_the_other_side_of_zero(self):
        out = forest_plot('i', '', [{'label': 'a', 'value': -10.0, 'significant': True}])
        self.assertIn(f'fill="{BAD}"', out)

    def test_the_zero_line_is_an_axis_not_a_gridline(self):
        out = forest_plot('i', '', [{'label': 'a', 'value': 5.0, 'significant': True}])
        self.assertIn('class="axis"', out)

    def test_annotation_text_is_used_when_given(self):
        out = forest_plot('i', '', [
            {'label': 'a', 'value': 15.1, 'significant': True,
             'annotation': '-15.1% p_adj=7.45e-09'},
        ])
        self.assertIn('p_adj=7.45e-09', out)

    def test_no_rows_is_an_empty_state(self):
        self.assertIn('fig-empty', forest_plot('i', '', []))


class TestHeatmap(unittest.TestCase):
    MATRIX = [[1, 0], [0, 40]]
    LABELS = ['sybil', 'none']

    def test_cells_come_from_the_single_hue_ramp(self):
        out = heatmap('c', '', self.LABELS, self.LABELS, self.MATRIX)
        used = {c for c in SEQ if f'fill="{c}"' in out}
        self.assertTrue(used, 'no ramp colour used')

    def test_an_empty_cell_recedes_to_the_surface_rather_than_glowing(self):
        # On a dark page the low end must be the dark end.
        out = heatmap('c', '', self.LABELS, self.LABELS, self.MATRIX)
        self.assertIn('fill="#1c2129"', out)

    def test_zero_cells_carry_no_number(self):
        out = heatmap('c', '', self.LABELS, self.LABELS, self.MATRIX)
        self.assertEqual(out.count('class="cellval"'), 2)

    def test_counts_render_as_integers(self):
        out = heatmap('c', '', self.LABELS, self.LABELS, self.MATRIX)
        self.assertIn('>40<', out)
        self.assertNotIn('>40.0<', out)

    def test_cells_are_separated_by_a_surface_gap_not_a_stroke(self):
        out = heatmap('c', '', self.LABELS, self.LABELS, self.MATRIX)
        self.assertNotIn('<rect class="cell" stroke', out)

    def test_no_labels_is_an_empty_state(self):
        self.assertIn('fig-empty', heatmap('c', '', [], [], []))


class TestFiguresAndTables(unittest.TestCase):
    def test_stat_tile_tone_ships_with_text_not_colour_alone(self):
        out = stat_tile('Accuracy', '97.9%', '47 of 48 subjects', 'good')
        self.assertIn('tone-good', out)
        self.assertIn('47 of 48 subjects', out)

    def test_legend_is_suppressed_for_a_single_series(self):
        self.assertEqual(legend([('a', S1)]), '')
        self.assertIn('lkey', legend([('a', S1), ('b', S2)]))

    def test_empty_figure_names_the_command_that_would_fix_it(self):
        out = empty_figure('Scalability', '', 'Not generated.',
                           'python3 -m evaluation.scalability_sweep --csv data/x.csv')
        self.assertIn('scalability_sweep', out)

    def test_table_renders_none_as_a_dash(self):
        out = table(['a', 'b'], [['x', None]])
        self.assertIn('—', out)
        self.assertNotIn('None', out)


class TestEscaping(unittest.TestCase):
    def test_labels_are_escaped_everywhere_they_are_interpolated(self):
        nasty = '<script>&"x"'
        for out in (
            hbar('t', '', [(nasty, 1.0)]),
            forest_plot('t', '', [{'label': nasty, 'value': 1.0, 'significant': True}]),
            heatmap('t', '', [nasty], [nasty], [[1]]),
            table(['h'], [[nasty]]),
            stat_tile(nasty, nasty),
            line_chart(nasty, nasty, [{'name': nasty, 'color': S1, 'values': [1, 2]},
                                      {'name': 'b', 'color': S2, 'values': [2, 1]}], [(0, nasty)]),
        ):
            self.assertNotIn('<script>', out)
            self.assertIn('&lt;script&gt;', out)


if __name__ == '__main__':
    unittest.main()
