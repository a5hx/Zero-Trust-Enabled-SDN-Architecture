"""Tests for evaluation/build_analysis_page.py.

The page's whole claim is that it *reuses* the analysis modules rather than
re-deriving their numbers for presentation. So the tests that matter most here
compare what the page renders against what the source tool returns -- a page
that quietly disagreed with `attack_report` would be worse than no page, and
would look completely fine.
"""

import json
import re
import unittest
from pathlib import Path

from evaluation import build_analysis_page as B
from evaluation.attack_report import score_run
from evaluation.availability_report import compute as compute_availability
from evaluation.nfr_report import build_report as build_nfr_report


# --------------------------------------------------------------------------- #
# Synthetic recording                                                          #
# --------------------------------------------------------------------------- #
def _graph():
    return {
        'nodes': [
            {'id': 's0', 'kind': 'core_switch'},
            {'id': 's1', 'kind': 'edge_switch'},
            {'id': 's2', 'kind': 'edge_switch'},
            {'id': 'srv1', 'kind': 'server', 'attack': 'none', 'attack_start_s': 0.0},
            {'id': 'srv2', 'kind': 'server', 'attack': 'sybil', 'attack_start_s': 30.0},
            {'id': 'iot1', 'kind': 'iot', 'attack': 'none'},
        ],
        'links': [
            {'a': 's1', 'b': 'srv1', 'kind': 'server_link', 'delay_ms': 2.0},
            {'a': 's0', 'b': 's1', 'kind': 'core_link', 'delay_ms': 5.0},
            {'a': 's2', 'b': 'srv2', 'kind': 'server_link', 'delay_ms': 2.0},
            {'a': 's0', 'b': 's2', 'kind': 'core_link', 'delay_ms': 5.0},
            {'a': 'iot1', 'b': 's1', 'kind': 'iot_link', 'delay_ms': 9.0},
        ],
    }


def _events(n_buckets=8):
    """A small but structurally complete recording."""
    evs = [{'type': 'topology', 'ts': 0.0, 'seq': 0, 'graph': _graph()}]
    seq = 1
    for t in range(n_buckets * 10):
        quarantined = t >= 40
        evs.append({
            'type': 'node_status', 'ts': float(t), 'seq': seq, 'nodes': {
                'srv1': {'trust': 0.9, 'quarantined': False, 'anomaly': 0.0},
                'srv2': {'trust': 0.2 if quarantined else 0.8,
                         'quarantined': quarantined, 'anomaly': 0.9 if quarantined else 0.0},
            }})
        seq += 1
        for k in range(4):
            evs.append({'type': 'route', 'ts': float(t), 'seq': seq,
                        'client_ip': '10.0.0.1', 'client_port': 1000 + t * 4 + k,
                        'chosen': 'srv1', 'decision_ms': 1.0, 'dpid': 2})
            seq += 1
            evs.append({'type': 'report', 'ts': float(t), 'seq': seq,
                        'device': 'iot1', 'node': 'srv1', 'status': 'success',
                        'latency_ms': 40.0, 'trust': 0.9})
            seq += 1
    evs.append({'type': 'quarantine', 'ts': 40.0, 'seq': seq, 'node': 'srv2',
                'trust': 0.2, 'anomaly': 0.9, 'isolation_threshold': 0.3,
                'anomaly_gate': 0.5})
    return evs


def _text(html: str) -> str:
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', html))


def _section(html: str, sid: str) -> str:
    m = re.search(rf'<section id="{sid}">(.*?)</section>', html, re.S)
    assert m, f'section {sid} missing'
    return m.group(1)


# --------------------------------------------------------------------------- #
class TestPageStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = _events()
        cls.html = B.build_from_events(cls.events, 'test.jsonl')

    def test_every_navigable_section_exists(self):
        for sid, _label in B._NAV:
            self.assertIn(f'id="{sid}"', self.html, f'section {sid} is in the nav but not the page')

    def test_the_page_is_self_contained(self):
        """No CDN, no external asset. It has to render over file:// on a
        projector with no wifi -- the same constraint index.html documents."""
        for pattern in ('http://', 'https://', '<script src', '<link ', '@import'):
            self.assertNotIn(pattern, self.html, f'external reference: {pattern}')

    def test_there_is_no_script_at_all(self):
        # The data is fixed at generation time; nothing needs to run.
        self.assertNotIn('<script', self.html)

    def test_it_declares_itself_generated(self):
        # So nobody hand-edits a file that the next build overwrites.
        self.assertIn('GENERATED FILE', self.html)
        self.assertIn('build_analysis_page', self.html)

    def test_it_links_back_to_the_live_dashboard(self):
        self.assertIn('href="/"', self.html)

    def test_no_chart_stretches_its_aspect_ratio(self):
        self.assertNotIn('preserveAspectRatio="none"', self.html)

    def test_no_gridline_is_dashed(self):
        self.assertNotIn('stroke-dasharray', self.html)

    def test_no_label_runs_past_its_viewbox(self):
        from evaluation.svg_charts import text_w
        for m in re.finditer(r'<svg viewBox="0 0 ([\d.]+) [\d.]+"(.*?)</svg>',
                             self.html, re.S):
            w, body = float(m.group(1)), m.group(2)
            for t in re.finditer(r'<text(?![^>]*text-anchor)[^>]*\bx="([\d.]+)"[^>]*>([^<]*)<', body):
                end = float(t.group(1)) + text_w(t.group(2))
                self.assertLessEqual(end, w + 0.5,
                                     f'label {t.group(2)!r} ends past the viewBox')


class TestNumbersMatchTheSourceTools(unittest.TestCase):
    """The page must agree with the tools it summarises.

    Every assertion here recomputes the figure with the source module and looks
    for it in the rendered page. A page that re-derived a metric for
    presentation would drift silently, which is the defect this whole design
    exists to avoid.
    """

    @classmethod
    def setUpClass(cls):
        cls.events = _events()
        cls.html = B.build_from_events(cls.events, 'test.jsonl')

    def test_nfr_verdicts_match_nfr_report(self):
        results = build_nfr_report(self.events)
        passed = sum(1 for r in results if r.passed)
        txt = _text(_section(self.html, 'nfr'))
        self.assertIn(f'{passed} of {len(results)}', txt)

    def test_classification_counts_match_attack_report(self):
        results = score_run(self.events)
        attacks = [r for r in results if r.truth != 'none']
        honest = [r for r in results if r.truth == 'none']
        exact = sum(1 for r in attacks if r.correct)
        family = sum(1 for r in attacks if r.family_correct)
        mislabelled = sum(1 for r in honest if r.predicted != 'none')
        txt = _text(_section(self.html, 'attacks'))
        self.assertIn(f'{exact}/{len(attacks)}', txt)
        self.assertIn(f'{family}/{len(attacks)}', txt)
        self.assertIn(f'{mislabelled}/{len(honest)}', txt)

    def test_availability_matches_availability_report(self):
        rep = compute_availability(self.events)
        txt = _text(_section(self.html, 'availability'))
        self.assertIn(f'{100 * rep.honest_availability:.2f}%', txt)

    def test_provenance_reports_the_real_event_count(self):
        self.assertIn(f'{len(self.events):,}', self.html)


class TestHonestEmptyStates(unittest.TestCase):
    """A block with no input says so and names the fix. It never vanishes, and
    it never shows a zero standing in for a missing measurement."""

    @classmethod
    def setUpClass(cls):
        cls.html = B.build_from_events(_events(), 'test.jsonl')   # no CSVs

    def test_comparison_blocks_render_an_empty_state(self):
        for sid in ('comparison', 'significance', 'ablation', 'scalability', 'optimizer'):
            body = _section(self.html, sid)
            self.assertIn('fig-empty', body, f'{sid} should be an empty state')

    def test_each_empty_state_names_the_command_that_fills_it(self):
        for sid, cmd in (('comparison', 'evaluation.baseline'),
                         ('scalability', 'evaluation.scalability_sweep'),
                         ('optimizer', 'rf_optimizer')):
            self.assertIn(cmd, _section(self.html, sid),
                          f'{sid} does not say how to generate its data')

    def test_an_empty_block_never_renders_a_zero(self):
        # "not generated" and "measured zero" are different claims.
        body = _text(_section(self.html, 'comparison'))
        self.assertNotIn('0.0000', body)


class TestComparisonSections(unittest.TestCase):
    ROWS = [
        {'strategy': st, 'scenario': 'sybil', 'seed': str(1000 + i),
         'offered': '100', 'completed': '90', 'failed': '10',
         'slo_violation_rate': f'{base + i * 0.001:.6f}',
         'failure_rate': '0.01', 'malicious_share': '0.02',
         'mean_latency_ms': '50', 'p95_latency_ms': '90', 'gini': '0.1',
         'time_to_isolate_s': '3.0'}
        for st, base in (('zt_sdn', 0.10), ('no_trust', 0.20),
                         ('random', 0.30), ('round_robin', 0.31),
                         ('least_conn', 0.40))
        for i in range(12)
    ]

    def setUp(self):
        self.html = B.build_from_events(_events(), 'test.jsonl',
                                        comparison_rows=self.ROWS)

    def test_the_system_under_test_is_highlighted_not_one_of_six_hues(self):
        """The emphasis form: one subject in colour, the rest in one gray."""
        from evaluation.svg_charts import DIM, S1
        body = _section(self.html, 'comparison')
        self.assertIn(f'fill="{S1}"', body)
        self.assertIn(f'fill="{DIM}"', body)

    def test_significance_reports_corrected_p_values(self):
        txt = _text(_section(self.html, 'significance'))
        self.assertIn('Holm', txt)
        self.assertIn('Wilcoxon', txt)

    def test_the_ablation_says_what_it_isolates(self):
        txt = _text(_section(self.html, 'ablation'))
        self.assertIn('no_trust', txt)
        self.assertIn('trust dimension', txt)

    def test_losses_section_exists_even_when_there_are_no_losses(self):
        # It still has to carry the measurement-trap notes.
        txt = _text(_section(self.html, 'losses'))
        self.assertIn('No comparison significantly favours a baseline', txt)

    def test_the_optimizer_arm_is_excluded_from_the_baseline_comparison(self):
        """zt_sdn_rf is a different question and would change the Holm family
        size if it were left in with the five headline routers."""
        rows = self.ROWS + [
            dict(r, strategy='zt_sdn_rf') for r in self.ROWS if r['strategy'] == 'zt_sdn'
        ]
        html = B.build_from_events(_events(), 'test.jsonl', comparison_rows=rows)
        table = _section(html, 'significance')
        self.assertNotIn('zt_sdn_rf', table)


class TestLossesAreAlwaysReported(unittest.TestCase):
    def test_a_baseline_that_wins_is_shown_as_a_loss(self):
        rows = []
        for i in range(12):
            # round_robin strictly better than the system on every seed.
            rows.append({'strategy': 'zt_sdn', 'scenario': 'clean', 'seed': str(1000 + i),
                         'offered': '100', 'completed': '99', 'failed': '1',
                         'slo_violation_rate': f'{0.20 + i * 0.001:.6f}',
                         'failure_rate': '0.01', 'malicious_share': '0.0',
                         'mean_latency_ms': '50', 'p95_latency_ms': '90',
                         'gini': '0.1', 'time_to_isolate_s': ''})
            rows.append({'strategy': 'round_robin', 'scenario': 'clean', 'seed': str(1000 + i),
                         'offered': '100', 'completed': '99', 'failed': '1',
                         'slo_violation_rate': f'{0.10 + i * 0.001:.6f}',
                         'failure_rate': '0.01', 'malicious_share': '0.0',
                         'mean_latency_ms': '50', 'p95_latency_ms': '90',
                         'gini': '0.1', 'time_to_isolate_s': ''})
        html = B.build_from_events(_events(), 'test.jsonl', comparison_rows=rows)
        txt = _text(_section(html, 'losses'))
        self.assertIn('round_robin', txt)
        self.assertIn('WORSE', _text(_section(html, 'significance')))


class TestAttackImpactWindow(unittest.TestCase):
    def test_a_zero_onset_attack_does_not_collapse_the_clean_window(self):
        """`bad_credentials` devices are refused at their first handshake, so
        their onset is a defaulted zero rather than a configured arming time.
        Letting it define the boundary leaves no clean window at all."""
        evs = _events()
        graph = evs[0]['graph']
        graph['nodes'].append({'id': 'iot9', 'kind': 'iot',
                               'attack': 'bad_credentials', 'attack_start_s': 0.0})
        html = B.build_from_events(evs, 'test.jsonl')
        txt = _text(_section(html, 'impact'))
        self.assertNotIn('no clean baseline window', txt)
        self.assertIn('30s', txt)          # the real timed onset

    def test_an_always_on_attack_is_named_as_contaminating_the_clean_window(self):
        evs = _events()
        evs[0]['graph']['nodes'].append(
            {'id': 'iot9', 'kind': 'iot', 'attack': 'bad_credentials', 'attack_start_s': 0.0})
        txt = _text(_section(B.build_from_events(evs, 'test.jsonl'), 'impact'))
        self.assertIn('iot9', txt)

    def test_a_startup_dominated_clean_window_is_flagged(self):
        """Comparing run start-up against steady-state-under-attack makes the
        attack look beneficial. Detected and warned about, never trimmed."""
        evs = _events()
        for n in evs[0]['graph']['nodes']:
            if n.get('attack') == 'sybil':
                n['attack_start_s'] = 10.0     # only one clean bucket
        txt = _text(_section(B.build_from_events(evs, 'test.jsonl'), 'impact'))
        self.assertIn('start-up', txt)

    def test_no_timed_attack_is_an_honest_empty_state(self):
        evs = _events()
        for n in evs[0]['graph']['nodes']:
            n.pop('attack', None)
        txt = _text(_section(B.build_from_events(evs, 'test.jsonl'), 'impact'))
        self.assertIn('no clean window', txt)


class TestRunHistory(unittest.TestCase):
    def test_summary_carries_the_false_quarantine_count(self):
        # The column that matters: this project has twice shipped a defect
        # whose only signature was honest nodes wrongly isolated.
        entry = B.run_summary(_events(), 'test.jsonl', 'unit')
        self.assertIn('honest_quarantined', entry)
        self.assertEqual(entry['honest_quarantined'], 0)
        self.assertEqual(entry['servers'], 2)

    def test_appending_the_same_label_replaces_rather_than_duplicates(self, ):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            orig = B.HISTORY_PATH
            try:
                B.HISTORY_PATH = Path(d) / 'run_history.json'
                B.append_history({'label': 'x', 'recorded': '2026-01-01', 'a': 1})
                B.append_history({'label': 'x', 'recorded': '2026-01-01', 'a': 2})
                hist = json.loads(B.HISTORY_PATH.read_text())
                self.assertEqual(len(hist), 1)
                self.assertEqual(hist[0]['a'], 2)
            finally:
                B.HISTORY_PATH = orig

    def test_history_section_renders_rows(self):
        hist = [
            {'label': 'run1', 'recorded': '2026-01-01', 'servers': 8, 'devices': 40,
             'span_s': 300, 'nfr_passed': 4, 'nfr_total': 4, 'attacks_exact': 6,
             'attacks_total': 8, 'attacks_family': 7, 'honest_mislabelled': 1,
             'honest_total': 40, 'honest_availability': 0.98,
             'honest_quarantined': 1, 'commit': 'abc'},
            {'label': 'run2', 'recorded': '2026-01-02', 'servers': 8, 'devices': 40,
             'span_s': 300, 'nfr_passed': 4, 'nfr_total': 4, 'attacks_exact': 8,
             'attacks_total': 8, 'attacks_family': 8, 'honest_mislabelled': 0,
             'honest_total': 40, 'honest_availability': 1.0,
             'honest_quarantined': 0, 'commit': 'def'},
        ]
        out = B.section_history(hist)
        self.assertIn('run1', out)
        self.assertIn('run2', out)
        # the run with a false quarantine is flagged
        self.assertIn('is-bad', out)


if __name__ == '__main__':
    unittest.main()
