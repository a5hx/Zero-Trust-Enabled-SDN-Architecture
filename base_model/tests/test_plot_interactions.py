"""The interaction figures: what gets written, and what the CSVs promise.

Same discipline as `test_plot_load.py` -- synthetic recordings only, `tmp_path`
for everything written, and no test touches `data/base_events.jsonl` or
`data/events.jsonl`.

The load-bearing tests here are the two about denominators. The arms admitted
different numbers of clients (40 against 37, because three were refused), so
any figure that implies a client count has to state which one it means.
"""

import csv
import json

import pytest

pytest.importorskip('matplotlib')

from base_model.interactions import (  # noqa: E402
    AUDIT_FIELDS,
    CLIENT_FIELDS,
    MATRIX_FIELDS,
    SPEED_FIELDS,
    TIMELINE_FIELDS,
    TIME_FIELDS,
)
from base_model.plot_interactions import _n_clients, main  # noqa: E402
from base_model.tests.test_interactions import (  # noqa: E402
    _report,
    _route,
    _topology,
    _write,
)
from base_model.interactions import ARM_BASELINE, score_arm_interactions  # noqa: E402

AGGREGATE_STEMS = [
    'interaction_matrix', 'fan_out', 'binding_stability', 'client_timeline',
    'client_population',
    'outcome_by_server', 'latency_ecdf', 'decision_time', 'latency_over_time',
    'residence_vs_latency', 'speed_summary',
]
CSV_FILES = {
    'interaction_matrix.csv': MATRIX_FIELDS,
    'client_summary.csv': CLIENT_FIELDS,
    'interaction_time.csv': TIME_FIELDS,
    'speed_summary.csv': SPEED_FIELDS,
    'task_timeline.csv': TIMELINE_FIELDS,
    'pairing_audit.csv': AUDIT_FIELDS,
}


def _recording(path, devices, servers=('srv1', 'srv2', 'srv3'), n=6,
               attacks=None):
    """A small run: each device cycles through `servers`, reporting each time."""
    events = [_topology(attacks=attacks, devices=devices)]
    port = 40000
    for k in range(n):
        for device in devices:
            server = servers[k % len(servers)]
            port += 1
            events.append(_route(1.0 + k * 5.0, device, server, port=port))
            events.append(_report(1.2 + k * 5.0, device, server))
    return _write(path, events)


@pytest.fixture
def baseline(tmp_path):
    return _recording(tmp_path / 'base_events.jsonl',
                      {'iot1': 'none', 'iot2': 'none'}, servers=('srv1',))


@pytest.fixture
def treatment(tmp_path):
    return _recording(tmp_path / 'events.jsonl',
                      {'iot1': 'none', 'iot2': 'none', 'iot3': 'none'},
                      attacks={'srv3': 'sybil'})


def _run(tmp_path, baseline, treatment=None, extra=()):
    out = tmp_path / 'out'
    argv = ['--baseline', baseline, '--out-dir', str(out), *extra]
    if treatment:
        argv += ['--treatment', treatment]
    assert main(argv) == 0
    return out


# --------------------------------------------------------------------------- #
# Outputs
# --------------------------------------------------------------------------- #
def test_writes_every_figure_as_png_and_svg(tmp_path, baseline, treatment):
    out = _run(tmp_path, baseline, treatment)
    for stem in AGGREGATE_STEMS:
        assert (out / f'{stem}.png').exists(), stem
        assert (out / f'{stem}.svg').exists(), stem


def test_writes_a_panel_per_server(tmp_path, baseline, treatment):
    out = _run(tmp_path, baseline, treatment)
    for i in range(1, 9):
        assert (out / f'srv{i}_interaction.png').exists()


def test_no_svg_suppresses_every_svg(tmp_path, baseline, treatment):
    out = _run(tmp_path, baseline, treatment, extra=['--no-svg'])
    assert list(out.glob('*.png'))
    assert not list(out.glob('*.svg'))


def test_baseline_alone_still_renders(tmp_path, baseline):
    """The control arm has to be scoreable before the treatment run exists."""
    out = _run(tmp_path, baseline)
    for stem in AGGREGATE_STEMS:
        assert (out / f'{stem}.png').exists(), stem
    rows = list(csv.DictReader(open(out / 'pairing_audit.csv')))
    assert [r['arm'] for r in rows] == ['baseline']


def test_a_missing_recording_says_how_to_make_one(tmp_path, capsys):
    assert main(['--baseline', str(tmp_path / 'nope.jsonl'),
                 '--out-dir', str(tmp_path / 'out')]) == 2
    assert 'run_base' in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# CSV contracts
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize('name,fields', list(CSV_FILES.items()))
def test_csv_headers_match_the_documented_schema(tmp_path, baseline, treatment,
                                                 name, fields):
    out = _run(tmp_path, baseline, treatment, extra=['--no-svg'])
    with open(out / name) as f:
        assert next(csv.reader(f)) == list(fields)


def test_both_arms_appear_in_every_csv(tmp_path, baseline, treatment):
    out = _run(tmp_path, baseline, treatment, extra=['--no-svg'])
    for name in CSV_FILES:
        arms = {r['arm'] for r in csv.DictReader(open(out / name))}
        assert arms == {'baseline', 'zero_trust'}, name


def test_unmeasured_cells_are_empty_never_zero(tmp_path, baseline, treatment):
    """`reroutes` in the baseline is the canonical case.

    A reader scanning a column scores 0 as a measurement. The baseline has no
    re-steer mechanism at all, and that has to stay legible as an absence.
    """
    out = _run(tmp_path, baseline, treatment, extra=['--no-svg'])
    rows = {r['arm']: r for r in csv.DictReader(open(out / 'pairing_audit.csv'))}
    assert rows['baseline']['reroutes'] == ''
    assert rows['baseline']['reroutes'] != '0'


def test_a_refused_client_keeps_a_row_with_an_empty_share(tmp_path):
    denied = _recording(tmp_path / 'events.jsonl', {'iot1': 'none'})
    with open(denied, 'a') as f:
        f.write(json.dumps(_topology(devices={
            'iot1': 'none', 'iot39': 'bad_credentials'})) + '\n')
    out = _run(tmp_path, denied, extra=['--no-svg'])
    rows = {r['device']: r for r in csv.DictReader(open(out / 'client_summary.csv'))}
    assert 'iot39' in rows, 'a client refused at admission must not vanish'
    assert rows['iot39']['total_routes'] == '0'
    assert rows['iot39']['dominant_share'] == ''


# --------------------------------------------------------------------------- #
# Denominators
# --------------------------------------------------------------------------- #
def test_the_client_denominator_names_the_refusals(tmp_path):
    """`_n_clients` is what every subtitle implying a fleet size prints."""
    path = _recording(tmp_path / 'e.jsonl', {'iot1': 'none'})
    with open(path, 'a') as f:
        f.write(json.dumps(_topology(devices={
            'iot1': 'none', 'iot39': 'bad_credentials'})) + '\n')
    arm = score_arm_interactions(ARM_BASELINE, path)
    assert _n_clients(arm) == '1 of 2, 1 refused'


def test_the_denominator_is_plain_when_every_client_was_routed(tmp_path):
    path = _recording(tmp_path / 'e.jsonl', {'iot1': 'none', 'iot2': 'none'})
    arm = score_arm_interactions(ARM_BASELINE, path)
    assert _n_clients(arm) == '2'


def test_every_client_count_in_a_figure_goes_through_that_helper():
    """Source check, the idiom `test_plot_load.py` uses for a formatting rule.

    A hand-written "40 clients" in one subtitle is how the two arms' different
    admission outcomes stop being visible.
    """
    import inspect

    from base_model import plot_interactions

    src = inspect.getsource(plot_interactions)
    for fn in ('fig_interaction_matrix', 'fig_fan_out', 'fig_client_population'):
        body = src.split(f'def {fn}(')[1].split('\ndef ')[0]
        assert '_n_clients(' in body, f'{fn} implies a client count without stating it'


# --------------------------------------------------------------------------- #
# The per-task timeline
# --------------------------------------------------------------------------- #
def test_timeline_has_one_row_per_task_including_the_lost_ones(tmp_path):
    """Rows = completed tasks + abandoned dispatches, in time order.

    Abandoned rows are the ones a server-side view drops. Losing them would let
    a blackhole read as idle rather than as harmful.
    """
    from base_model.interactions import score_arm_interactions, timeline_rows
    from base_model.tests.test_interactions import _report, _route, _topology, _write

    path = _write(tmp_path / 'e.jsonl', [
        _topology(attacks={'srv6': 'drop'}),
        _route(1.0, 'iot1', 'srv2', port=1), _report(1.1, 'iot1', 'srv2'),
        _route(2.0, 'iot1', 'srv6', port=2),          # swallowed, never reported
        _route(3.0, 'iot1', 'srv2', port=3), _report(3.1, 'iot1', 'srv2'),
    ])
    arm = score_arm_interactions('zero_trust', path)
    rows = list(timeline_rows(arm))
    assert [r['node'] for r in rows] == ['srv2', 'srv6', 'srv2']
    assert [r['blamed_on'] for r in rows] == ['srv2', 'srv6', 'srv2']
    assert [r['status'] for r in rows] == ['success', 'abandoned', 'success']
    assert rows[1]['latency_ms'] is None      # never returned; no latency exists
    assert [r['t_s'] for r in rows] == sorted(r['t_s'] for r in rows)


def test_every_server_gets_a_distinct_colour():
    """Server identity is a colour channel here, so collisions are silent bugs."""
    from base_model.plot_interactions import SERVER_COLORS, _server_color
    assert len(set(SERVER_COLORS.values())) == len(SERVER_COLORS) == 8
    assert _server_color('srv3') == SERVER_COLORS['srv3']
    assert _server_color('srv99') in set(SERVER_COLORS.values())   # wraps, no raise
