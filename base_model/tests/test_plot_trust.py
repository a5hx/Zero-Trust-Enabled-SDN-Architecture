"""The trust figures: right data, right axes, no fabricated points.

The visual result cannot be asserted here -- that needs a human looking at the
render, which is step 7 of the procedure and was done. What IS asserted is
everything a reader would have to take on faith otherwise: that the plotted
points are the recording's own, that the axis is fixed so two servers can be
compared, that the onset band comes from ground truth, and that the label
de-collision never moves a value to make room for its own annotation.
"""

import csv
import json

import pytest

matplotlib = pytest.importorskip('matplotlib')

# The palette, the axis treatment and the label de-collision live in
# base_model/figure_style.py -- one visual system across both figure families.
# Imported from there rather than from plot_trust so this file fails if the two
# ever grow separate copies.
from base_model.figure_style import (  # noqa: E402
    LABEL_MIN_GAP_FRAC,
    X_HEADROOM,
    resolve_label_collisions,
)
from base_model.plot_trust import _load_series, main  # noqa: E402

_LABEL_MIN_GAP = LABEL_MIN_GAP_FRAC          # trust's y range is 1.0
_resolve_label_collisions = resolve_label_collisions

SERVERS = [f'srv{i}' for i in range(1, 9)]
ATTACKS = {'srv3': 'sybil', 'srv6': 'drop'}
ONSETS = {'srv3': 20.0, 'srv6': 30.0}


def _recording(path, t0=1000.0, steps=60):
    graph_nodes = [{'id': 's0', 'kind': 'core_switch', 'dpid': 1}]
    for i in range(1, 9):
        graph_nodes.append({
            'id': f'srv{i}', 'kind': 'server', 'ip': f'10.0.1.{i}',
            'attack': ATTACKS.get(f'srv{i}', 'none'),
            'attack_start_s': ONSETS.get(f'srv{i}', 0.0),
        })
    events = [{'type': 'topology', 'ts': t0, 'graph': {'nodes': graph_nodes,
                                                       'links': []}}]
    for step in range(steps):
        events.append({
            'type': 'node_status', 'ts': t0 + step,
            'nodes': {
                n: {
                    'trust': 0.12 if (n == 'srv6' and step >= 30) else 0.80,
                    'anomaly': 0.0, 'quarantined': False,
                }
                for n in SERVERS
            },
        })
    with open(path, 'w') as f:
        for ev in events:
            f.write(json.dumps(ev) + '\n')
    return path


@pytest.fixture
def recording(tmp_path):
    return str(_recording(tmp_path / 'base_events.jsonl'))


# ---------------------------------------------------------------------- #
# The data behind the picture                                            #
# ---------------------------------------------------------------------- #
def test_series_are_the_recordings_own_points(recording):
    series, roles, onsets = _load_series(recording, 'baseline')
    assert set(series) == set(SERVERS)
    assert len(series['srv6']) == 60
    # First sample at t=0 -- anchored on the topology event, not on the first
    # node_status, so the onset band and the curve share one clock.
    assert series['srv6'][0][0] == pytest.approx(0.0)
    assert series['srv6'][0][1] == pytest.approx(0.80)
    assert series['srv6'][-1][1] == pytest.approx(0.12)


def test_ground_truth_comes_from_the_recording_not_the_plotter(recording):
    _, roles, onsets = _load_series(recording, 'baseline')
    assert roles['srv6'] == 'drop'
    assert onsets['srv6'] == 30.0
    assert roles['srv2'] == 'none'
    assert onsets['srv2'] == 0.0


def test_points_are_sorted_in_time(tmp_path):
    """The bus fans out from several threads; a later line can carry an earlier
    stamp, and an unsorted plot would zig-zag backwards."""
    path = tmp_path / 'out_of_order.jsonl'
    with open(path, 'w') as f:
        f.write(json.dumps({'type': 'topology', 'ts': 100.0,
                            'graph': {'nodes': [], 'links': []}}) + '\n')
        for ts in (105.0, 103.0, 104.0, 101.0):
            f.write(json.dumps({
                'type': 'node_status', 'ts': ts,
                'nodes': {'srv1': {'trust': ts / 1000.0}},
            }) + '\n')
    series, _, _ = _load_series(str(path), 'baseline')
    times = [p[0] for p in series['srv1']]
    assert times == sorted(times)


def test_a_recording_with_no_trust_samples_fails_loudly(tmp_path):
    """Silence must not render as an empty but plausible-looking chart."""
    path = tmp_path / 'empty.jsonl'
    path.write_text(json.dumps({'type': 'topology', 'ts': 1.0,
                                'graph': {'nodes': [], 'links': []}}) + '\n')
    with pytest.raises(SystemExit, match='no `node_status` events'):
        _load_series(str(path), 'baseline')


# ---------------------------------------------------------------------- #
# Label de-collision                                                     #
# ---------------------------------------------------------------------- #
def test_a_single_label_is_never_moved():
    assert _resolve_label_collisions([('baseline', 300.0, 0.42)]) == [
        ('baseline', 300.0, 0.42, 0.42)
    ]


def test_close_labels_are_pushed_apart():
    out = _resolve_label_collisions([
        ('baseline', 300.0, 0.211), ('zero_trust', 300.0, 0.223),
    ])
    labels = sorted(row[3] for row in out)
    assert labels[1] - labels[0] >= _LABEL_MIN_GAP - 1e-9


def test_de_collision_never_moves_the_value_it_states():
    """`y_end` is the number printed and the point the leader attaches to.

    Displacing a datum to make room for its own annotation would be the figure
    lying about where the line ended.
    """
    ends = [('baseline', 300.0, 0.211), ('zero_trust', 300.0, 0.223)]
    out = _resolve_label_collisions(ends)
    assert {(a, x, y) for a, x, y, _ in out} == set(ends)


def test_labels_stay_inside_the_axis():
    """A pair near the top is pushed down, not off the chart."""
    out = _resolve_label_collisions([
        ('baseline', 10.0, 0.99), ('zero_trust', 10.0, 0.995),
    ])
    assert all(0.0 <= row[3] <= 1.0 for row in out)


def test_far_apart_labels_are_left_alone():
    ends = [('baseline', 300.0, 0.10), ('zero_trust', 300.0, 0.90)]
    out = _resolve_label_collisions(ends)
    assert {(a, y, lab) for a, _, y, lab in out} == {
        ('baseline', 0.10, 0.10), ('zero_trust', 0.90, 0.90)
    }


# ---------------------------------------------------------------------- #
# The files                                                              #
# ---------------------------------------------------------------------- #
def test_writes_one_figure_per_server_plus_the_grid(recording, tmp_path):
    out = tmp_path / 'trust'
    assert main(['--baseline', recording, '--out-dir', str(out)]) == 0
    for node in SERVERS:
        assert (out / f'{node}_trust.png').stat().st_size > 0
        assert (out / f'{node}_trust.svg').stat().st_size > 0
    assert (out / 'all_servers_trust.png').stat().st_size > 0
    assert (out / 'trust_data.csv').exists()


def test_csv_is_the_table_view_of_exactly_what_was_plotted(recording, tmp_path):
    out = tmp_path / 'trust'
    main(['--baseline', recording, '--out-dir', str(out)])
    with open(out / 'trust_data.csv') as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 8 * 60
    srv6 = [r for r in rows if r['node'] == 'srv6']
    assert all(r['role'] == 'drop' for r in srv6)
    assert all(r['attack_start_s'] == '30' for r in srv6)
    assert float(srv6[-1]['trust']) == pytest.approx(0.12)
    assert {r['arm'] for r in rows} == {'baseline'}


def test_two_arms_produce_two_arms_of_rows(recording, tmp_path):
    treatment = str(_recording(tmp_path / 'events.jsonl'))
    out = tmp_path / 'trust'
    main(['--baseline', recording, '--treatment', treatment,
          '--out-dir', str(out)])
    with open(out / 'trust_data.csv') as f:
        rows = list(csv.DictReader(f))
    assert {r['arm'] for r in rows} == {'baseline', 'zero_trust'}


def test_ground_truth_mismatch_between_arms_is_reported(recording, tmp_path, capsys):
    """Two recordings that disagree on who attacked are not one experiment."""
    other = tmp_path / 'other.jsonl'
    global ONSETS
    saved = dict(ONSETS)
    try:
        ONSETS = {'srv3': 20.0, 'srv6': 99.0}
        _recording(other)
    finally:
        ONSETS = saved
    main(['--baseline', recording, '--treatment', str(other),
          '--out-dir', str(tmp_path / 'trust')])
    assert 'disagree on ground truth' in capsys.readouterr().out


def test_missing_recording_says_how_to_make_one(tmp_path, capsys):
    assert main(['--baseline', str(tmp_path / 'nope.jsonl')]) == 1
    assert 'run_base' in capsys.readouterr().out


def test_no_svg_flag(recording, tmp_path):
    out = tmp_path / 'trust'
    main(['--baseline', recording, '--out-dir', str(out), '--no-svg'])
    assert (out / 'srv1_trust.png').exists()
    assert not (out / 'srv1_trust.svg').exists()


# ---------------------------------------------------------------------- #
# Axis discipline                                                        #
# ---------------------------------------------------------------------- #
def test_y_axis_is_fixed_to_the_full_trust_range(recording, tmp_path):
    """Auto-scaling would make a flat honest node look like a rollercoaster and
    put it beside a blackhole's collapse at apparently the same amplitude."""
    import matplotlib.pyplot as plt

    out = tmp_path / 'trust'
    main(['--baseline', recording, '--out-dir', str(out)])
    # Rebuild one panel through the same styling path and read the limits back.
    from base_model.plot_trust import _style_axes
    fig, ax = plt.subplots()
    _style_axes(ax, 300.0, 'srv1')
    assert ax.get_ylim() == (0.0, 1.0)
    # x carries headroom for the end labels, and only headroom.
    assert ax.get_xlim() == (0.0, pytest.approx(300.0 * (1 + X_HEADROOM)))
    plt.close(fig)


# ---------------------------------------------------------------------- #
# Arm mislabelling                                                       #
# ---------------------------------------------------------------------- #
def test_enforcement_events_in_a_baseline_recording_warn(tmp_path, capsys):
    """A figure legended "baseline (no zero trust)" over a zero-trust curve is
    the worst thing this script could emit -- wrong in a paper, and undetectable
    downstream. The baseline arm cannot quarantine, so a quarantine event in a
    recording passed as --baseline is proof of a mix-up."""
    path = tmp_path / 'mislabelled.jsonl'
    _recording(path)
    with open(path, 'a') as f:
        f.write(json.dumps({'type': 'quarantine', 'ts': 1035.0,
                            'node': 'srv6', 'trust': 0.12}) + '\n')
    _load_series(str(path), 'baseline')
    assert 'enforcement event' in capsys.readouterr().out


def test_declared_arm_mismatch_warns(tmp_path, capsys):
    path = tmp_path / 'declared.jsonl'
    _recording(path)
    with open(path, 'a') as f:
        f.write(json.dumps({'type': 'arm', 'ts': 1000.1,
                            'arm': 'zero_trust'}) + '\n')
    _load_series(str(path), 'baseline')
    assert "declares arm='zero_trust'" in capsys.readouterr().out


def test_a_genuine_baseline_recording_warns_about_nothing(tmp_path, capsys):
    path = tmp_path / 'clean.jsonl'
    _recording(path)
    with open(path, 'a') as f:
        f.write(json.dumps({'type': 'arm', 'ts': 1000.1, 'arm': 'baseline',
                            'strategy': 'static_nearest'}) + '\n')
    _load_series(str(path), 'baseline')
    assert 'WARNING' not in capsys.readouterr().out
