"""The load figures, and the fairness trap they exist to avoid.

The central test here is `test_whole_roster_jain_hides_the_difference`. It
encodes the thing that would otherwise reach the paper as a wrong claim:
Jain over all eight servers is nearly identical in the two arms (0.622 vs
0.627 measured), for **opposite** reasons — the baseline failed to spread a
flood, the treatment arm deliberately withheld traffic from attackers. Any
change that makes this tool report a single whole-roster index should fail.
"""

import csv
import json

import pytest

pytest.importorskip('matplotlib')

from base_model.figure_style import jain  # noqa: E402
from base_model.plot_load import _fairness_series, _load_routes, _rate_series, main  # noqa: E402

SERVERS = [f'srv{i}' for i in range(1, 9)]
ATTACKS = {'srv1': 'grayhole', 'srv3': 'sybil', 'srv6': 'drop', 'srv8': 'onoff'}
ONSETS = {'srv1': 40.0, 'srv3': 20.0, 'srv6': 30.0, 'srv8': 50.0}
HONEST = ['srv2', 'srv4', 'srv5', 'srv7']


def _recording(path, per_bucket, t0=1000.0, n_buckets=6, bucket_s=10.0):
    """`per_bucket` maps server -> routes emitted in every bucket."""
    nodes = [{'id': 's0', 'kind': 'core_switch', 'dpid': 1}]
    for i in range(1, 9):
        nodes.append({
            'id': f'srv{i}', 'kind': 'server', 'ip': f'10.0.1.{i}',
            'attack': ATTACKS.get(f'srv{i}', 'none'),
            'attack_start_s': ONSETS.get(f'srv{i}', 0.0),
        })
    events = [{'type': 'topology', 'ts': t0, 'graph': {'nodes': nodes, 'links': []}}]
    for b in range(n_buckets):
        for node, count in per_bucket.items():
            for k in range(count):
                events.append({
                    'type': 'route', 'ts': t0 + b * bucket_s + k * 0.01,
                    'client_ip': '10.0.0.1', 'client_port': 40000 + k,
                    'chosen': node,
                })
    with open(path, 'w') as f:
        for ev in events:
            f.write(json.dumps(ev) + '\n')
    return str(path)


@pytest.fixture
def baseline(tmp_path):
    """Uniform-ish, except a flood pinned to the honest srv5 and attackers
    still receiving their full static share."""
    return _recording(tmp_path / 'base_events.jsonl',
                      {n: 10 for n in SERVERS} | {'srv5': 40})


@pytest.fixture
def treatment(tmp_path):
    """Attackers starved on purpose; the honest four carry the load evenly."""
    return _recording(tmp_path / 'events.jsonl',
                      {n: 2 for n in ATTACKS} | {n: 25 for n in HONEST})


# ---------------------------------------------------------------------- #
# The trap                                                               #
# ---------------------------------------------------------------------- #
def test_whole_roster_jain_hides_the_difference(baseline, treatment):
    """Two arms, near-identical whole-roster Jain, opposite causes.

    If this test's two `jain(all)` values ever drift far apart, the fixture has
    stopped reproducing the situation the two-population reporting exists for --
    fix the fixture, do not delete the test.
    """
    b, _, _, _ = _load_routes(baseline, 10.0)
    t, _, _, _ = _load_routes(treatment, 10.0)
    b_all = [sum(b.get(n, {}).values()) for n in SERVERS]
    t_all = [sum(t.get(n, {}).values()) for n in SERVERS]

    # Whole-roster: the arms look the same...
    assert abs(jain(b_all) - jain(t_all)) < 0.12

    # ...and on the population a load balancer is responsible for, they do not.
    b_hon = [sum(b.get(n, {}).values()) for n in HONEST]
    t_hon = [sum(t.get(n, {}).values()) for n in HONEST]
    assert jain(t_hon) > jain(b_hon) + 0.2
    assert jain(t_hon) == pytest.approx(1.0)


def test_share_reaching_attackers_separates_the_arms(baseline, treatment):
    b, _, _, _ = _load_routes(baseline, 10.0)
    t, _, _, _ = _load_routes(treatment, 10.0)

    def atk_share(arm):
        total = sum(sum(v.values()) for v in arm.values())
        return sum(sum(arm.get(n, {}).values()) for n in ATTACKS) / total

    assert atk_share(b) > atk_share(t) * 2


# ---------------------------------------------------------------------- #
# The data behind the picture                                            #
# ---------------------------------------------------------------------- #
def test_routes_are_bucketed_at_the_interval_report_width(baseline):
    """Same bucket width as evaluation/interval_report.py, so a number read off
    a figure can be checked against that report rather than merely resembling it."""
    from evaluation.interval_report import DEFAULT_BUCKET_S
    from base_model.plot_load import main as _m  # noqa: F401
    import inspect
    import base_model.plot_load as mod
    assert inspect.signature(mod.main).parameters  # smoke
    src = inspect.getsource(mod)
    assert 'DEFAULT_BUCKET_S' in src
    assert DEFAULT_BUCKET_S == 10.0


def test_empty_buckets_are_plotted_as_zero_not_dropped():
    """A bucket where a server received nothing is the signal, not missing data.

    Dropping it would draw a line straight across a starvation gap -- which is
    precisely the interval this comparison is about.
    """
    xs, ys = _rate_series({0: 5, 2: 5}, n_buckets=4, bucket_s=10.0)
    assert xs == [0.0, 10.0, 20.0, 30.0]
    assert ys == [0.5, 0.0, 0.5, 0.0]


def test_a_bucket_with_no_traffic_at_all_is_nan_not_a_fairness_claim():
    """Jain over an all-zero bucket is undefined; reporting 1.0 there would
    claim perfect fairness during an outage."""
    series = _fairness_series({'srv1': {0: 5}, 'srv2': {0: 5}},
                              ['srv1', 'srv2'], n_buckets=2)
    assert series[0] == pytest.approx(1.0)
    assert series[1] != series[1]        # NaN


def test_ground_truth_comes_from_the_recording(baseline):
    _, roles, onsets, t_end = _load_routes(baseline, 10.0)
    assert roles['srv6'] == 'drop'
    assert onsets['srv6'] == 30.0
    assert roles['srv2'] == 'none'
    assert t_end > 0


def test_a_recording_with_no_routes_fails_loudly(tmp_path):
    path = tmp_path / 'empty.jsonl'
    path.write_text(json.dumps({'type': 'topology', 'ts': 1.0,
                                'graph': {'nodes': [], 'links': []}}) + '\n')
    with pytest.raises(SystemExit, match='no `route` events'):
        _load_routes(str(path), 10.0)


# ---------------------------------------------------------------------- #
# The files                                                              #
# ---------------------------------------------------------------------- #
def test_writes_the_full_figure_set(baseline, treatment, tmp_path):
    out = tmp_path / 'load'
    assert main(['--baseline', baseline, '--treatment', treatment,
                 '--out-dir', str(out)]) == 0
    for node in SERVERS:
        assert (out / f'{node}_load.png').stat().st_size > 0
        assert (out / f'{node}_load.svg').stat().st_size > 0
    for extra in ('all_servers_load', 'load_share', 'fairness_over_time'):
        assert (out / f'{extra}.png').stat().st_size > 0
    assert (out / 'load_data.csv').exists()


def test_csv_carries_both_arms_and_the_role(baseline, treatment, tmp_path):
    out = tmp_path / 'load'
    main(['--baseline', baseline, '--treatment', treatment, '--out-dir', str(out)])
    with open(out / 'load_data.csv') as f:
        rows = list(csv.DictReader(f))
    assert {r['arm'] for r in rows} == {'baseline', 'zero_trust'}
    srv6 = [r for r in rows if r['node'] == 'srv6' and r['arm'] == 'baseline']
    assert all(r['role'] == 'drop' for r in srv6)
    assert all(r['attack_start_s'] == '30' for r in srv6)
    # requests_per_s must be the count over the bucket width, not the raw count.
    for r in rows:
        assert float(r['requests_per_s']) == pytest.approx(int(r['requests']) / 10.0)


def test_missing_recording_says_how_to_make_one(tmp_path, capsys):
    assert main(['--baseline', str(tmp_path / 'nope.jsonl')]) == 1
    assert 'run_base' in capsys.readouterr().out


def test_baseline_alone_still_renders(baseline, tmp_path):
    out = tmp_path / 'load'
    assert main(['--baseline', baseline, '--out-dir', str(out)]) == 0
    assert (out / 'load_share.png').exists()


# ---------------------------------------------------------------------- #
# The partial final bucket                                               #
# ---------------------------------------------------------------------- #
def test_the_partial_tail_is_identified_not_trimmed():
    """A run does not end on a bucket boundary, and the agents die first.

    Measured 2026-09-05: the zero-trust arm's final bucket held 47 requests over
    1.9 s against ~232 over 10 s for its neighbours. A rate computed from that
    is teardown noise -- and the figure had a bold direct label sitting on it,
    which was read as the run's headline. The tail is still DRAWN (never trim
    inconvenient tail data); it is drawn dashed, and the labels move back.
    """
    from base_model.plot_load import complete_buckets
    assert complete_buckets(305.7, 10.0) == 30    # 0..29 full, 30 is partial
    assert complete_buckets(311.9, 10.0) == 31
    assert complete_buckets(300.0, 10.0) == 30    # exact boundary: all full
    # Never zero, however short the run -- a one-bucket run still has a line.
    assert complete_buckets(4.0, 10.0) == 1


def test_direct_labels_attach_to_the_last_complete_bucket(baseline, treatment, tmp_path):
    """The end label must state a value computed over a full bucket."""
    import matplotlib.pyplot as plt
    from base_model.plot_load import _plot_with_partial_tail

    fig, ax = plt.subplots()
    xs = [0.0, 10.0, 20.0, 30.0]
    ys = [1.0, 1.0, 1.0, 0.2]          # the 0.2 is the teardown bucket
    x_lab, y_lab = _plot_with_partial_tail(ax, xs, ys, n_complete=3,
                                           color='#2a78d6')
    assert (x_lab, y_lab) == (20.0, 1.0)
    # ...and the tail is still on the chart, as a second dashed line.
    assert len(ax.lines) == 2
    assert ax.lines[1].get_linestyle() != '-'
    plt.close(fig)
