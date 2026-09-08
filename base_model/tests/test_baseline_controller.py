"""The baseline controller: right shape, no enforcement.

Every test here writes its recording into `tmp_path`. Constructing the app
opens its record file in truncating mode, so a test that used the configured
path would destroy a real baseline run the moment the suite was run after it.
"""

import copy

import pytest

yaml = pytest.importorskip('yaml')
pytest.importorskip('os_ken')

from base_model.baseline_controller import BaselineControllerApp  # noqa: E402

BASELINE_CONFIG = 'base_model/config/params_base_full.yaml'


def _repo_path(relative: str) -> str:
    from pathlib import Path
    return str(Path(__file__).resolve().parents[2] / relative)


@pytest.fixture
def app(tmp_path, monkeypatch):
    with open(_repo_path(BASELINE_CONFIG)) as f:
        cfg = yaml.safe_load(f)
    cfg['controller']['dashboard']['record_path'] = str(tmp_path / 'events.jsonl')
    path = tmp_path / 'params.yaml'
    path.write_text(yaml.safe_dump(cfg, sort_keys=False))
    monkeypatch.setenv('ZTSDN_BASE_CONFIG', str(path))
    instance = BaselineControllerApp()
    yield instance
    instance.bus.close()


def _make_app(tmp_path, monkeypatch, mutate):
    with open(_repo_path(BASELINE_CONFIG)) as f:
        cfg = yaml.safe_load(f)
    cfg = copy.deepcopy(cfg)
    cfg['controller']['dashboard']['record_path'] = str(tmp_path / 'events.jsonl')
    mutate(cfg)
    path = tmp_path / 'params.yaml'
    path.write_text(yaml.safe_dump(cfg, sort_keys=False))
    monkeypatch.setenv('ZTSDN_BASE_CONFIG', str(path))
    return BaselineControllerApp()


# ---------------------------------------------------------------------- #
# Absences                                                               #
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize('name', [
    'PRIO_QUARANTINE_DROP', 'PRIO_PROBATION', 'PRIO_HEALTH_CHECK',
])
def test_enforcement_priorities_are_absent(name):
    """The three flow priorities that ARE the treatment arm's enforcement.

    Their absence is checked rather than assumed: a priority constant is the
    kind of thing that gets copied along with the file it was pasted from, and
    it would sit there looking harmless until something used it.
    """
    from controller.trust_balancer import TrustBalancerApp
    assert hasattr(TrustBalancerApp, name), (
        f'{name} is gone from the treatment arm -- this test is now checking '
        f'the absence of something that no longer exists anywhere'
    )
    assert not hasattr(BaselineControllerApp, name)


@pytest.mark.parametrize('name', [
    '_install_meters', '_meter_for_node', '_meter_id_for',
    '_on_trust_collapse', '_on_trust_recovered', '_redispatch_after_quarantine',
    '_check_flood', 'record_auth_denial',
])
def test_enforcement_methods_are_absent(name):
    from controller.trust_balancer import TrustBalancerApp
    assert hasattr(TrustBalancerApp, name)
    assert not hasattr(BaselineControllerApp, name)


def _published_event_types(cls) -> set:
    """Event type names this class can actually publish.

    Read from the AST rather than by string search: the source discusses the
    events it does NOT emit, and a substring match would trip on the prose.
    """
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(cls)))
    types = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == 'publish':
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                types.add(first.value)
    return types


@pytest.mark.parametrize('event_type', [
    'route_denied',   # nothing to deny on: there is no eligibility check
    'quarantine', 'recovered', 'reroute', 'flow_delete',
    'block', 'optimizer', 'flood', 'auth_denied', 'classification',
])
def test_enforcement_events_are_never_published(event_type):
    """A single such event would be scored as a mechanism this arm lacks.

    `route_denied` is the sharpest example: `evaluation/interval_report.py`
    reads it as offered-but-unserved load, in an arm where that concept does
    not exist.
    """
    assert event_type not in _published_event_types(BaselineControllerApp)


def test_the_events_this_arm_does_publish():
    """Pinned as a whole set, so a new event type has to be a deliberate act."""
    assert _published_event_types(BaselineControllerApp) == {
        'topology', 'topology_links', 'arm', 'switch_up',
        'route', 'flow_install', 'report', 'node_status', 'anomaly',
        'auth_admitted',
    }


# ---------------------------------------------------------------------- #
# Presences                                                              #
# ---------------------------------------------------------------------- #
def test_topology_graph_carries_both_tiers_of_ground_truth(app):
    graph = app.topology_graph()
    by_id = {n['id']: n for n in graph['nodes']}

    assert by_id['srv3']['attack'] == 'sybil'
    assert by_id['srv3']['attack_start_s'] == 20.0
    assert by_id['srv6']['attack'] == 'drop'
    assert by_id['srv1']['attack'] == 'grayhole'
    assert by_id['srv8']['attack'] == 'onoff'
    assert by_id['srv2']['attack'] == 'none'

    # The two device-side attacks -- without these, flood and spoof would have
    # no row in any confusion matrix and would vanish rather than be scored.
    assert by_id['iot37']['attack'] == 'flood'
    assert by_id['iot38']['attack'] == 'spoof'
    assert by_id['iot39']['attack'] == 'bad_credentials'
    assert by_id['iot40']['attack'] == 'bad_credentials'


def test_topology_graph_link_shape_matches_the_treatment_arm(app):
    """`{a, b, kind}`, not `{source, target}`.

    `topology_metrics.py`, `attack_report.py` and `dashboard/replay.py` all key
    on this. The wrong shape parses cleanly, yields an empty graph and reports
    a plausible-looking nothing.
    """
    graph = app.topology_graph()
    assert graph['links']
    for link in graph['links']:
        assert set(link) >= {'a', 'b', 'kind'}
    kinds = {link['kind'] for link in graph['links']}
    assert kinds == {'core_link', 'server_link', 'iot_link'}


def test_topology_graph_counts_match_the_config(app):
    graph = app.topology_graph()
    kinds = [n['kind'] for n in graph['nodes']]
    assert kinds.count('core_switch') == 1
    assert kinds.count('edge_switch') == 8
    assert kinds.count('server') == 8
    assert kinds.count('iot') == 40


def test_bound_to_is_emitted_only_for_the_static_strategy(tmp_path, monkeypatch):
    """Under a rotating strategy there is no fixed binding to write down."""
    static = _make_app(tmp_path, monkeypatch, lambda c: None)
    try:
        iot = [n for n in static.topology_graph()['nodes'] if n['kind'] == 'iot']
        assert all('bound_to' in n for n in iot)
        assert {n['id']: n['bound_to'] for n in iot}['iot9'] == 'srv1'
    finally:
        static.bus.close()

    def to_rr(cfg):
        cfg['baseline']['strategy'] = 'round_robin'

    rotating = _make_app(tmp_path, monkeypatch, to_rr)
    try:
        iot = [n for n in rotating.topology_graph()['nodes'] if n['kind'] == 'iot']
        assert all('bound_to' not in n for n in iot)
    finally:
        rotating.bus.close()


def test_no_edge_score_weights_are_published(app):
    """The treatment arm publishes w1/w2/w3 because it has an EdgeScore.

    Emitting nulls or zeros here would invite a reader to plot "the baseline's
    trust weight" against the treatment arm's. There is no such quantity.
    """
    graph = app.topology_graph()
    assert 'weights' not in graph
    assert graph['thresholds']['enforced'] is False
    assert graph['selection']['adaptive'] is False


# ---------------------------------------------------------------------- #
# Admission                                                              #
# ---------------------------------------------------------------------- #
def test_every_device_is_admitted(app):
    for device in ('iot1', 'iot39', 'iot40'):
        assert app.admit(device, f'10.0.0.{device[3:]}')


def test_a_spoof_is_admitted_and_recorded_as_a_mismatch(app):
    """iot38 authenticating as iot1 is admitted -- and the fact is written down.

    The recording, not the controller, is what makes the spoof findable later:
    nothing here compares the two addresses before issuing the token.
    """
    events = []
    app.bus.publish = lambda etype, **fields: events.append({'type': etype, **fields})

    app.admit('iot1', '10.0.0.1')       # the real iot1
    app.admit('iot1', '10.0.0.38')      # the spoofer

    admissions = [e for e in events if e['type'] == 'auth_admitted']
    assert len(admissions) == 2
    assert admissions[0]['source_matches_identity'] is True
    assert admissions[1]['source_matches_identity'] is False
    assert admissions[1]['expected_ip'] == '10.0.0.1'
    assert admissions[1]['source_ip'] == '10.0.0.38'
    assert admissions[1]['reclaimed_from'] == '10.0.0.1'
    assert admissions[1]['verified'] is False


def test_report_from_an_unknown_flow_is_not_charged(app):
    assert app.handle_client_report('10.0.0.1', 65000, 'iot1', 'timeout', 4000.0) is None


def test_report_carries_the_real_source_ip(app):
    """A spoofed device's traffic stays attributable to the host that sent it."""
    events = []
    app.bus.publish = lambda etype, **fields: events.append({'type': etype, **fields})

    app.observer.register_dispatch('10.0.0.38', 44444, 'srv6')
    app.handle_client_report('10.0.0.38', 44444, 'iot1', 'success', 42.0)

    report = next(e for e in events if e['type'] == 'report')
    assert report['device'] == 'iot1'        # what it claimed
    assert report['source_ip'] == '10.0.0.38'  # where it really came from
    assert report['node'] == 'srv6'


def test_pause_monitor_stops_polling(app):
    assert app._monitor_paused is False
    assert app.pause_monitor() is True
    assert app._monitor_paused is True


def test_link_params_are_keyed_for_graph_lookup(app):
    n = app.record_link_params([
        {'a': 'iot1', 'b': 's1', 'delay_ms': 7.0, 'bw_mbps': 10.0},
    ])
    assert n == 1
    link = next(
        lk for lk in app.topology_graph()['links']
        if {lk['a'], lk['b']} == {'iot1', 's1'}
    )
    assert link['delay_ms'] == 7.0
