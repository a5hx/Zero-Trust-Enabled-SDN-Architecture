"""The control arm's routing policy, pinned.

Two of these tests exist to protect claims the paper makes about the baseline
rather than to protect the code from crashing:

  * `test_static_map_is_exactly_uniform` -- the paper says this control is
    *a priori perfectly balanced*, so nothing it loses can be blamed on unfair
    static assignment. That sentence is only true while 40 devices over 8
    servers is exactly 5 each.

  * `test_bind_never_returns_none` -- the paper says the baseline cannot deny a
    request. `select_edge_node` returns None when every candidate is
    quarantined; this router has no such outcome, and that asymmetry is the
    mechanism behind the availability difference.
"""

import pytest

from base_model.static_router import (
    STRATEGY_RANDOM,
    STRATEGY_ROUND_ROBIN,
    STRATEGY_STATIC_NEAREST,
    StaticRouter,
    expected_static_map,
    iot_index,
    load_share,
)

N_EDGE = 8
N_IOT = 40


def _ip(j: int) -> str:
    return f'10.0.0.{j}'


# -- address parsing ------------------------------------------------------- #
@pytest.mark.parametrize('ip,expected', [
    ('10.0.0.1', 1), ('10.0.0.7', 7), ('10.0.0.40', 40),
    ('10.0.1.3', None),      # a server, not a device
    ('10.0.99.254', None),   # the cx routing node
    ('not-an-ip', None),
])
def test_iot_index(ip, expected):
    assert iot_index(ip) == expected


# -- static_nearest -------------------------------------------------------- #
def test_static_map_matches_the_topology_attachment_rule():
    """srv index must follow ZeroTrustTopo.build()'s `(j - 1) % n_edge`.

    If it did not, a client would be served across the core switch by a server
    that is not on its own edge switch -- which is a different (and better)
    policy than the one this arm claims to implement.
    """
    mapping = expected_static_map(N_IOT, N_EDGE)
    assert mapping['iot1'] == 'srv1'
    assert mapping['iot8'] == 'srv8'
    assert mapping['iot9'] == 'srv1'
    assert mapping['iot40'] == 'srv8'


def test_static_map_is_exactly_uniform():
    share = load_share(expected_static_map(N_IOT, N_EDGE), N_EDGE)
    assert set(share.values()) == {5}, (
        f'the static map is no longer uniform: {share}. The paper claims this '
        f'control is a priori perfectly balanced; if that stops being true the '
        f'claim must change, not this test.'
    )


def test_router_agrees_with_the_derived_map():
    """The router's live decisions must equal the map derived from config.

    Same discipline as `_publish_link_table`: check what was applied against
    what was specified, rather than assuming they agree.
    """
    router = StaticRouter(N_EDGE, STRATEGY_STATIC_NEAREST)
    expected = expected_static_map(N_IOT, N_EDGE)
    for j in range(1, N_IOT + 1):
        assert router.bind(_ip(j), 40000 + j) == expected[f'iot{j}']


def test_static_binding_is_stable_across_connections():
    """A client bound to a blackhole stays bound to it. This is the finding."""
    router = StaticRouter(N_EDGE, STRATEGY_STATIC_NEAREST)
    first = router.bind(_ip(6), 1000)
    for port in range(1001, 1100):
        assert router.bind(_ip(6), port) == first


def test_static_binding_ignores_everything_about_the_server():
    """There is no argument through which node state could reach the decision.

    `select_edge_node(states, weights, ...)` takes the whole fleet's trust,
    load, latency and anomaly. `bind(client_ip, client_port)` takes an address.
    The difference is the experiment.
    """
    import inspect
    params = list(inspect.signature(StaticRouter.bind).parameters)
    assert params == ['self', 'client_ip', 'client_port'], (
        f'StaticRouter.bind grew parameters {params} -- the control arm must '
        f'not be able to see node state'
    )


# -- the other two strategies ---------------------------------------------- #
def test_round_robin_cycles_the_whole_roster():
    router = StaticRouter(N_EDGE, STRATEGY_ROUND_ROBIN)
    got = [router.bind(_ip(1), p) for p in range(1000, 1000 + N_EDGE * 3)]
    assert got[:N_EDGE] == [f'srv{i}' for i in range(1, N_EDGE + 1)]
    assert got[N_EDGE:2 * N_EDGE] == got[:N_EDGE]


def test_round_robin_still_feeds_a_dead_server_its_full_share():
    """Naive balancing is not failover.

    This is why `round_robin` is offered as a second control: it separates
    "no load balancing" from "no failover". It still sends 1/n of everything to
    a black hole, forever.
    """
    router = StaticRouter(N_EDGE, STRATEGY_ROUND_ROBIN)
    picks = [router.bind(_ip(1), p) for p in range(2000, 2000 + 800)]
    assert picks.count('srv6') == 100


def test_random_is_reproducible_from_the_seed():
    a = StaticRouter(N_EDGE, STRATEGY_RANDOM, seed=7)
    b = StaticRouter(N_EDGE, STRATEGY_RANDOM, seed=7)
    assert [a.bind(_ip(1), p) for p in range(50)] == \
           [b.bind(_ip(1), p) for p in range(50)]


# -- invariants ------------------------------------------------------------ #
@pytest.mark.parametrize('strategy',
                         [STRATEGY_STATIC_NEAREST, STRATEGY_ROUND_ROBIN, STRATEGY_RANDOM])
def test_bind_never_returns_none(strategy):
    router = StaticRouter(N_EDGE, strategy)
    for j in range(1, N_IOT + 1):
        assert router.bind(_ip(j), 5000 + j) is not None


def test_unknown_source_is_bound_not_dropped():
    """An unfamiliar address must still be routed.

    Refusing one would be a decision, and the control arm makes none.
    """
    router = StaticRouter(N_EDGE, STRATEGY_STATIC_NEAREST)
    chosen = router.bind('10.0.99.254', 9999)
    assert chosen in {f'srv{i}' for i in range(1, N_EDGE + 1)}


def test_unknown_strategy_is_rejected_at_construction():
    with pytest.raises(ValueError, match='unknown baseline strategy'):
        StaticRouter(N_EDGE, 'p2c')


def test_load_share_reports_zeros():
    """A server nothing is bound to must appear as 0, not be absent."""
    share = load_share({'iot1': 'srv1'}, N_EDGE)
    assert len(share) == N_EDGE
    assert share['srv1'] == 1
    assert share['srv5'] == 0
