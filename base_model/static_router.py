"""The control arm's routing policy: a fixed map, decided without evidence.

This is the file that makes the baseline a baseline. It is deliberately tiny,
deliberately pure, and deliberately unable to see anything — no trust, no load,
no latency, no liveness, no history. Compare its signature to
`controller/edge_selector.py::select_edge_node`, which takes the state of every
candidate node: the difference between the two arms is visible in the
*arguments*, before either function's body is read.

Three strategies, none adaptive.

`static_nearest` (default)
    iotJ is served by srv[((J - 1) mod n_edge) + 1].

    That is the same modulo `ZeroTrustTopo.build()` already uses to attach IoT
    hosts to edge switches, so each client is served by the server hanging off
    its own edge switch and its traffic never crosses the core. This is the
    conventional non-adaptive edge assignment: no measurement, no controller
    state, no feedback loop. It is what an edge network does when nobody has
    built a load balancer.

    It is also uniform BY CONSTRUCTION — 40 devices over 8 servers is exactly 5
    each, for the whole run, whatever happens. That is the point, and it is
    worth stating in the paper: this control is *a priori perfectly balanced*,
    so nothing it loses can be attributed to unfair static assignment. What it
    cannot do is notice that srv6 stopped answering, and the five devices bound
    to srv6 stay bound to srv6 until the run ends.

`round_robin`
    Rotate over the server list per new connection. Spreads each client's own
    traffic across the fleet, and is still blind to trust, load and liveness —
    a blackhole receives exactly its 1/n share of every client's tasks instead
    of all of five clients' tasks. Use this arm if a reviewer objects that
    `static_nearest` conflates "no load balancing" with "no failover"; it
    separates the two, because round_robin *is* naive load balancing.

`random`
    Uniform per connection from a seeded RNG. Included because it is the usual
    stateless-balancer strawman and costs nothing to support.

None of the three ever excludes a node. There is no eligibility check to
apply — that concept does not exist in this arm.
"""

import random as _random
import re
from typing import Optional

STRATEGY_STATIC_NEAREST = 'static_nearest'
STRATEGY_ROUND_ROBIN = 'round_robin'
STRATEGY_RANDOM = 'random'

STRATEGIES = (STRATEGY_STATIC_NEAREST, STRATEGY_ROUND_ROBIN, STRATEGY_RANDOM)

DEFAULT_STRATEGY = STRATEGY_STATIC_NEAREST

#: 10.0.0.J -> J. Matches simulation/addressing.py's iot_ip(); imported there
#: would be circular-ish and this is the only direction ever needed.
_IOT_IP_RE = re.compile(r'^10\.0\.0\.(\d+)$')


def iot_index(client_ip: str) -> Optional[int]:
    """'10.0.0.7' -> 7, or None if this is not an IoT host address.

    None is not an error. The VIP punt rule matches on destination, so anything
    that can open a TCP connection to the VIP lands here — including, in
    principle, the `cx` root-namespace node. Callers fall back to hashing.
    """
    m = _IOT_IP_RE.match(client_ip)
    return int(m.group(1)) if m else None


class StaticRouter:
    """Binds a connection to a server without consulting anything about it.

    Thread-safety: `round_robin`'s counter is incremented without a lock. The
    os-ken app runs its PacketIn handling on a single hub greenthread, so there
    is no concurrent caller in the live path; a torn counter would in any case
    only shift which server a connection got, which under a strategy that is
    already blind is not a correctness property.
    """

    def __init__(
        self,
        n_edge: int,
        strategy: str = DEFAULT_STRATEGY,
        seed: int = 1,
        rng: Optional[_random.Random] = None,
    ) -> None:
        if strategy not in STRATEGIES:
            raise ValueError(
                f"unknown baseline strategy {strategy!r}; expected one of {STRATEGIES}"
            )
        if n_edge < 1:
            raise ValueError(f"n_edge must be >= 1, got {n_edge}")
        self.n_edge = n_edge
        self.strategy = strategy
        self._rng = rng or _random.Random(seed)
        self._rr = 0
        # Every binding this router has handed out, so a run can report the map
        # it actually used rather than one re-derived from config afterwards.
        self._bindings: dict = {}

    def bind(self, client_ip: str, client_port: int = 0) -> str:
        """Return the server id for this connection. Never None.

        Contrast `select_edge_node`, which returns None when every candidate is
        quarantined — deny-by-default. This arm has no such outcome: there is
        nothing it could deny on, so a request is always routed somewhere, and
        "somewhere" includes a node that has been black-holing every task for
        four minutes.
        """
        if self.strategy == STRATEGY_STATIC_NEAREST:
            idx = iot_index(client_ip)
            if idx is None:
                # Not an IoT address. Hash it rather than dropping it: the
                # binding still has to be stable per client, and a control arm
                # that silently refuses unfamiliar sources would be making a
                # decision, which is the thing it must not do.
                idx = (hash(client_ip) & 0x7FFFFFFF) + 1
            node_index = ((idx - 1) % self.n_edge) + 1
        elif self.strategy == STRATEGY_ROUND_ROBIN:
            node_index = (self._rr % self.n_edge) + 1
            self._rr += 1
        else:  # STRATEGY_RANDOM
            node_index = self._rng.randint(1, self.n_edge)

        node_id = f'srv{node_index}'
        self._bindings.setdefault(client_ip, node_id)
        return node_id

    def binding_table(self) -> dict:
        """client_ip -> the server it was FIRST bound to.

        Under `static_nearest` this is the whole routing policy and is fixed for
        the run. Under the other two it records only the first binding, and the
        `route` events are the authority — recorded so a reader cannot mistake a
        rotating arm for a static one.
        """
        return dict(self._bindings)


def expected_static_map(n_iot: int, n_edge: int) -> dict:
    """The complete `static_nearest` map, derived from config alone.

    Exists so a run's actual bindings can be checked against the policy rather
    than assumed to follow it — the same discipline `_publish_link_table` uses
    for link parameters. `base_model/tests/test_static_router.py` uses it to
    assert the map is exactly uniform, which is the property the paper leans on.
    """
    return {
        f'iot{j}': f'srv{((j - 1) % n_edge) + 1}'
        for j in range(1, n_iot + 1)
    }


def load_share(mapping: dict, n_edge: int) -> dict:
    """server -> how many clients are bound to it. Zeros included.

    Zeros included on purpose: a server nothing is bound to must appear as 0,
    not be absent, or a fairness figure computed from this would quietly be
    taken over the wrong denominator.
    """
    share = {f'srv{i}': 0 for i in range(1, n_edge + 1)}
    for node_id in mapping.values():
        if node_id in share:
            share[node_id] += 1
    return share
