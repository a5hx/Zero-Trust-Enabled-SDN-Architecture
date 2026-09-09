#!/usr/bin/env python3
"""Who talked to whom, what each server saw over time, and how fast it was.

The analysis core behind `base_model/plot_interactions.py`. No matplotlib here,
so the pairing rule below can be unit-tested in any environment -- the same
split `compare.py` already has against `plot_trust.py`/`plot_load.py`.

Three questions, from the recordings both arms already write:

  (a) STRUCTURE -- which client was served by which server, how many distinct
      servers each client ever reached, and how stable that binding was.
  (b) THE SERVER SIDE OVER TIME -- how many distinct clients each server was
      talking to per bucket, and how evenly it split its capacity between them.
  (c) SPEED -- end-to-end task latency (client-measured), controller decision
      time, and residence time (route -> report), each at p50/p95/p99.

WHY A PAIRING RULE IS NEEDED AT ALL
-----------------------------------
`report` events carry `device` and `node` but NOT `client_port`. The controller
knows the port -- `handle_client_report` resolves its dispatch with it -- but
never publishes it. So a report cannot be joined to its route by flow key, and
residence time needs a rule for deciding which route a report belongs to.

NAIVE PER-CLIENT FIFO IS WRONG, AND IT FAILS SILENTLY
-----------------------------------------------------
The obvious rule -- pop the client's oldest outstanding route -- mispairs 2,687
of the treatment arm's 6,454 reports (42%). One route that never gets a report
offsets that client's queue by one for the whole rest of the run, and every
later pairing inherits the error.

What makes it dangerous is that the BASELINE cannot show the bug. Under
`static_nearest` every outstanding route for a client names the same server, so
a wrong pairing still reports the right server: the same rule that is 42% wrong
on the treatment arm measures 0.3% wrong on the control. Trusting the control
arm's agreement would have shipped it.

The numbers it produces are not merely noisy, they are inverted -- naive FIFO
puts treatment residence p95 at 6,572 ms against the true 200 ms, which would
have read as the zero-trust arm being thirty times slower than it is.

THE RULE THIS MODULE USES
-------------------------
Match a report to the OLDEST outstanding route FOR THAT CLIENT WHOSE SERVER
EQUALS `report.node`. Routes skipped past in the search are recorded as
abandoned; when no server matches, fall back to FIFO and count the fallback.
Measured on the real recordings: 100% (baseline, 6,764 pairs) and 99.73%
(treatment, 6,353 of 6,370) of reports pair on an exact (client, server) match,
against 58% for naive FIFO on the treatment arm.

Four details that the rule is wrong without:

1. IDENTITY COMES FROM THE SOCKET, NOT THE CLAIM. The baseline admits a
   spoofer, so `device` is not a safe queue key there: `iot38` reports as
   `iot1`. Baseline reports carry `source_ip`; use it, and count the
   disagreement as contamination rather than believing either side. This is the
   same fact `compare.py::contaminated_identities` reports, keyed the same way,
   so the two tools agree about which host did what.

2. A REPEATED FLOW KEY IS THE SAME TASK. 145 baseline and 110 treatment route
   events repeat a `(client_ip, client_port)` that is still outstanding -- a TCP
   SYN re-signalled to the controller, not a second task. Appending them would
   invent tasks that never existed and then report them as abandoned.
   `TrustState.register_dispatch` treats a live re-registration the same way.

3. RE-STEERS MOVE THE TASK, NOT THE CLIENT. A `reroute` rewrites the pending
   entry's server, so the task is matched by where it actually landed. The
   client is never told, and its next connection is routed fresh.

4. FIFO IS EXACT ONLY WHEN ONE REQUEST IS IN FLIGHT. `simulation/iot_client.py`
   is strictly closed-loop -- `_send_task` -> `_report` -> `wait(interval_s)` --
   so every honest client has exactly one. The flood attacker is the exception:
   `--flood-concurrency 3` (pinned by `test_launcher_parity.py`) gives it up to
   three overlapping tasks, and pairing within its own queue may swap their
   residence times. Measured, the depth histogram tops out at exactly 3 and all
   1,544 deep pairings but one belong to that client, which is the launcher's
   configuration showing up in the data.

   That is a different fact from a pairing failure, so it gets a different
   field: `exact` says the join found a route to the right server,
   `sole_inflight` says nothing could have been swapped even in principle, and
   only `trustworthy` (both) is quoted in a percentile. Folding them together
   would report the flood client's concurrency as a 14% pairing-failure rate
   and hide the real one -- 0% and 0.27% -- underneath it.

WHAT IS DELIBERATELY NOT MEASURED HERE
--------------------------------------
`observed_load` and `claimed_cpu`. The baseline's current recording (2026-09-05)
integrated them over a 5 s window against the treatment arm's 3 s, so they are
not comparable across arms -- `plot_load.py` refuses to plot them for the same
reason and `README.md` §7 states it. Nothing in this module reads either field;
`test_interactions.py` pins that by inspecting the source.

Per-server request RATE and total load share are also absent, because
`plot_load.py` already plots them (`srvN_load`, `load_share`,
`fairness_over_time`). What is new here is the CLIENT dimension those figures
integrate away.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from base_model.compare import (
    GroundTruth,
    _read_ground_truth,
    _srv_sort_key,
    stream_events,
)
from evaluation.interval_report import DEFAULT_BUCKET_S, jain_fairness_index
from evaluation.nfr_report import _percentile
from simulation.addressing import iot_ip

ARM_BASELINE = 'baseline'
ARM_TREATMENT = 'zero_trust'

HONEST = 'none'

#: Client-side task timeout, both arms (`params_base_full.yaml:130`,
#: `params_trust_full.yaml:209`). A route older than this can no longer be
#: waiting on a task the client still cares about.
DEFAULT_TASK_TIMEOUT_S = 4.0

#: How long past `task_timeout_s` a route stays eligible to be paired before it
#: is swept as abandoned. Derived, never hardcoded, exactly as
#: `TrustState._dispatch_reap_after_s` derives its own: the client gives up at
#: `task_timeout_s`, then still has to POST its report, and that hop is bounded
#: by nothing the controller controls. A fixed value smaller than the real tail
#: reaps tasks that were about to be reported.
REAP_MARGIN = 1.5

#: Percentiles reported everywhere. p99 is new to this repo -- nothing else
#: reports past p95 -- and it is here because the finding this whole module
#: exists to surface lives in the tail: the baseline's blackhole-bound clients
#: are invisible at p50 and only fully resolved past p95.
PCTS = (50, 95, 99)


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Pairing:
    """One route matched to its report. `exact` False means read with care."""

    device: str
    client_ip: str
    client_port: Optional[int]
    routed_to: str                 # server after any re-steer -- where it landed
    served_by: str                 # what the report said; equal to routed_to when exact
    route_t_s: float
    report_t_s: float
    residence_ms: float            # controller-observed, minus any controller-side hold
    latency_ms: Optional[float]    # client-measured end-to-end
    decision_ms: Optional[float]
    status: str
    #: The pairing rule found a route to `node` -- the join is sound.
    exact: bool
    #: The controller declined to charge this outcome to `routed_to`, because
    #: the flow was re-steered onto it after the work had already been lost
    #: elsewhere. `blamed_on` names the server that actually lost it.
    inherited: bool
    resteered_from: Optional[str]
    #: This client had exactly one request in flight, so FIFO could not have
    #: swapped anything even in principle. Separate from `exact` on purpose:
    #: conflating them reports the flood client's concurrency as a pairing
    #: failure, and buries the real pairing-failure rate underneath it.
    sole_inflight: bool
    queue_depth: int               # outstanding routes for this client at pairing time

    @property
    def blamed_on(self) -> str:
        """The server responsible for this outcome.

        Normally where it ran. But a task re-steered off a quarantined node
        after that node had already swallowed it belongs to the node that
        swallowed it -- the survivor inherited a corpse. Charging the survivor
        is how an honest server acquires a blackhole's failures, which is
        exactly the misreading this whole tool exists to avoid.
        """
        if self.inherited and self.resteered_from:
            return self.resteered_from
        return self.routed_to

    @property
    def trustworthy(self) -> bool:
        """Safe to quote in a percentile.

        Inherited pairings are excluded: the task's life spans two servers, so
        its residence is not attributable to either one.
        """
        return self.exact and self.sole_inflight and not self.inherited


@dataclass(frozen=True)
class AbandonedRoute:
    """A dispatch with no report. Never dropped -- this is availability."""

    device: str
    client_ip: str
    client_port: Optional[int]
    node: str
    route_t_s: float
    reason: str                    # 'skipped' | 'aged_out' | 'open_at_end'


@dataclass
class ArmInteractions:
    """Everything one recording says about client<->server interaction."""

    name: str
    events_path: str
    bucket_s: float = DEFAULT_BUCKET_S
    task_timeout_s: float = DEFAULT_TASK_TIMEOUT_S
    truth: GroundTruth = field(default_factory=GroundTruth)
    duration_s: Optional[float] = None

    # (a) structure
    routed: Dict[Tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    resteered: Dict[Tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    first_server: Dict[str, str] = field(default_factory=dict)
    last_server: Dict[str, str] = field(default_factory=dict)
    switches: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # (b) server side over time
    bucket_clients: Dict[str, Dict[int, Dict[str, int]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(int))))
    bucket_active: Dict[int, Set[str]] = field(default_factory=lambda: defaultdict(set))
    n_buckets: int = 0

    # (c) speed
    pairings: List[Pairing] = field(default_factory=list)
    abandoned: List[AbandonedRoute] = field(default_factory=list)

    # audit
    routes_total: int = 0
    duplicate_routes: int = 0
    reports_total: int = 0
    fallback_pairs: int = 0
    orphan_reports: int = 0
    inherited_reports: int = 0
    unresolved_reports: int = 0
    contaminated_reports: int = 0
    admitted: Set[str] = field(default_factory=set)
    denied: Set[str] = field(default_factory=set)
    #: None, not 0, in an arm with no such mechanism -- see compare.py rule 1.
    reroutes: Optional[int] = None

    # -- populations -------------------------------------------------------- #
    @property
    def servers(self) -> List[str]:
        return sorted(self.truth.servers, key=_srv_sort_key)

    @property
    def devices(self) -> List[str]:
        return sorted(self.truth.devices, key=_srv_sort_key)

    @property
    def honest_devices(self) -> List[str]:
        return [d for d in self.devices
                if self.truth.devices.get(d) in (HONEST, '', None)]

    def device_of(self, client_ip: str) -> str:
        return self.truth.ip_device.get(client_ip, client_ip)

    def role_of_device(self, device: str) -> str:
        return self.truth.devices.get(device) or HONEST

    def role_of_server(self, node: str) -> str:
        return self.truth.servers.get(node) or HONEST


@dataclass
class _Pending:
    """A route awaiting its report."""

    route_t_s: float
    server: str
    client_port: Optional[int]
    decision_ms: Optional[float]


# --------------------------------------------------------------------------- #
# The streaming pass
# --------------------------------------------------------------------------- #
def score_arm_interactions(
    name: str,
    path: str,
    bucket_s: float = DEFAULT_BUCKET_S,
    task_timeout_s: float = DEFAULT_TASK_TIMEOUT_S,
) -> ArmInteractions:
    """One streaming pass over a recording. Bounded state, 130 MB+ safe.

    Processed in FILE ORDER, which is publish order: `event_bus.publish`
    assigns `seq` under a global lock, and both recordings check out with zero
    seq inversions on disk. Sorting by `ts` would mean holding the whole
    recording in memory to fix an ordering problem that does not exist.
    """
    arm = ArmInteractions(name=name, events_path=path, bucket_s=bucket_s,
                          task_timeout_s=task_timeout_s)
    reap_after = max(1.0, task_timeout_s * REAP_MARGIN)
    pending: Dict[str, List[_Pending]] = defaultdict(list)
    t0: Optional[float] = None
    t_last: Optional[float] = None

    def reap(client_ip: str, now: float) -> None:
        """Sweep this client's routes that can no longer be reported.

        Load-bearing for the BASELINE specifically. There, every outstanding
        route names the same server, so the skip-scan can never skip and would
        report zero abandonment however much of it there was. Age is the only
        evidence that arm can offer, so it has to be asked for explicitly.
        """
        q = pending[client_ip]
        if not q:
            return
        keep = []
        for p in q:
            if now - p.route_t_s > reap_after:
                arm.abandoned.append(AbandonedRoute(
                    device=arm.device_of(client_ip), client_ip=client_ip,
                    client_port=p.client_port, node=p.server,
                    route_t_s=p.route_t_s, reason='aged_out'))
            else:
                keep.append(p)
        pending[client_ip] = keep

    for ev in stream_events(path):
        etype = ev.get('type')
        ts = ev.get('ts')
        if ts is not None:
            ts = float(ts)
            if t0 is None:
                # The topology event, first in both arms -- the same anchor
                # compare.py and plot_load.py use, so every t_s here lines up
                # with the onset times those figures shade.
                t0 = ts
            t_last = ts if t_last is None else max(t_last, ts)
        t_s = (ts - t0) if (ts is not None and t0 is not None) else 0.0
        bucket = int(t_s // bucket_s)

        if etype == 'topology':
            _read_ground_truth(arm.truth, ev.get('graph') or {})

        elif etype == 'route':
            client_ip = ev.get('client_ip')
            server = ev.get('chosen')
            if not client_ip or not server:
                continue
            arm.routes_total += 1
            port = ev.get('client_port')
            reap(client_ip, t_s)

            # A repeat of a still-outstanding flow key is the SAME task
            # re-signalled (a retransmitted SYN), not a second one. Counted as
            # a routing decision -- it was one -- but never queued twice, or it
            # would surface later as an abandoned task that never existed.
            live = next((p for p in pending[client_ip] if p.client_port == port), None)
            if live is not None:
                arm.duplicate_routes += 1
            else:
                pending[client_ip].append(
                    _Pending(t_s, server, port, _as_float(ev.get('decision_ms'))))

            device = arm.device_of(client_ip)
            arm.routed[(client_ip, server)] += 1
            prev = arm.last_server.get(client_ip)
            if prev is None:
                arm.first_server[client_ip] = server
            elif prev != server:
                arm.switches[client_ip] += 1
            arm.last_server[client_ip] = server
            arm.bucket_clients[server][bucket][client_ip] += 1
            arm.bucket_active[bucket].add(client_ip)
            arm.n_buckets = max(arm.n_buckets, bucket + 1)
            del device

        elif etype == 'reroute':
            arm.reroutes = (arm.reroutes or 0) + 1
            client_ip = ev.get('client_ip')
            to_node = ev.get('to_node')
            from_node = ev.get('from_node')
            if client_ip and to_node:
                arm.resteered[(client_ip, to_node)] += 1
                for p in pending.get(client_ip, ()):
                    if p.client_port == ev.get('client_port') and p.server == from_node:
                        p.server = to_node
                        break

        elif etype == 'report':
            arm.reports_total += 1
            node = ev.get('node')
            client_ip = _resolve_client_ip(arm, ev)
            if client_ip is None:
                arm.unresolved_reports += 1
                continue
            reap(client_ip, t_s)
            q = pending[client_ip]
            depth = len(q)
            if not q:
                # A report with nothing outstanding. In the baseline this is the
                # admitted spoofer reporting for an identity it does not own.
                # Counted, never dropped, and never allowed to steal the
                # victim's pairing.
                arm.orphan_reports += 1
                continue

            idx = next((i for i, p in enumerate(q) if p.server == node), None)
            exact = idx is not None
            if idx is None:
                idx = 0
                arm.fallback_pairs += 1
            for p in q[:idx]:
                arm.abandoned.append(AbandonedRoute(
                    device=arm.device_of(client_ip), client_ip=client_ip,
                    client_port=p.client_port, node=p.server,
                    route_t_s=p.route_t_s, reason='skipped'))
            p = q[idx]
            del q[:idx + 1]

            # A controller-side hold is not the server's latency. Only the
            # treatment arm records one, and only on 20 of 6,454 reports.
            # The controller's own verdict, not re-derived here: it knows it
            # moved the flow and says so. `charged is False` is the signal --
            # `None` means an ordinary report, not "uncharged".
            inherited = ev.get('charged') is False or bool(ev.get('resteered_from'))
            if inherited:
                arm.inherited_reports += 1
            held_s = _as_float(ev.get('held_for_s')) or 0.0
            residence_ms = max(0.0, (t_s - p.route_t_s - held_s) * 1000.0)
            arm.pairings.append(Pairing(
                device=arm.device_of(client_ip), client_ip=client_ip,
                client_port=p.client_port, routed_to=p.server, served_by=node,
                route_t_s=p.route_t_s, report_t_s=t_s, residence_ms=residence_ms,
                latency_ms=_as_float(ev.get('latency_ms')),
                decision_ms=p.decision_ms, status=ev.get('status') or 'unknown',
                exact=exact, sole_inflight=depth == 1, queue_depth=depth,
                inherited=inherited, resteered_from=ev.get('resteered_from')))

        elif etype == 'auth_admitted':
            if ev.get('device_id'):
                arm.admitted.add(ev['device_id'])
        elif etype == 'auth_denied':
            subject = ev.get('device_id') or ev.get('client_ip')
            if subject:
                arm.denied.add(subject)

    for client_ip, q in pending.items():
        for p in q:
            arm.abandoned.append(AbandonedRoute(
                device=arm.device_of(client_ip), client_ip=client_ip,
                client_port=p.client_port, node=p.server,
                route_t_s=p.route_t_s, reason='open_at_end'))

    if t0 is not None and t_last is not None:
        arm.duration_s = t_last - t0
        arm.n_buckets = max(arm.n_buckets, int(arm.duration_s // bucket_s) + 1)
    return arm


def _as_float(value: Any) -> Optional[float]:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _resolve_client_ip(arm: ArmInteractions, ev: Dict[str, Any]) -> Optional[str]:
    """Which host actually sent this report -- the socket, never the claim.

    The baseline admits a spoofer, so `device` names an identity that may not
    belong to the sender. `source_ip` is the socket the controller read the
    report off and is the only field the sender cannot choose. When the two
    disagree, the disagreement is the finding (`compare.py` reports the same
    fact as a contaminated identity) and the socket wins.
    """
    source_ip = ev.get('source_ip')
    device = ev.get('device')
    claimed_ip = arm.truth.device_ip.get(device) if device else None
    if source_ip:
        if claimed_ip and claimed_ip != source_ip:
            arm.contaminated_reports += 1
        return source_ip
    if claimed_ip:
        return claimed_ip
    if isinstance(device, str) and device.startswith('iot') and device[3:].isdigit():
        return iot_ip(int(device[3:]))
    return None


# --------------------------------------------------------------------------- #
# Derived metrics
# --------------------------------------------------------------------------- #
def fan_out(arm: ArmInteractions) -> Dict[str, int]:
    """client_ip -> how many distinct servers it was ever routed to.

    1 for every client in a statically bound arm; that is the finding, not a
    degenerate case to special-case away.
    """
    out: Dict[str, int] = {}
    for ip in _client_ips(arm):
        out[ip] = len({s for (c, s) in arm.routed if c == ip})
    return out


def effective_fan_out(arm: ArmInteractions) -> Dict[str, int]:
    """As `fan_out`, plus servers reached only by a re-steer.

    A quarantine can move a flow to a server the selector never picked for that
    client. Counting only `route.chosen` would miss it.
    """
    out: Dict[str, int] = {}
    for ip in _client_ips(arm):
        seen = {s for (c, s) in arm.routed if c == ip}
        seen |= {s for (c, s) in arm.resteered if c == ip}
        out[ip] = len(seen)
    return out


def binding_stability(arm: ArmInteractions) -> Dict[str, Optional[float]]:
    """client_ip -> share of its routes that went to its single busiest server.

    1.0 means a static pin. `None` means the client was never routed, which is
    not the same as a client that was routed evenly -- the three treatment hosts
    refused at admission must not read as perfectly balanced.
    """
    out: Dict[str, Optional[float]] = {}
    for ip in _client_ips(arm):
        counts = [n for (c, s), n in arm.routed.items() if c == ip]
        total = sum(counts)
        out[ip] = (max(counts) / total) if total else None
    return out


def client_jain_per_server(arm: ArmInteractions) -> Dict[str, Optional[float]]:
    """server -> Jain across the request counts of the clients IT served.

    Distinct from `plot_load.py`'s fairness, which is across servers. This one
    asks whether a server split its capacity evenly between its own clients --
    the question a client asks, where the other is the question an operator
    asks.
    """
    out: Dict[str, Optional[float]] = {}
    for node in arm.servers:
        counts = [n for (c, s), n in arm.routed.items() if s == node]
        out[node] = jain_fairness_index(counts) if counts else None
    return out


def server_clients_per_bucket(arm: ArmInteractions, node: str) -> List[int]:
    """Distinct clients this server served, per bucket, zeros included."""
    per = arm.bucket_clients.get(node, {})
    return [len(per.get(i, ())) for i in range(arm.n_buckets)]


def active_clients_per_bucket(arm: ArmInteractions) -> List[int]:
    """The arm's own per-bucket denominator.

    Not 40, and not 37: the population that was actually sending in that
    bucket. Clients start staggered and the three refused hosts never join, so
    a fixed denominator would understate every early bucket.
    """
    return [len(arm.bucket_active.get(i, ())) for i in range(arm.n_buckets)]


def speed_stats(values: Sequence[float]) -> Dict[str, Optional[float]]:
    """p50/p95/p99 + n/mean/max. Every field `None` when there is no data.

    Never 0.0 for an unmeasured quantity -- `compare.py`'s first rule. A reader
    scanning a latency column scores 0 as *better*.
    """
    vals = [v for v in values if v is not None]
    if not vals:
        return {'n': 0, 'mean': None, 'max': None,
                **{f'p{p}': None for p in PCTS}}
    return {
        'n': len(vals),
        'mean': sum(vals) / len(vals),
        'max': max(vals),
        **{f'p{p}': _percentile(vals, p) for p in PCTS},
    }


#: The three speed metrics, and where each is measured. They answer different
#: questions and are never summed: `decision_ms` is the controller's own cost,
#: `latency_ms` is what the device experienced, and `residence_ms` spans both
#: plus flow install, transit and the client's report hop.
SPEED_METRICS = ('latency_ms', 'decision_ms', 'residence_ms')


def speed_samples(arm: ArmInteractions, metric: str, honest_only: bool = True,
                  exact_only: bool = True, node: Optional[str] = None,
                  successes_only: bool = False) -> List[float]:
    """Pull one speed metric out of the pairings, with the usual guards.

    `honest_only` excludes the flood attacker, whose 1,578 tasks against a
    typical client's ~135 would otherwise decide any pooled percentile on its
    own. `exact_only` excludes pairings whose queue was deeper than one, where
    residence may have been swapped within that client's own queue.
    """
    out = []
    for p in arm.pairings:
        if honest_only and arm.role_of_device(p.device) != HONEST:
            continue
        if exact_only and not p.trustworthy:
            continue
        if node is not None and p.routed_to != node:
            continue
        if successes_only and p.status != 'success':
            continue
        v = getattr(p, metric)
        if v is not None:
            out.append(v)
    return out


def outcome_counts(arm: ArmInteractions) -> Dict[str, Dict[str, int]]:
    """server -> {success, timeout, failure, abandoned}.

    `abandoned` sits alongside the reported statuses on purpose: a task that
    was dispatched and never came back is an outcome the client lived through,
    and leaving it out of the denominator is how a blackhole scores well.
    """
    out: Dict[str, Dict[str, int]] = {
        n: {'success': 0, 'timeout': 0, 'failure': 0, 'abandoned': 0}
        for n in arm.servers}
    for p in arm.pairings:
        row = out.setdefault(p.blamed_on, {'success': 0, 'timeout': 0,
                                           'failure': 0, 'abandoned': 0})
        row[p.status] = row.get(p.status, 0) + 1
    for a in arm.abandoned:
        row = out.setdefault(a.node, {'success': 0, 'timeout': 0,
                                      'failure': 0, 'abandoned': 0})
        row['abandoned'] += 1
    return out


def latency_residence_disagreement(arm: ArmInteractions) -> Dict[str, Optional[float]]:
    """Median (residence - latency), split by whether the pairing was exact.

    Reported, not resolved. Residence should run slightly LONGER than the
    client's own figure -- it spans the client's report hop, which `latency_ms`
    stops timing before -- so a small positive median is the expected result and
    a large or negative one means the pairing is not measuring what it claims.
    Splitting by exactness keeps the flood client's approximate pairings from
    being read as measurement error in everyone else's.
    """
    exact, approx = [], []
    for p in arm.pairings:
        if p.latency_ms is None:
            continue
        (exact if p.trustworthy else approx).append(p.residence_ms - p.latency_ms)
    return {
        'exact_median_ms': _median(exact),
        'approx_median_ms': _median(approx),
        'n_exact': len(exact),
        'n_approx': len(approx),
    }


def pairing_audit(arm: ArmInteractions) -> Dict[str, Any]:
    """The record that makes every residence number above auditable."""
    reasons = defaultdict(int)
    for a in arm.abandoned:
        reasons[a.reason] += 1
    matched = len(arm.pairings)
    exact = sum(1 for p in arm.pairings if p.exact)
    sole = sum(1 for p in arm.pairings if p.sole_inflight)
    return {
        'arm': arm.name,
        'routes': arm.routes_total,
        'duplicate_routes': arm.duplicate_routes,
        'reports': arm.reports_total,
        'pairs': matched,
        'exact_pairs': exact,
        'exact_share': (exact / matched) if matched else None,
        'sole_inflight_pairs': sole,
        'fallback_pairs': arm.fallback_pairs,
        'abandoned_skipped': reasons['skipped'],
        'abandoned_aged_out': reasons['aged_out'],
        'abandoned_open_at_end': reasons['open_at_end'],
        'orphan_reports': arm.orphan_reports,
        'resteer_inherited': arm.inherited_reports,
        'unresolved_reports': arm.unresolved_reports,
        'contaminated_reports': arm.contaminated_reports,
        'clients_in_topology': len(arm.truth.devices),
        'clients_routed': len({c for (c, _s) in arm.routed}),
        'clients_admitted': len(arm.admitted) or None,
        'clients_denied': len(arm.denied) or None,
        'reroutes': arm.reroutes,
    }


def _median(values: Sequence[float]) -> Optional[float]:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2.0


def _client_ips(arm: ArmInteractions) -> List[str]:
    """Every client the TOPOLOGY declares, routed or not.

    Driven from ground truth rather than from the routes actually seen, so a
    client that was refused at admission appears everywhere downstream with an
    explicit zero instead of vanishing from the figure -- which would quietly
    turn "we refused three hosts" into "there were only 37 hosts".
    """
    ips = [arm.truth.device_ip[d] for d in arm.devices if d in arm.truth.device_ip]
    seen = {c for (c, _s) in arm.routed}
    return sorted(set(ips) | seen,
                  key=lambda ip: _srv_sort_key(arm.device_of(ip)))


# --------------------------------------------------------------------------- #
# CSV rows (long format, matching load_data.csv's shape)
# --------------------------------------------------------------------------- #
MATRIX_FIELDS = ('arm', 'device', 'client_ip', 'client_role', 'node', 'server_role',
                 'attack_start_s', 'routes', 'resteers', 'pairs', 'successes',
                 'timeouts', 'failures', 'abandoned', 'mean_latency_ms',
                 'p95_latency_ms')

CLIENT_FIELDS = ('arm', 'device', 'client_ip', 'client_role', 'attack_start_s',
                 'total_routes', 'servers_routed', 'servers_effective',
                 'dominant_share', 'switches', 'first_server', 'last_server',
                 'abandoned', 'mean_latency_ms', 'p95_latency_ms')

TIME_FIELDS = ('arm', 'node', 'server_role', 'attack_start_s', 't_s', 'requests',
               'requests_per_s', 'distinct_clients', 'client_share', 'client_jain')

SPEED_FIELDS = ('arm', 'metric', 'scope', 'n', 'mean_ms', 'p50_ms', 'p95_ms',
                'p99_ms', 'max_ms')

TIMELINE_FIELDS = ('arm', 't_s', 'device', 'client_ip', 'client_role', 'node',
                   'blamed_on', 'server_role', 'status', 'latency_ms',
                   'resteered_from', 'exact')

AUDIT_FIELDS = tuple(pairing_audit(ArmInteractions('x', 'x')).keys())


def matrix_rows(arm: ArmInteractions) -> Iterator[Dict[str, Any]]:
    """One row per (client, server) pair that ever interacted."""
    per_pair: Dict[Tuple[str, str], List[Pairing]] = defaultdict(list)
    for p in arm.pairings:
        per_pair[(p.client_ip, p.routed_to)].append(p)
    aband: Dict[Tuple[str, str], int] = defaultdict(int)
    for a in arm.abandoned:
        aband[(a.client_ip, a.node)] += 1

    keys = set(arm.routed) | set(per_pair) | set(aband) | set(arm.resteered)
    for client_ip, node in sorted(
            keys, key=lambda k: (_srv_sort_key(arm.device_of(k[0])), _srv_sort_key(k[1]))):
        device = arm.device_of(client_ip)
        ps = per_pair.get((client_ip, node), [])
        lats = [p.latency_ms for p in ps if p.latency_ms is not None]
        stats = speed_stats(lats)
        yield {
            'arm': arm.name, 'device': device, 'client_ip': client_ip,
            'client_role': arm.role_of_device(device), 'node': node,
            'server_role': arm.role_of_server(node),
            'attack_start_s': arm.truth.server_onset.get(node),
            'routes': arm.routed.get((client_ip, node), 0),
            'resteers': arm.resteered.get((client_ip, node), 0),
            'pairs': len(ps),
            'successes': sum(1 for p in ps if p.status == 'success'),
            'timeouts': sum(1 for p in ps if p.status == 'timeout'),
            'failures': sum(1 for p in ps if p.status == 'failure'),
            'abandoned': aband.get((client_ip, node), 0),
            'mean_latency_ms': stats['mean'], 'p95_latency_ms': stats['p95'],
        }


def client_rows(arm: ArmInteractions) -> Iterator[Dict[str, Any]]:
    """One row per client the topology declares -- including never-routed ones."""
    fo, efo, stab = fan_out(arm), effective_fan_out(arm), binding_stability(arm)
    per_client: Dict[str, List[Pairing]] = defaultdict(list)
    for p in arm.pairings:
        per_client[p.client_ip].append(p)
    aband: Dict[str, int] = defaultdict(int)
    for a in arm.abandoned:
        aband[a.client_ip] += 1

    for ip in _client_ips(arm):
        device = arm.device_of(ip)
        ps = per_client.get(ip, [])
        stats = speed_stats([p.latency_ms for p in ps if p.latency_ms is not None])
        yield {
            'arm': arm.name, 'device': device, 'client_ip': ip,
            'client_role': arm.role_of_device(device),
            'attack_start_s': arm.truth.device_onset.get(device),
            'total_routes': sum(n for (c, _s), n in arm.routed.items() if c == ip),
            'servers_routed': fo.get(ip, 0),
            'servers_effective': efo.get(ip, 0),
            'dominant_share': stab.get(ip),
            'switches': arm.switches.get(ip, 0),
            'first_server': arm.first_server.get(ip),
            'last_server': arm.last_server.get(ip),
            'abandoned': aband.get(ip, 0),
            'mean_latency_ms': stats['mean'], 'p95_latency_ms': stats['p95'],
        }


def time_rows(arm: ArmInteractions) -> Iterator[Dict[str, Any]]:
    """One row per (server, bucket). Zeros included -- a quiet server is data."""
    jains = client_jain_per_server(arm)
    active = active_clients_per_bucket(arm)
    for node in arm.servers:
        per = arm.bucket_clients.get(node, {})
        for i in range(arm.n_buckets):
            clients = per.get(i, {})
            requests = sum(clients.values())
            denom = active[i] if i < len(active) else 0
            yield {
                'arm': arm.name, 'node': node,
                'server_role': arm.role_of_server(node),
                'attack_start_s': arm.truth.server_onset.get(node),
                't_s': i * arm.bucket_s,
                'requests': requests,
                'requests_per_s': requests / arm.bucket_s,
                'distinct_clients': len(clients),
                'client_share': (len(clients) / denom) if denom else None,
                'client_jain': (jain_fairness_index(list(clients.values()))
                                if clients else None),
            }


def timeline_rows(arm: ArmInteractions) -> Iterator[Dict[str, Any]]:
    """One row per TASK, in time order: who talked to which server, when.

    The long-format twin of `client_timeline.png`, and the most granular thing
    this module emits -- every other CSV here is an aggregate of these rows.

    Abandoned dispatches are included with `status='abandoned'` and no latency.
    They are the rows a server-side view loses: a task that was sent and never
    came back is still a client's task, and dropping it would let a blackhole
    look idle rather than harmful.
    """
    rows: List[Tuple[float, Dict[str, Any]]] = []
    for p in arm.pairings:
        rows.append((p.route_t_s, {
            'arm': arm.name, 't_s': round(p.route_t_s, 3), 'device': p.device,
            'client_ip': p.client_ip,
            'client_role': arm.role_of_device(p.device), 'node': p.routed_to,
            'blamed_on': p.blamed_on,
            'server_role': arm.role_of_server(p.blamed_on), 'status': p.status,
            'latency_ms': p.latency_ms, 'resteered_from': p.resteered_from,
            'exact': p.trustworthy,
        }))
    for a in arm.abandoned:
        rows.append((a.route_t_s, {
            'arm': arm.name, 't_s': round(a.route_t_s, 3), 'device': a.device,
            'client_ip': a.client_ip,
            'client_role': arm.role_of_device(a.device), 'node': a.node,
            'blamed_on': a.node,
            'server_role': arm.role_of_server(a.node), 'status': 'abandoned',
            'latency_ms': None, 'resteered_from': None, 'exact': False,
        }))
    rows.sort(key=lambda r: r[0])
    for _t, row in rows:
        yield row


def speed_rows(arm: ArmInteractions) -> Iterator[Dict[str, Any]]:
    """Percentile rows for every metric, over every scope worth quoting."""
    scopes: List[Tuple[str, Dict[str, Any]]] = [
        ('honest', {'honest_only': True}),
        ('attacker', {'honest_only': False, 'exact_only': False}),
        ('all', {'honest_only': False}),
    ]
    for metric in SPEED_METRICS:
        for scope, kwargs in scopes:
            if scope == 'attacker':
                vals = [getattr(p, metric) for p in arm.pairings
                        if arm.role_of_device(p.device) != HONEST
                        and getattr(p, metric) is not None]
            else:
                vals = speed_samples(arm, metric, **kwargs)
            yield _speed_row(arm, metric, scope, vals)
        for node in arm.servers:
            yield _speed_row(arm, metric, node,
                             speed_samples(arm, metric, node=node))


def _speed_row(arm: ArmInteractions, metric: str, scope: str,
               vals: Sequence[float]) -> Dict[str, Any]:
    s = speed_stats(vals)
    return {
        'arm': arm.name, 'metric': metric, 'scope': scope, 'n': s['n'],
        'mean_ms': s['mean'], 'p50_ms': s['p50'], 'p95_ms': s['p95'],
        'p99_ms': s['p99'], 'max_ms': s['max'],
    }
