"""Pub/sub event bus feeding the live dashboard (controller/../dashboard/).

Every visualised event -- a routing decision, a rule install, a quarantine --
originates on a thread that must not be slowed down to draw a picture. The
OpenFlow event thread in particular has a <200ms routing-decision NFR to hold,
and it services *every* switch: one blocked publish there stalls PacketIn
processing network-wide. So the rules here are:

    * publish() never blocks and never raises. A subscriber whose queue is full
      (a browser that stopped reading, a laptop that went to sleep) loses its
      oldest events -- it does not get to apply back-pressure to the control
      plane. Dropping pixels is always the right trade against dropping packets.
    * publish() does no network I/O and holds the lock only to append/fan out.

This mirrors the discipline documented at the top of controller/trust_state.py.

Every event is also appended to a JSONL file (data/events.jsonl by default), so
a run can be replayed into the dashboard later with no controller and no
Mininet -- see dashboard/replay.py. That write is done outside the lock.

NullBus is the no-op implementation used when the dashboard is disabled in
config: same interface, empty methods, so the publish call sites in
trust_balancer.py / flow_monitor.py need no `if enabled:` guard and the
controller's behaviour is bit-for-bit what it was before this file existed.
"""

import json
import logging
import queue
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger(__name__)

# Events retained for late-joining subscribers: a browser opened mid-run gets
# this much backfill so its topology/rules panels aren't empty until the next
# event happens to fire.
_HISTORY_MAXLEN = 500

# Event types pinned into every backfill regardless of age.
#
# `topology` is published exactly once, at run start, and it is the only
# carrier of the server roster and the ground-truth attack onsets. Three
# panels are built on it: the trust/topology map, the chart panel's shaded
# attack bands, and the cluster split's membership. At 500 events of history
# and ~20 events/sec it falls out of the window within half a minute, so
# without pinning, a browser opened even slightly into a run gets no roster at
# all -- and the failure is silent, because every panel simply renders empty
# rather than erroring.
_STICKY_TYPES = ('topology',)

# Per-subscriber queue depth. At ~20 events/sec (12 IoT clients at 1Hz plus
# flow-stats and node-status polls) this is several seconds of slack before a
# stalled reader starts losing events.
_SUBSCRIBER_MAXSIZE = 256


class EventBus:
    """Fan-out of controller events to any number of dashboard subscribers."""

    def __init__(
        self,
        record_path: Optional[str] = 'data/events.jsonl',
        history_maxlen: int = _HISTORY_MAXLEN,
        subscriber_maxsize: int = _SUBSCRIBER_MAXSIZE,
    ) -> None:
        self._lock = threading.Lock()
        self._history: Deque[Dict[str, Any]] = deque(maxlen=history_maxlen)
        self._sticky: Dict[str, Dict[str, Any]] = {}
        self._subscribers: List[queue.Queue] = []
        self._subscriber_maxsize = subscriber_maxsize
        self._seq = 0
        self._dropped = 0

        self._record_file = None
        if record_path:
            path = Path(record_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            # Line-buffered: a run that is killed with Ctrl-C (the normal way
            # this controller exits) still leaves a complete, replayable file
            # rather than losing the tail to an unflushed buffer.
            self._record_file = open(path, 'w', buffering=1)
            logger.info("EventBus recording to %s", path)

    def publish(self, event_type: str, **fields: Any) -> Dict[str, Any]:
        """Emit one event. Never blocks, never raises.

        Returns the event dict (with `seq`/`ts`/`type` added), mostly so tests
        and callers can assert on what was sent.
        """
        event = {'type': event_type, 'ts': time.time(), **fields}

        with self._lock:
            self._seq += 1
            event['seq'] = self._seq
            self._history.append(event)
            if event_type in _STICKY_TYPES:
                self._sticky[event_type] = event
            subscribers = list(self._subscribers)

        for q in subscribers:
            self._offer(q, event)

        self._record(event)
        return event

    def _offer(self, q: queue.Queue, event: Dict[str, Any]) -> None:
        """Non-blocking put, dropping this subscriber's oldest event to make
        room. A reader that has stopped consuming must never stall the caller."""
        try:
            q.put_nowait(event)
            return
        except queue.Full:
            pass

        try:
            q.get_nowait()  # discard oldest
        except queue.Empty:
            pass  # drained by its reader between our put and get -- fine

        try:
            q.put_nowait(event)
        except queue.Full:
            # Reader is wedged and another thread refilled it. Give up on this
            # event rather than spin: the control plane keeps moving.
            with self._lock:
                self._dropped += 1

    def _record(self, event: Dict[str, Any]) -> None:
        if self._record_file is None:
            return
        try:
            self._record_file.write(json.dumps(event) + '\n')
        except (OSError, ValueError):
            # Disk full, or file closed under us during shutdown. Recording is a
            # convenience for replay; losing it must not take down the demo.
            logger.warning("EventBus failed to record event", exc_info=True)

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=self._subscriber_maxsize)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def history(self) -> List[Dict[str, Any]]:
        """Backfill for a subscriber that connected mid-run.

        Sticky events are prepended when they have already aged out of the
        ring, and never duplicated when they are still in it. They go FIRST
        because everything after them refers to the roster they define -- a
        `route` naming srv6 is not interpretable before the topology that says
        what srv6 is.
        """
        with self._lock:
            hist = list(self._history)
            present = {e.get('seq') for e in hist}
            pinned = [e for e in self._sticky.values() if e.get('seq') not in present]
            pinned.sort(key=lambda e: e.get('seq', 0))
            return pinned + hist

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def close(self) -> None:
        if self._record_file is not None:
            self._record_file.close()
            self._record_file = None


class NullBus:
    """Inert bus used when the dashboard is disabled.

    Exists so the publish call sites elsewhere in the controller stay
    unconditional -- no `if self.bus:` guard at any of them, and no behaviour
    difference to reason about between dashboard-on and dashboard-off runs.
    """

    def publish(self, event_type: str, **fields: Any) -> None:
        return None

    def subscribe(self) -> queue.Queue:
        return queue.Queue()

    def unsubscribe(self, q: queue.Queue) -> None:
        return None

    def history(self) -> List[Dict[str, Any]]:
        return []

    @property
    def dropped(self) -> int:
        return 0

    @property
    def subscriber_count(self) -> int:
        return 0

    def close(self) -> None:
        return None
