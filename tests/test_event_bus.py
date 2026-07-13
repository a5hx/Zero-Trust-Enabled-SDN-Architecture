"""Tests for controller/event_bus.py.

The properties that actually matter here are the ones that protect the control
plane: publish() must not block on a stalled subscriber, and it must not raise.
Everything else (history, recording) is a convenience.
"""

import json
import queue
import threading
import time

import pytest

from controller.event_bus import EventBus, NullBus


@pytest.fixture
def bus(tmp_path):
    b = EventBus(record_path=str(tmp_path / 'events.jsonl'))
    yield b
    b.close()


def test_publish_adds_type_ts_and_monotonic_seq(bus):
    first = bus.publish('route', chosen='srv2')
    second = bus.publish('route', chosen='srv1')

    assert first['type'] == 'route'
    assert first['chosen'] == 'srv2'
    assert isinstance(first['ts'], float)
    assert second['seq'] == first['seq'] + 1


def test_subscriber_receives_published_events(bus):
    q = bus.subscribe()
    bus.publish('quarantine', node='srv3')

    event = q.get_nowait()
    assert event['type'] == 'quarantine'
    assert event['node'] == 'srv3'


def test_publish_does_not_block_when_subscriber_queue_is_full(tmp_path):
    """The core guarantee. A browser that stops reading must not be able to
    stall the OpenFlow event thread -- it loses events instead."""
    bus = EventBus(record_path=None, subscriber_maxsize=4)
    bus.subscribe()  # subscribed but never read from

    done = threading.Event()

    def publish_many():
        for i in range(1000):
            bus.publish('flow_install', i=i)
        done.set()

    threading.Thread(target=publish_many, daemon=True).start()

    assert done.wait(timeout=5.0), "publish() blocked on a full subscriber queue"


def test_full_subscriber_keeps_newest_events_not_oldest(tmp_path):
    """Drop-oldest, not drop-newest: a reconnecting dashboard should see what
    just happened, not stale events from the start of the run."""
    bus = EventBus(record_path=None, subscriber_maxsize=4)
    q = bus.subscribe()

    for i in range(10):
        bus.publish('flow_install', i=i)

    received = []
    while True:
        try:
            received.append(q.get_nowait()['i'])
        except queue.Empty:
            break

    assert len(received) <= 4
    assert 9 in received, f"newest event was dropped; got {received}"
    assert 0 not in received, f"oldest event was kept over newer ones; got {received}"


def test_multiple_subscribers_each_get_every_event(bus):
    a, b = bus.subscribe(), bus.subscribe()
    bus.publish('switch_up', dpid=1)

    assert a.get_nowait()['dpid'] == 1
    assert b.get_nowait()['dpid'] == 1


def test_unsubscribe_stops_delivery(bus):
    q = bus.subscribe()
    bus.unsubscribe(q)
    bus.publish('route', chosen='srv1')

    assert bus.subscriber_count == 0
    with pytest.raises(queue.Empty):
        q.get_nowait()


def test_history_backfills_a_late_subscriber(bus):
    bus.publish('switch_up', dpid=1)
    bus.publish('route', chosen='srv2')

    history = bus.history()
    assert [e['type'] for e in history] == ['switch_up', 'route']


def test_history_is_bounded(tmp_path):
    bus = EventBus(record_path=None, history_maxlen=5)
    for i in range(20):
        bus.publish('flow_install', i=i)

    history = bus.history()
    assert len(history) == 5
    assert [e['i'] for e in history] == [15, 16, 17, 18, 19]


def test_events_are_recorded_as_replayable_jsonl(tmp_path):
    path = tmp_path / 'events.jsonl'
    bus = EventBus(record_path=str(path))
    bus.publish('route', chosen='srv2', edge_score=0.81)
    bus.publish('quarantine', node='srv3')
    bus.close()

    lines = path.read_text().strip().split('\n')
    assert len(lines) == 2

    first = json.loads(lines[0])
    assert first['type'] == 'route'
    assert first['edge_score'] == 0.81
    assert json.loads(lines[1])['node'] == 'srv3'


def test_recording_is_optional(tmp_path):
    bus = EventBus(record_path=None)
    bus.publish('route', chosen='srv1')  # must not raise
    bus.close()


def test_concurrent_publishers_do_not_lose_or_duplicate_seq(tmp_path):
    """publish() is called from the OpenFlow thread, FlowMonitor's poll loop and
    the REST handler threads simultaneously -- seq must stay unique."""
    bus = EventBus(record_path=None)

    def publish_many():
        for _ in range(200):
            bus.publish('report', status='ok')

    threads = [threading.Thread(target=publish_many) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    seqs = [e['seq'] for e in bus.history()]
    assert len(seqs) == len(set(seqs)), "duplicate seq under concurrent publish"
    assert max(seqs) == 800


class TestNullBus:
    """When the dashboard is disabled the controller must behave exactly as it
    did before this feature existed."""

    def test_publish_is_inert(self):
        assert NullBus().publish('route', chosen='srv1') is None

    def test_subscriber_never_receives_anything(self):
        bus = NullBus()
        q = bus.subscribe()
        bus.publish('route', chosen='srv1')

        assert bus.subscriber_count == 0
        with pytest.raises(queue.Empty):
            q.get_nowait()

    def test_history_is_always_empty(self):
        bus = NullBus()
        bus.publish('route', chosen='srv1')
        assert bus.history() == []

    def test_interface_matches_eventbus(self):
        """If EventBus grows a method the call sites use, NullBus must have it
        too -- otherwise a dashboard-off run crashes where a dashboard-on run
        works, which is the worst possible failure mode for this design."""
        public = {n for n in dir(EventBus) if not n.startswith('_')}
        assert public <= {n for n in dir(NullBus) if not n.startswith('_')}
