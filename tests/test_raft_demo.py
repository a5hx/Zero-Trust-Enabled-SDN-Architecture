"""Tests for the pure-logic helpers in blockchain/raft_demo.py.

The actual multi-process, kill-the-leader scenario is run by hand
(`python3 -m blockchain.raft_demo`) rather than in the automated suite -- see
docs/RAFT.md for a recorded live run with real commit-latency numbers. What's
tested here is the address-book bookkeeping and the reporting helper, which
don't need real processes to exercise."""

from blockchain.raft_demo import NODE_IDS, _addresses, _peers_arg, report


def test_addresses_gives_every_node_a_distinct_raft_and_http_port() -> None:
    raft_peers, http_ports = _addresses()
    assert set(raft_peers) == set(NODE_IDS)
    assert set(http_ports) == set(NODE_IDS)
    assert len({addr for addr in raft_peers.values()}) == len(NODE_IDS)
    assert len(set(http_ports.values())) == len(NODE_IDS)
    # RAFT and HTTP ports must not collide with each other either.
    assert set(p for _, p in raft_peers.values()).isdisjoint(http_ports.values())


def test_peers_arg_round_trips_through_parse_peers() -> None:
    from blockchain.raft_replica import _parse_peers
    raft_peers, _ = _addresses()
    assert _parse_peers(_peers_arg(raft_peers)) == raft_peers


def test_report_handles_no_successful_commits(capsys) -> None:
    report("phase", [], attempted=5)
    out = capsys.readouterr().out
    assert '0/5' in out


def test_report_flags_nfr_pass_and_fail(capsys) -> None:
    report("fast", [10.0, 20.0, 30.0], attempted=3, nfr_ms=500.0)
    assert 'PASS' in capsys.readouterr().out

    report("slow", [10.0, 600.0], attempted=2, nfr_ms=500.0)
    assert 'FAIL' in capsys.readouterr().out
