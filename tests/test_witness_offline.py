"""evaluation/witness_offline.py -- Phase 2a, the switch as a witness."""

import json

from evaluation.witness_offline import load_run, summarise_run

VIP = '10.0.99.1'


def _rule(node, idx, client, port, fwd, packets, nbytes, dpid=3, prio=300):
    m = (f'eth_type=2048,ip_proto=6,ipv4_dst={VIP},ipv4_src={client},tcp_dst=9000,tcp_src={port}'
         if fwd else
         f'eth_type=2048,ip_proto=6,ipv4_dst={client},ipv4_src=10.0.1.{idx},tcp_dst={port},tcp_src=8000')
    return {'dpid': dpid, 'table': 0, 'priority': prio, 'cookie': 0x5A00000000000000 | idx,
            'node': node, 'match': m, 'packets': packets, 'bytes': nbytes, 'is_vip': True}


def _write(path):
    evs = [{'type': 'topology', 'ts': 100.0, 'vip': f'{VIP}:9000', 'graph': {'nodes': [
        {'kind': 'server', 'id': 'srv1', 'attack': 'none'},
        {'kind': 'server', 'id': 'srv2', 'attack': 'drop', 'attack_start_s': 0.0}]}}]
    # Two polls: counters grow, the scorer keeps the maximum.
    for ts, scale in ((101.0, 0.5), (102.0, 1.0)):
        evs.append({'type': 'flow_stats', 'ts': ts, 'dpid': 3, 'rules': [
            _rule('srv1', 1, '10.0.0.5', '40001', True, int(6 * scale), int(548 * scale)),
            _rule('srv1', 1, '10.0.0.5', '40001', False, int(6 * scale), int(598 * scale)),
            _rule('srv2', 2, '10.0.0.6', '40002', True, int(4 * scale), int(296 * scale)),
            _rule('srv2', 2, '10.0.0.6', '40002', False, 0, 0),
            # A connection the client gave up on: the FIN's ACK comes back, no response.
            _rule('srv2', 2, '10.0.0.7', '40003', True, 7, 400),
            _rule('srv2', 2, '10.0.0.7', '40003', False, 2, 132),
        ]})
    evs.append({'type': 'report', 'ts': 102.5, 'node': 'srv1', 'status': 'success', 'device': 'iot5'})
    evs.append({'type': 'report', 'ts': 105.0, 'node': 'srv2', 'status': 'timeout', 'device': 'iot6'})
    evs.append({'type': 'port_stats', 'ts': 101.0, 'dpid': 2, 'ports': [{'port': 1, 'tx_bytes': 1000, 'rx_bytes': 1000}]})
    evs.append({'type': 'port_stats', 'ts': 103.0, 'dpid': 2, 'ports': [{'port': 1, 'tx_bytes': 1800, 'rx_bytes': 1600}]})
    path.write_text(''.join(json.dumps(e) + '\n' for e in evs))


def test_connections_are_classified_from_the_return_bytes(tmp_path):
    p = tmp_path / 'r01.jsonl'
    _write(p)
    rw = load_run(str(p), 'treat')
    kinds = {c.client_port: c.kind for c in rw.conns.values()}
    assert kinds == {'40001': 'served', '40002': 'unanswered', '40003': 'partial'}


def test_per_server_witness_counts(tmp_path):
    p = tmp_path / 'r01.jsonl'
    _write(p)
    s1, s2 = summarise_run(load_run(str(p), 'treat'))
    assert (s1.node, s1.client_success, s1.switch_served, s1.agreement) == ('srv1', 1, 1, 1.0)
    assert s1.rule_bytes == 548 + 598
    assert s1.port_bytes == 1400               # srv1's own edge switch is dpid 2, port 1
    assert (s2.switch_served, s2.switch_unanswered, s2.switch_partial) == (0, 1, 1)
    assert s2.client_timeout == 1 and s2.agreement is None
