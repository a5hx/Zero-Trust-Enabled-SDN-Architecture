"""Check, on this machine's Open vSwitch, the OpenFlow role behaviour that
multi-controller fencing (controller/fencing.py) depends on.

    sudo python3 tools/role_fencing_check.py

It creates a throwaway bridge (ztfence0, no ports), points it at two
controllers that this script plays itself over raw OpenFlow 1.3 (A on
127.0.0.1:6681, B on 127.0.0.1:6682), runs the checks below, and deletes the
bridge again. Nothing else on the host is touched; Mininet need not run.

  1  A: MASTER, generation 1                 -> granted
  2  B: SLAVE, generation 0                  -> refused STALE (why the auditor
                                                must ask under the current one)
  3  B: SLAVE, generation 1                  -> granted
  4  A writes a flow                         -> accepted
  5  B writes a flow                         -> refused IS_SLAVE
  6  B: MASTER, generation 2 (a takeover)    -> granted
  7  A writes a flow                         -> refused IS_SLAVE (A was demoted)
  8  A: MASTER, generation 1 again           -> refused STALE
  9  A: EQUAL, then writes a flow            -> reported, not judged: the gap
                                                docs/MULTI_CONTROLLER.md
                                                describes (EQUAL is not fenced)

Exit code 0 when checks 1-8 behave as described.
"""

from __future__ import annotations

import itertools
import os
import socket
import struct
import subprocess
import sys
import time
from typing import Any, List, Optional, Tuple

from os_ken.ofproto import ofproto_parser
from os_ken.ofproto import ofproto_v1_3 as ofp
from os_ken.ofproto import ofproto_v1_3_parser as parser

BRIDGE = 'ztfence0'
PORTS = {'A': 6681, 'B': 6682}


class _DP:
    """What os-ken's message classes need from a datapath to (de)serialize."""
    ofproto = ofp
    ofproto_parser = parser
    id = 0


class Controller:
    """One raw OpenFlow 1.3 controller connection, accepted from OVS."""

    _xids = itertools.count(100)

    def __init__(self, name: str, sock: socket.socket) -> None:
        self.name = name
        self.sock = sock
        self.dp = _DP()
        self._buf = b''

    def send(self, msg: Any) -> int:
        msg.xid = next(self._xids)
        msg.serialize()
        self.sock.sendall(bytes(msg.buf))
        return msg.xid

    def _read(self, n: int, deadline: float) -> bytes:
        while len(self._buf) < n:
            self.sock.settimeout(max(0.05, deadline - time.monotonic()))
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError(f'{self.name}: switch closed the connection')
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv(self, timeout: float = 3.0) -> Optional[Any]:
        deadline = time.monotonic() + timeout
        try:
            head = self._read(8, deadline)
            version, msg_type, msg_len, xid = struct.unpack('!BBHI', head)
            body = self._read(msg_len - 8, deadline)
        except socket.timeout:
            return None
        buf = head + body
        if msg_type == ofp.OFPT_ECHO_REQUEST:
            self.send(parser.OFPEchoReply(self.dp, data=buf[8:]))
            return self.recv(max(0.05, deadline - time.monotonic()))
        try:
            return ofproto_parser.msg(self.dp, version, msg_type, msg_len, xid, buf)
        except Exception:
            return ('unparsed', msg_type, xid)

    def answer(self, xid: int, timeout: float = 3.0) -> Optional[Any]:
        """The reply or error carrying `xid`; other messages are skipped."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            m = self.recv(deadline - time.monotonic())
            if m is not None and getattr(m, 'xid', None) == xid:
                return m
        return None

    def role(self, role: int, generation: int) -> Any:
        return self.answer(self.send(parser.OFPRoleRequest(self.dp, role, generation)))

    def write_flow(self) -> Optional[Any]:
        """Add a harmless flow, then a barrier. The error, or None if accepted."""
        fm = parser.OFPFlowMod(self.dp, table_id=0, command=ofp.OFPFC_ADD, priority=10,
                               match=parser.OFPMatch(eth_type=0x0800, ipv4_dst='10.255.0.1'),
                               instructions=[])
        fm_xid = self.send(fm)
        barrier = self.send(parser.OFPBarrierRequest(self.dp))
        deadline = time.monotonic() + 3.0
        error = None
        while time.monotonic() < deadline:
            m = self.recv(deadline - time.monotonic())
            if m is None:
                continue
            if isinstance(m, parser.OFPErrorMsg) and m.xid == fm_xid:
                error = m
            if getattr(m, 'xid', None) == barrier:
                return error
        return error or ('no barrier reply',)


def _vsctl(*args: str) -> None:
    subprocess.run(['ovs-vsctl', *args], check=True, capture_output=True, text=True)


def _accept_all(listeners: dict, timeout: float = 15.0) -> dict:
    conns = {}
    deadline = time.monotonic() + timeout
    for name, lsock in listeners.items():
        lsock.settimeout(max(0.1, deadline - time.monotonic()))
        sock, _ = lsock.accept()
        c = Controller(name, sock)
        c.send(parser.OFPHello(c.dp))
        hello = c.recv(5.0)
        if not isinstance(hello, parser.OFPHello):
            raise RuntimeError(f'{name}: expected HELLO from the switch, got {hello!r}')
        conns[name] = c
    return conns


def _describe(m: Any) -> str:
    if isinstance(m, parser.OFPRoleReply):
        names = {ofp.OFPCR_ROLE_MASTER: 'MASTER', ofp.OFPCR_ROLE_SLAVE: 'SLAVE',
                 ofp.OFPCR_ROLE_EQUAL: 'EQUAL'}
        return f'RoleReply {names.get(m.role, m.role)} gen {m.generation_id}'
    if isinstance(m, parser.OFPErrorMsg):
        if m.type == ofp.OFPET_ROLE_REQUEST_FAILED and m.code == ofp.OFPRRFC_STALE:
            return 'Error ROLE_REQUEST_FAILED/STALE'
        if m.type == ofp.OFPET_BAD_REQUEST and m.code == ofp.OFPBRC_IS_SLAVE:
            return 'Error BAD_REQUEST/IS_SLAVE'
        return f'Error type {m.type} code {m.code}'
    return 'accepted' if m is None else repr(m)


def run() -> int:
    listeners = {}
    for name, port in PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', port))
        s.listen(1)
        listeners[name] = s
    _vsctl('--if-exists', 'del-br', BRIDGE)
    _vsctl('add-br', BRIDGE, '--', 'set', 'bridge', BRIDGE, 'protocols=OpenFlow13',
           'fail-mode=secure', '--', 'set-controller', BRIDGE,
           *(f'tcp:127.0.0.1:{p}' for p in PORTS.values()))
    try:
        c = _accept_all(listeners)
        A, B = c['A'], c['B']
        M, S, E = ofp.OFPCR_ROLE_MASTER, ofp.OFPCR_ROLE_SLAVE, ofp.OFPCR_ROLE_EQUAL

        def is_role(m, role):
            return isinstance(m, parser.OFPRoleReply) and m.role == role

        def is_err(m, typ, code):
            return isinstance(m, parser.OFPErrorMsg) and m.type == typ and m.code == code

        stale = (ofp.OFPET_ROLE_REQUEST_FAILED, ofp.OFPRRFC_STALE)
        slave_err = (ofp.OFPET_BAD_REQUEST, ofp.OFPBRC_IS_SLAVE)
        checks: List[Tuple[str, Any, bool]] = []

        def check(label, m, ok):
            checks.append((label, m, ok))
            print(f"  {'PASS' if ok else 'FAIL'}  {label:<44} {_describe(m)}")

        print(f'Open vSwitch role behaviour (bridge {BRIDGE}):')
        m = A.role(M, 1);  check('1 A: MASTER gen 1 -> granted', m, is_role(m, M))
        m = B.role(S, 0);  check('2 B: SLAVE gen 0 -> STALE', m, is_err(m, *stale))
        m = B.role(S, 1);  check('3 B: SLAVE gen 1 -> granted', m, is_role(m, S))
        m = A.write_flow(); check('4 A writes -> accepted', m, m is None)
        m = B.write_flow(); check('5 B writes -> IS_SLAVE', m, is_err(m, *slave_err))
        m = B.role(M, 2);  check('6 B: MASTER gen 2 -> granted', m, is_role(m, M))
        m = A.write_flow(); check('7 A writes -> IS_SLAVE (demoted)', m, is_err(m, *slave_err))
        m = A.role(M, 1);  check('8 A: MASTER gen 1 again -> STALE', m, is_err(m, *stale))

        print('Not judged -- the gap fencing cannot close by roles alone:')
        m = A.role(E, 0);  print(f'        9 A: EQUAL                                  {_describe(m)}')
        m = A.write_flow(); print(f'          A writes as EQUAL                         {_describe(m)}')
        failed = [label for label, _m, ok in checks if not ok]
        print('OK: every fencing assumption holds on this switch.' if not failed
              else f'{len(failed)} check(s) FAILED: fencing assumptions do not hold here.')
        return 0 if not failed else 1
    finally:
        try:
            _vsctl('--if-exists', 'del-br', BRIDGE)
        finally:
            for s in listeners.values():
                s.close()


def main() -> int:
    if os.geteuid() != 0:
        print('needs root for ovs-vsctl:  sudo python3 tools/role_fencing_check.py',
              file=sys.stderr)
        return 2
    return run()


if __name__ == '__main__':
    sys.exit(main())
