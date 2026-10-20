"""Who is on the network and at which address -- the controller's inventory.

The controller needs every edge server's IP and MAC without any runtime
discovery: the virtual-IP rewrite installs the server's MAC directly
(`TrustBalancerApp._install_vip_pair`), quarantine matches on its IP, the
health-check carve-out matches the controller's own polling address, and the
identity roster pins each device to its IP. Under Mininet all of that is
*computed* by `simulation/addressing.py`, because Mininet hands out the
addresses the same function chose.

On real hardware the addresses are whatever the machines have, so they must be
*configured*. This module is the one place both cases meet:

* no ``inventory:`` block -> generated from `simulation/addressing.py`
  (``simulation.num_edge_nodes`` / ``num_iot_devices``), byte-for-byte what every
  Mininet run so far has used;
* an ``inventory:`` block -> read from config and validated up front, so a typo
  fails at start-up instead of as a rewrite rule for a MAC nobody owns.

Config shape::

    inventory:
      controller_ip: 192.168.50.10      # source address of the /status polls
      vip_mac: 02:00:00:00:99:01         # optional; the default is fine
      servers:
        srv1: {ip: 192.168.50.101, mac: dc:a6:32:01:02:03, class: pi4}
        srv2: {ip: 192.168.50.102, mac: dc:a6:32:01:02:04, class: pi5}
      devices:                           # optional; enables the provisioned roster
        iot1: 192.168.50.201
        iot2: 192.168.50.202

``class`` (optional) names the server's hardware class. With
``controller.latency_baseline: class`` the latency tell compares a server with
the median of its own class instead of the whole fleet, so a slower but honest
Raspberry Pi is not judged against a laptop (`controller/flow_monitor.py`).

Server ids must keep the ``srvN`` form: N is the server's OpenFlow cookie and
meter id (`TrustBalancerApp._cookie_for`, `_meter_id_for`).
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from simulation.addressing import CX_IP, VIP_MAC, iot_ip, srv_index, srv_ip, srv_mac

_MAC_RE = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')
_SRV_RE = re.compile(r'^srv([1-9]\d*)$')


class InventoryError(ValueError):
    """The inventory block is malformed or inconsistent."""


def _check_ip(value: Any, where: str) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value)))
    except ValueError:
        raise InventoryError(f'{where}: {value!r} is not an IPv4 address') from None


def _check_mac(value: Any, where: str) -> str:
    mac = str(value).strip().lower()
    if not _MAC_RE.match(mac):
        raise InventoryError(f'{where}: {value!r} is not a MAC address (aa:bb:cc:dd:ee:ff)')
    return mac


@dataclass(frozen=True)
class Inventory:
    servers: Dict[str, Tuple[str, str]]          # srvN -> (ip, mac)
    devices: Dict[str, str] = field(default_factory=dict)   # iotN -> ip
    classes: Dict[str, str] = field(default_factory=dict)   # srvN -> hardware class
    controller_ip: str = CX_IP
    vip_mac: str = VIP_MAC
    source: str = 'mininet'                      # 'mininet' | 'config'

    # -- lookups ------------------------------------------------------------ #
    @property
    def server_ids(self) -> List[str]:
        """Server ids ordered by index (srv1, srv2, ...)."""
        return sorted(self.servers, key=srv_index)

    def server_ip(self, node_id: str) -> str:
        return self.servers[node_id][0]

    def server_mac(self, node_id: str) -> str:
        return self.servers[node_id][1]

    def device_ip(self, device_id: str) -> str:
        return self.devices[device_id]

    def server_class(self, node_id: str) -> str:
        return self.classes.get(node_id, 'default')

    def roster(self) -> Dict[str, str]:
        """device_id -> the source IP entitled to it (security.IdentityBinding)."""
        return dict(self.devices)

    # -- construction ------------------------------------------------------- #
    @classmethod
    def generated(cls, num_servers: int, num_devices: int = 0) -> 'Inventory':
        """The Mininet addressing scheme (`simulation/addressing.py`)."""
        return cls(
            servers={f'srv{i}': (srv_ip(i), srv_mac(i)) for i in range(1, num_servers + 1)},
            devices={f'iot{j}': iot_ip(j) for j in range(1, num_devices + 1)},
            controller_ip=CX_IP, vip_mac=VIP_MAC, source='mininet',
        )

    @classmethod
    def from_config(cls, cfg: Dict[str, Any]) -> 'Inventory':
        sim = cfg.get('simulation') or {}
        block = cfg.get('inventory')
        if not block:
            inv = cls.generated(int(sim.get('num_edge_nodes') or 0),
                                int(sim.get('num_iot_devices') or 0))
            # Mininet runs take their hardware classes from the emulated CPU
            # profiles (simulation/cpu_profiles.py), so latency_baseline: class
            # works in emulation exactly as it would on mixed hardware.
            from simulation.cpu_profiles import server_classes
            classes = server_classes(cfg)
            if classes:
                inv = cls(servers=inv.servers, devices=inv.devices, classes=classes,
                          controller_ip=inv.controller_ip, vip_mac=inv.vip_mac,
                          source=inv.source)
            return inv

        raw_servers = block.get('servers') or {}
        if not raw_servers:
            raise InventoryError('inventory.servers is empty')
        servers: Dict[str, Tuple[str, str]] = {}
        classes: Dict[str, str] = {}
        for node_id, entry in raw_servers.items():
            where = f'inventory.servers.{node_id}'
            if not _SRV_RE.match(str(node_id)):
                raise InventoryError(f'{where}: server ids must look like srv1, srv2, ...')
            if not isinstance(entry, dict):
                raise InventoryError(f'{where}: expected {{ip: ..., mac: ...}}')
            servers[str(node_id)] = (_check_ip(entry.get('ip'), f'{where}.ip'),
                                     _check_mac(entry.get('mac'), f'{where}.mac'))
            classes[str(node_id)] = str(entry.get('class', 'default'))

        devices = {str(d): _check_ip(ip, f'inventory.devices.{d}')
                   for d, ip in (block.get('devices') or {}).items()}

        ips = [ip for ip, _ in servers.values()] + list(devices.values())
        dup_ips = sorted({ip for ip in ips if ips.count(ip) > 1})
        if dup_ips:
            raise InventoryError(f'inventory: address(es) used twice: {dup_ips}')
        macs = [mac for _, mac in servers.values()]
        if len(set(macs)) != len(macs):
            raise InventoryError('inventory.servers: two servers share a MAC')

        expected = sim.get('num_edge_nodes')
        if expected is not None and int(expected) != len(servers):
            raise InventoryError(
                f'inventory lists {len(servers)} servers but simulation.num_edge_nodes '
                f'is {expected}')

        if 'controller_ip' not in block:
            raise InventoryError('inventory.controller_ip is required (the /status poll source)')
        return cls(
            servers=servers, devices=devices, classes=classes,
            controller_ip=_check_ip(block['controller_ip'], 'inventory.controller_ip'),
            vip_mac=_check_mac(block.get('vip_mac', VIP_MAC), 'inventory.vip_mac'),
            source='config',
        )
