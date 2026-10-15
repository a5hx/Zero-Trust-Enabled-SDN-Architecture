"""contracts/inventory.py and the controller's use of it (task 3: run outside
Mininet).

Two properties matter most:

* Under Mininet nothing changes: with no `inventory:` block the generated
  inventory is exactly simulation/addressing.py's scheme, for the shipped
  full-scale config.
* On real hardware a bad inventory fails at start-up, before any rule is
  installed for an address nobody owns.

Plus the hardware-class latency baseline, which is what lets the latency tell
work on mixed hardware without being evadable by a server slow from boot.
"""

import pytest

from contracts.inventory import Inventory, InventoryError
from controller.flow_monitor import MIN_CLASS_SIZE, FlowMonitor, StatusProbe
from controller.trust_state import TrustState
from simulation.addressing import CX_IP, VIP_MAC, iot_ip, srv_ip, srv_mac

yaml = pytest.importorskip('yaml')


def _real_cfg(**overrides):
    inv = {
        'controller_ip': '192.168.50.10',
        'servers': {
            'srv1': {'ip': '192.168.50.101', 'mac': 'DC:A6:32:00:00:01', 'class': 'pi4'},
            'srv2': {'ip': '192.168.50.102', 'mac': 'dc:a6:32:00:00:02', 'class': 'pi4'},
        },
        'devices': {'iot1': '192.168.50.201'},
    }
    inv.update(overrides)
    return {'simulation': {'num_edge_nodes': 2}, 'inventory': inv}


class TestGeneratedInventory:
    def test_shipped_config_generates_exactly_the_mininet_addresses(self) -> None:
        with open('config/params_trust_full.yaml') as fh:
            cfg = yaml.safe_load(fh)
        inv = Inventory.from_config(cfg)
        n = cfg['simulation']['num_edge_nodes']
        m = cfg['simulation']['num_iot_devices']
        assert inv.source == 'mininet'
        assert inv.server_ids == [f'srv{i}' for i in range(1, n + 1)]
        assert all(inv.server_ip(f'srv{i}') == srv_ip(i) and inv.server_mac(f'srv{i}') == srv_mac(i)
                   for i in range(1, n + 1))
        assert inv.roster() == {f'iot{j}': iot_ip(j) for j in range(1, m + 1)}
        assert (inv.controller_ip, inv.vip_mac) == (CX_IP, VIP_MAC)

    def test_server_ids_sort_numerically(self) -> None:
        assert Inventory.generated(12).server_ids[-3:] == ['srv10', 'srv11', 'srv12']


class TestConfiguredInventory:
    def test_reads_and_normalises_a_real_inventory(self) -> None:
        inv = Inventory.from_config(_real_cfg())
        assert inv.source == 'config'
        assert inv.server_mac('srv1') == 'dc:a6:32:00:00:01'
        assert inv.server_class('srv1') == 'pi4'
        assert inv.roster() == {'iot1': '192.168.50.201'}
        assert inv.controller_ip == '192.168.50.10'

    @pytest.mark.parametrize('bad', [
        {'servers': {'server1': {'ip': '192.168.50.101', 'mac': 'dc:a6:32:00:00:01'}}},
        {'servers': {'srv1': {'ip': '300.1.1.1', 'mac': 'dc:a6:32:00:00:01'}}},
        {'servers': {'srv1': {'ip': '192.168.50.101', 'mac': 'not-a-mac'}}},
        {'servers': {}},
    ])
    def test_malformed_servers_fail_at_load(self, bad) -> None:
        cfg = _real_cfg(**bad)
        cfg['simulation'] = {}
        with pytest.raises(InventoryError):
            Inventory.from_config(cfg)

    def test_duplicate_address_fails(self) -> None:
        cfg = _real_cfg(devices={'iot1': '192.168.50.101'})
        with pytest.raises(InventoryError, match='used twice'):
            Inventory.from_config(cfg)

    def test_server_count_must_match_the_simulation_block(self) -> None:
        cfg = _real_cfg()
        cfg['simulation']['num_edge_nodes'] = 8
        with pytest.raises(InventoryError, match='num_edge_nodes'):
            Inventory.from_config(cfg)

    def test_controller_ip_is_required(self) -> None:
        cfg = _real_cfg()
        del cfg['inventory']['controller_ip']
        with pytest.raises(InventoryError, match='controller_ip'):
            Inventory.from_config(cfg)

    def test_the_controller_roster_comes_from_the_inventory(self) -> None:
        from controller.trust_balancer import _device_roster
        assert _device_roster(_real_cfg()) == {'iot1': '192.168.50.201'}


# --------------------------------------------------------------------------- #
def _monitor(classes, mode='class'):
    ids = sorted(classes, key=lambda n: int(n[3:]))
    return FlowMonitor(
        state=TrustState(node_ids=ids), node_ids=ids, agent_port=8000,
        poll_interval_s=1.0, honesty_deviation_threshold=0.4,
        on_quarantine=lambda _n: None,
        node_hosts={n: f'192.168.50.{100 + int(n[3:])}' for n in ids},
        node_classes=classes, latency_baseline=mode,
    )


def _probes(rtts):
    return {n: StatusProbe(payload={'cpu_load': 0.1}, rtt_ms=r) for n, r in rtts.items()}


class TestClassBaseline:
    CLASSES = {'srv1': 'pi4', 'srv2': 'pi4', 'srv3': 'pi4',
               'srv4': 'nuc', 'srv5': 'nuc', 'srv6': 'nuc'}

    def test_each_node_is_judged_against_its_own_class(self) -> None:
        mon = _monitor(self.CLASSES)
        rtts = {'srv1': 60, 'srv2': 64, 'srv3': 62, 'srv4': 10, 'srv5': 12, 'srv6': 11}
        base = mon._latency_baselines(_probes(rtts), fleet=37.0)
        assert base['srv1'] == 62 and base['srv4'] == 11

    def test_fleet_mode_keeps_the_original_behaviour(self) -> None:
        mon = _monitor(self.CLASSES, mode='fleet')
        base = mon._latency_baselines(_probes({n: 10 for n in self.CLASSES}), fleet=37.0)
        assert set(base.values()) == {37.0}

    def test_a_class_too_small_for_a_median_falls_back_to_the_fleet(self) -> None:
        classes = {'srv1': 'pi4', 'srv2': 'pi4', 'srv3': 'pi4', 'srv4': 'nuc'}
        assert sum(1 for c in classes.values() if c == 'nuc') < MIN_CLASS_SIZE
        mon = _monitor(classes)
        base = mon._latency_baselines(_probes({'srv1': 60, 'srv2': 61, 'srv3': 62, 'srv4': 10}),
                                      fleet=35.5)
        assert base['srv4'] == 35.5 and base['srv1'] == 61

    def test_a_slow_honest_pi_is_not_flagged_but_a_slow_liar_among_pis_is(self) -> None:
        """The point of the class baseline: under the fleet median a slow but
        honest Pi looks like a liar next to fast NUCs; under its class median it
        does not, while a Pi that is far slower than other Pis still does."""
        from controller.flow_monitor import evaluate_latency_tell, fleet_latency_baseline
        classes = {'srv1': 'pi4', 'srv2': 'pi4', 'srv3': 'pi4',
                   'srv4': 'nuc', 'srv5': 'nuc', 'srv6': 'nuc', 'srv7': 'nuc', 'srv8': 'nuc'}
        rtts = {'srv1': 60, 'srv2': 64, 'srv3': 250,
                'srv4': 10, 'srv5': 12, 'srv6': 11, 'srv7': 10, 'srv8': 12}
        fleet = fleet_latency_baseline(list(rtts.values()))        # 12 ms: NUCs dominate
        by_class = _monitor(classes)._latency_baselines(_probes(rtts), fleet)

        def tripped(node, baseline):
            strikes = 0
            for _ in range(3):
                strikes = evaluate_latency_tell(0.1, rtts[node], baseline, strikes).strikes
            return strikes >= 3

        assert tripped('srv1', fleet)                # fleet median: honest Pi accused
        assert not tripped('srv1', by_class['srv1'])  # class median: not accused
        assert tripped('srv3', by_class['srv3'])     # a Pi 4x slower than Pis still is

    def test_unknown_mode_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            _monitor(self.CLASSES, mode='self')

    def test_polls_go_to_the_inventory_address(self) -> None:
        mon = _monitor(self.CLASSES)
        assert mon.node_hosts['srv4'] == '192.168.50.104'


class TestBaselineRouterOnRealAddresses:
    def test_static_router_uses_the_inventory_map_for_non_mininet_ips(self) -> None:
        from base_model.static_router import StaticRouter
        router = StaticRouter(n_edge=4, ip_to_index={'192.168.50.201': 1, '192.168.50.206': 6})
        assert router.bind('192.168.50.201') == 'srv1'
        assert router.bind('192.168.50.206') == 'srv2'     # (6-1) % 4 + 1
        assert router.bind('10.0.0.3') == 'srv3'           # Mininet scheme still works


class TestDeployExample:
    def test_the_testbed_example_loads_over_the_full_config(self) -> None:
        with open('config/params_trust_full.yaml') as fh:
            cfg = yaml.safe_load(fh)
        with open('deploy/testbed.example.yaml') as fh:
            overlay = yaml.safe_load(fh)
        for key, block in overlay.items():
            if isinstance(block, dict) and isinstance(cfg.get(key), dict):
                cfg[key].update(block)
            else:
                cfg[key] = block
        inv = Inventory.from_config(cfg)
        assert inv.source == 'config' and len(inv.servers) == cfg['simulation']['num_edge_nodes']
        assert {inv.server_class(n) for n in inv.server_ids} == {'pi4', 'nuc'}
        from blockchain.commit_backend import parse_replicas
        assert len(parse_replicas(cfg['ledger']['replicas'])) == 3
