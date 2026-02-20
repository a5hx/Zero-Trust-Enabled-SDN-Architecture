from mininet.topo import Topo
from mininet.net  import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
import yaml, random

class ZeroTrustTopo(Topo):
    def build(self, cfg):
        n_edge   = cfg['simulation']['num_edge_nodes']
        n_iot    = cfg['simulation']['num_iot_devices']
        n_mal    = cfg['simulation']['num_malicious']

        edge_switches = []
        edge_servers  = []

        # Create edge switches + servers
        for i in range(n_edge):
            sw  = self.addSwitch(f's{i+1}', cls=OVSSwitch, protocols='OpenFlow13')
            srv = self.addHost(f'srv{i+1}', ip=f'10.0.1.{i+1}')
            self.addLink(sw, srv, cls=TCLink, delay='2ms', bw=100)
            edge_switches.append(sw)
            edge_servers.append(srv)

        # Core switch — connects edge switches
        core = self.addSwitch('s0', cls=OVSSwitch, protocols='OpenFlow13')
        for sw in edge_switches:
            self.addLink(core, sw, cls=TCLink, delay='5ms', bw=1000)

        # IoT devices — mark last n_mal as malicious via metadata
        iot_ids = []
        for j in range(n_iot):
            is_mal = (j >= n_iot - n_mal)
            h = self.addHost(f'iot{j+1}', ip=f'10.0.0.{j+1}',
                             metadata={'malicious': is_mal})
            sw_idx = j % n_edge
            delay  = f'{random.randint(1,10)}ms'
            self.addLink(h, edge_switches[sw_idx], cls=TCLink, delay=delay, bw=10)
            iot_ids.append(h)

        return iot_ids, edge_servers
