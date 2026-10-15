# Deploying outside Mininet

What runs where on a real testbed, and how it is configured. The Mininet path
(`run_demo.py --mode mininet`) is unchanged and needs none of this.

## The pieces

| Process | Where | Template |
|---|---|---|
| Controller (`controller.trust_balancer`) | One host with OVS reachability and the northbound API | `systemd/ztsdn-controller.service` |
| Ledger replicas (`blockchain.raft_replica`) | Three hosts, ideally three different machines | `systemd/ztsdn-raft@.service` |
| Edge-server agent (`simulation.node_agent`) | Each edge server (e.g. a Raspberry Pi) | `systemd/ztsdn-agent@.service` |
| IoT client (`simulation.iot_client`) | Client machines, one source IP per device | `systemd/ztsdn-client@.service` |

The code goes to `/opt/ztsdn` on every host; per-instance settings go in
`/etc/ztsdn/*.env` (root-only, since the client env holds the device key).

## Configuration

1. Copy `config/params_trust_full.yaml` (or `params_trust_raft.yaml`) to
   `config/params_testbed.yaml` and merge in `deploy/testbed.example.yaml`
   with your machines' real addresses.
2. The `inventory:` block is the only place addresses live
   (`contracts/inventory.py`). Server ids must stay `srv1, srv2, ...`.
   `controller_ip` must be the controller host's own testbed address: the
   quarantine rules exempt `/status` polls from it.
3. Mixed hardware: give each server a `class` and set
   `controller.latency_baseline: class`. A class needs at least 3 servers to
   get its own baseline; smaller classes use the fleet median.
4. Keep every host's clock in sync (chrony or systemd-timesyncd). Recordings
   are controller-side, but client-reported latencies and replica logs are
   easier to read against one clock.

## Order of bring-up

1. OVS bridges and VXLAN tunnels between hosts.
2. Ledger replicas (`ztsdn-raft@n1..n3`); check one reports `leader` at `/status`.
3. Controller. Its switches must connect to it (`ovs-vsctl set-controller`).
4. Edge-server agents.
5. `python3 scripts/preflight_live_run.py --config config/params_testbed.yaml`
   from the controller host -- it checks the inventory loads, every server
   answers `/status`, `controller_ip` is local, and the ledger has one leader.
6. IoT clients.

## Not done yet (task 4)

The management endpoints (`/register`, `/topology/links`, `/monitor/pause`)
are unauthenticated, and the device key is still passed on the client's
command line. Do not put this on a network you do not control until task 4.
