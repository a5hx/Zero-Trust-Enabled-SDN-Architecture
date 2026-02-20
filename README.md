# Zero Trust–Enabled SDN for Secure Load Balancing in Edge Networks

Final year research project — SDN + blockchain-backed trust engine for secure IoT edge computing.

---

## Overview

This system integrates a Zero Trust security model into a Software-Defined Network to make intelligent, trust-aware routing decisions for IoT workloads at the edge. Trust scores are computed dynamically and stored in a tamper-evident blockchain ledger maintained via RAFT consensus.

**Core components:**
- **Mininet** — network emulation (IoT devices, edge switches, edge servers)
- **Ryu SDN Controller** — OpenFlow-based trust-aware load balancer
- **PRESENT-80 Cipher** — lightweight IoT device authentication
- **Blockchain Ledger** — SHA-256 + Merkle tree trust record store
- **RAFT Consensus** — 3-replica fault-tolerant ledger replication
- **Dynamic Trust Model** — normalised formula with EMA decay
- **AI Weight Optimizer** — Random Forest (offline) + UCB1 Bandit (online)

---

## Repository Structure

```
project/
├── config/
│   └── params.yaml           
├── contracts/
│   ├── trust_update.py       
│   └── block_schema.py       
├── blockchain/
│   ├── merkle.py
│   ├── block.py
│   ├── ledger.py
│   └── raft.py
├── trust_engine/
│   ├── trust_calculator.py
│   └── ai_optimizer.py
├── controller/
│   ├── trust_balancer.py     
│   └── flow_monitor.py
├── security/
│   └── present_cipher.py
├── simulation/
│   ├── topology.py
│   └── attack_simulator.py
├── evaluation/
│   ├── metrics.py
│   ├── baseline.py
│   ├── stats.py
│   └── plots.py
├── tests/
├── data/                     
├── logs/                     
└── requirements.txt
```

---

## Prerequisites

- Python 3.9+
- Mininet 2.3+
- Ryu SDN Framework
- Open vSwitch

Install Python dependencies:

```bash
pip install -r requirements.txt
```

`requirements.txt` includes: `ryu`, `scikit-learn`, `scipy`, `matplotlib`, `pyyaml`, `pytest`, `joblib`

---

## Quick Start

**1. Start the Mininet topology**

```bash
sudo python simulation/topology.py
```

**2. Launch the Ryu controller** (separate terminal)

```bash
ryu-manager controller/trust_balancer.py
```

**3. Run tests**

```bash
pytest tests/ -v
```

---

## Status

| Phase | Component | Status |
|-------|-----------|--------|
| 0 | Repo structure & data contracts | ✅ Done |
| 1 | Mininet topology | 🔄 In progress |
| 2 | Trust formula & calculator | ⬜ Pending |
| 3 | Blockchain core | ⬜ Pending |
| 4 | RAFT consensus | ⬜ Pending |
| 5 | Ryu controller & load balancer | ⬜ Pending |
| 6 | PRESENT-80 authentication | ⬜ Pending |
| 7 | AI weight optimizer | ⬜ Pending |
| 8 | Attack simulation | ⬜ Pending |
| 9 | Evaluation | ⬜ Pending |

---

