"""Show multi-controller fencing state during a run (docs/MULTI_CONTROLLER.md).

    python3 tools/fencing_status.py                      # generation + holder
    sudo python3 tools/fencing_status.py                 # ...and each switch's controller roles
    python3 tools/fencing_status.py --claim standby      # take the generation over, as a
                                                         # standby would (ledger side only)

Reads the ledger replica addresses (and token env var) from the config, by
default config/params_mc_fencing.yaml. `--claim` writes one CONTROLLER_CLAIM
entry to the ledger: the primary's later trust batches are then refused as
stale_generation. It does NOT touch the switches -- no standby exists yet to
become MASTER there (step 2) -- so the primary stays MASTER on them.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from controller.auditor import _generation_reader  # noqa: E402


def _vsctl(*args: str) -> str:
    return subprocess.run(['ovs-vsctl', *args], check=True, capture_output=True,
                          text=True, timeout=5).stdout.strip()


def _switch_roles() -> str:
    """Per bridge, each controller target with the role OVS has granted it
    (master / slave / other, where other = EQUAL) and whether it is connected."""
    try:
        bridges = _vsctl('list-br').split()
    except (OSError, subprocess.SubprocessError) as exc:
        return f'  (switch roles need root and a running OVS: {exc})'
    if not bridges:
        return '  (no bridges: is the run up?)'
    lines = []
    for br in bridges:
        uuids = _vsctl('get', 'bridge', br, 'controller').strip('[]').replace(',', ' ').split()
        cells = []
        for uuid in uuids:
            target, role, connected = _vsctl('get', 'controller', uuid,
                                             'target', 'role', 'is_connected').splitlines()
            cells.append(f"{target.strip(chr(34))}={role}{'' if connected == 'true' else '(down)'}")
        lines.append(f"  {br:<6} {'  '.join(sorted(cells))}")
    return '\n'.join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--config', default='config/params_mc_fencing.yaml')
    ap.add_argument('--claim', metavar='CONTROLLER_ID',
                    help='claim the next generation for this id (a takeover, ledger side)')
    args = ap.parse_args()

    with open(args.config) as fh:
        cfg = yaml.safe_load(fh)
    reader = _generation_reader(cfg)

    state = reader.current_generation()
    if state is None:
        print('ledger cluster unreachable (are the replicas up?)')
        return 1
    print(f"generation {state.get('generation')}  held by {state.get('holder')!r}")

    if args.claim:
        result = reader.claim_generation(args.claim, takeover=True)
        if result is None:
            print('claim: no answer from the cluster')
            return 1
        print(f"claim by {args.claim!r}: {'GRANTED' if result.granted else 'refused'}"
              f" -> generation {result.generation}, held by {result.holder!r}")
        print("The primary's next trust batches should now be refused "
              "(dashboard: ledger_rejected, reason stale_generation).")

    if os.geteuid() == 0:
        print('switch controller roles (target, role, connected):')
        print(_switch_roles())
    return 0


if __name__ == '__main__':
    sys.exit(main())
