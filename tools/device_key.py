"""Print a device's own PRESENT-80 key for provisioning (key_derivation: per_device).

    ZTSDN_MASTER_KEY=<20 hex chars> python3 tools/device_key.py iot1 [iot2 ...]

Reads the master key from the environment (never an argument, so it does not
land in shell history or `ps`), and prints `<device_id> <key hex>` per device.
Put each device's key in its own /etc/ztsdn/client-<id>.env as ZTSDN_DEVICE_KEY.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.admin_auth import derive_device_key  # noqa: E402


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    var = os.environ.get('ZTSDN_MASTER_KEY_ENV', 'ZTSDN_MASTER_KEY')
    master_hex = os.environ.get(var, '').strip()
    if not master_hex or not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    master = bytes.fromhex(master_hex)
    if len(master) != 10:
        print(f'{var} must be 10 bytes (20 hex chars), got {len(master)}', file=sys.stderr)
        return 2
    for device_id in argv:
        print(device_id, derive_device_key(master, device_id).hex())
    return 0


if __name__ == '__main__':
    sys.exit(main())
