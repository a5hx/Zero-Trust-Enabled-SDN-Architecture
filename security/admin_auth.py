"""Bearer-token protection for the controller's management endpoints, and
key handling that keeps secrets off command lines.

Management endpoints are the ones the *harness* (or an operator) calls, not a
device: ``/register``, ``/topology/links`` and ``/monitor/pause``. The last one
switches off continuous verification, so on any network the controller does
not fully own it must not be callable by anyone who can reach the API.

The token is read from an environment variable whose *name* is in the config
(``controller.admin_token_env``), never from the config file or a command line,
so it does not end up in git or in ``ps``. Behaviour:

* name not configured -> endpoints stay open, exactly as before (Mininet runs
  on one laptop); the controller logs a warning at start-up;
* name configured but the variable unset or empty -> refuse to start. A config
  that asks for protection must never silently run without it.

Device keys follow the same rule: ``security.shared_key_env`` names a variable
holding the PRESENT-80 key in hex, as an alternative to ``shared_key_hex``.
With ``security.key_derivation: per_device`` each device's key is derived from
that master key (`derive_device_key`), so a captured device gives away its own
key and nobody else's.
"""

import hashlib
import hmac
import os
from typing import Any, Dict, Optional

#: POST endpoints that need the admin token when one is configured.
ADMIN_PATHS = frozenset({'/register', '/topology/links', '/monitor/pause'})

_DERIVE_LABEL = b'ztsdn-device-key:'


class SecretConfigError(ValueError):
    """A config names a secret that is not available."""


def _from_env(var: str, what: str) -> str:
    value = os.environ.get(var, '').strip()
    if not value:
        raise SecretConfigError(
            f"{what}: environment variable {var} is unset or empty. Set it, or "
            f"remove the setting from the config to run without it.")
    return value


def load_admin_token(cfg: Dict[str, Any]) -> Optional[str]:
    """The management-endpoint token, or None when the config asks for none."""
    var = (cfg.get('controller') or {}).get('admin_token_env')
    return _from_env(var, 'controller.admin_token_env') if var else None


def admin_headers(cfg: Dict[str, Any]) -> Dict[str, str]:
    """Headers a harness call to a management endpoint must carry."""
    var = (cfg.get('controller') or {}).get('admin_token_env')
    token = os.environ.get(var, '').strip() if var else ''
    return {'Authorization': f'Bearer {token}'} if token else {}


def is_authorized(header_value: Optional[str], token: Optional[str]) -> bool:
    """Constant-time check of an Authorization header against the token.
    Always True when no token is configured."""
    if not token:
        return True
    return hmac.compare_digest((header_value or '').encode(), f'Bearer {token}'.encode())


def resolve_shared_key_hex(sec: Dict[str, Any]) -> Optional[str]:
    """The PRESENT-80 master key in hex: from ``shared_key_env`` if set,
    else ``shared_key_hex``, else None."""
    var = sec.get('shared_key_env')
    if var:
        return _from_env(var, 'security.shared_key_env')
    return sec.get('shared_key_hex')


def derive_device_key(master: bytes, device_id: str) -> bytes:
    """A device's own 80-bit PRESENT key: HMAC-SHA256(master, label || id),
    truncated to 10 bytes. Deterministic, so the controller re-derives it on
    every challenge instead of storing a key table."""
    return hmac.new(master, _DERIVE_LABEL + device_id.encode(), hashlib.sha256).digest()[:10]
