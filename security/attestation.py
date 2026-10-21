"""Server admission by remote attestation (Phase 4).

Behaviour -- the trust score and the anomaly gate -- judges what a server
*does*. Attestation judges what it *is*: before a server is offered work, the
controller checks a signed measurement of the code it runs against a reference.
The two catch different things, which is the point of having both:

* code tampered with on disk is refused at admission, before it serves a task,
  whatever it would have done -- behaviour only notices after it has done it;
* genuine code compromised at run time measures exactly like genuine code, so
  it passes attestation, and only behaviour can catch it.

WHO MEASURES. Not the agent. Code that reports its own hash can report any hash
it likes, so the measurement is taken by a separate attester process
(simulation/attester.py) that reads, from outside, which files the agent
process is actually running -- the role IMA plays for a TPM. The attester holds
the node's signing key; the controller holds only the public key.

WHAT THIS IS NOT. The quote is an Ed25519 signature made in software. Nothing
here is a hardware root of trust: on this testbed every process runs as root on
one host, so the separation between attester and agent is a design boundary,
not an enforced one. The protocol is the real one (nonce, signed measurement,
reference values, re-attestation); the trust anchor is emulated.

The measurement is a PCR-style chain over named components:

    m_0 = 32 zero bytes
    m_i = sha256(m_{i-1} || sha256(role_i) || digest_i)

so reordering, renaming or dropping a component changes it, and the components
travel with the quote so a refusal can name the file that differed.
"""

import hashlib
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

NONCE_BYTES = 16
NONCE_TTL_S = 30.0
QUOTE_LABEL = b'ztsdn-attest-v1\x00'

#: The agent's code, as roles relative to the repository root. The package
#: __init__ is measured too: it runs before the module does.
AGENT_MODULE = 'simulation.node_agent'
INTERPRETER_ROLE = 'interpreter'

# Verdict reasons. 'attested' is the only one that admits.
ATTESTED = 'attested'
NO_CHALLENGE = 'no_challenge'
NONCE_EXPIRED = 'nonce_expired'
UNKNOWN_KEY = 'unknown_key'
BAD_SIGNATURE = 'bad_signature'
IP_PIN = 'ip_pin'
MALFORMED = 'malformed'
NOT_IN_ALLOWLIST = 'not_in_allowlist'
UNMEASURABLE = 'unmeasurable'

REFUSALS = (NO_CHALLENGE, NONCE_EXPIRED, UNKNOWN_KEY, BAD_SIGNATURE, IP_PIN,
            MALFORMED, NOT_IN_ALLOWLIST, UNMEASURABLE)


class MeasurementError(Exception):
    """The attester cannot tell which code a process runs, so it will not vouch
    for it. Fails closed: no quote is better than a quote about the wrong file."""


# --------------------------------------------------------------------------- #
# Measurement                                                                  #
# --------------------------------------------------------------------------- #
def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def extend(components: Sequence[Tuple[str, str]]) -> str:
    """The composite measurement of (role, sha256 hex) pairs, in order."""
    m = bytes(32)
    for role, digest in components:
        m = hashlib.sha256(m + hashlib.sha256(role.encode()).digest()
                           + bytes.fromhex(digest)).digest()
    return m.hex()


def module_files(module: str) -> List[str]:
    """Relative paths Python executes for `-m module`: each package __init__
    on the way, then the module itself."""
    parts = module.split('.')
    files = ['/'.join(parts[:i]) + '/__init__.py' for i in range(1, len(parts))]
    return files + ['/'.join(parts) + '.py']


def measure_tree(root: Path, module: str = AGENT_MODULE,
                 interpreter: Optional[Path] = None) -> List[Tuple[str, str]]:
    """Components for `module` as found under `root`, interpreter first."""
    comps: List[Tuple[str, str]] = []
    if interpreter is not None:
        comps.append((INTERPRETER_ROLE, file_digest(interpreter)))
    for rel in module_files(module):
        comps.append((rel, file_digest(root / rel)))
    return comps


def resolve_python_module(argv: Sequence[str], environ: Dict[str, str]) -> str:
    """The module a `python3 ... -m <module>` command line runs.

    Only the plain form is accepted. -I, -P, -E, -S or a PYTHONPATH/PYTHONHOME
    in the environment change where the module is found, and the attester does
    not re-implement Python's import system to follow them: it refuses.
    """
    if not argv or 'python' not in os.path.basename(argv[0]):
        raise MeasurementError(f'not a python process: {argv[:1]}')
    if environ.get('PYTHONPATH') or environ.get('PYTHONHOME'):
        raise MeasurementError('PYTHONPATH/PYTHONHOME set; module location is ambiguous')
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '-m':
            if i + 1 >= len(argv):
                break
            return argv[i + 1]
        if not a.startswith('-'):
            raise MeasurementError(f'runs a script, not a module: {a}')
        if any(c in a[1:] for c in 'IPESm') or a.startswith('-X') or a == '-c':
            raise MeasurementError(f'interpreter flag {a} changes module resolution')
        i += 1
    raise MeasurementError('no -m <module> on the command line')


def measure_process(pid: int, module: str = AGENT_MODULE,
                    proc: Path = Path('/proc')) -> List[Tuple[str, str]]:
    """Measure the code process `pid` is running, from outside it.

    Reads the interpreter from /proc/<pid>/exe, the command line and the
    environment, and resolves `-m module` against /proc/<pid>/cwd -- the first
    place Python looks. Raises MeasurementError if the process does not run
    `module` in that plain form.
    """
    base = proc / str(pid)
    try:
        argv = [a.decode() for a in (base / 'cmdline').read_bytes().split(b'\0') if a]
        environ = dict(
            e.decode(errors='replace').split('=', 1)
            for e in (base / 'environ').read_bytes().split(b'\0') if b'=' in e)
        cwd = Path(os.readlink(base / 'cwd'))
        exe = Path(os.readlink(base / 'exe'))
    except OSError as exc:
        raise MeasurementError(f'cannot read /proc/{pid}: {exc}') from exc
    ran = resolve_python_module(argv, environ)
    if ran != module:
        raise MeasurementError(f'process runs {ran}, not {module}')
    try:
        return measure_tree(cwd, module, interpreter=exe)
    except OSError as exc:
        raise MeasurementError(f'cannot read the module files: {exc}') from exc


# --------------------------------------------------------------------------- #
# Quotes                                                                       #
# --------------------------------------------------------------------------- #
def quote_message(node_id: str, nonce: bytes, measurement: str) -> bytes:
    return QUOTE_LABEL + node_id.encode() + b'\0' + nonce + bytes.fromhex(measurement)


def generate_keypair() -> Tuple[bytes, bytes]:
    """(private, public), both raw 32 bytes."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    raw = serialization.Encoding.Raw
    return (sk.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()),
            sk.public_key().public_bytes(raw, serialization.PublicFormat.Raw))


def sign_quote(private_key: bytes, node_id: str, nonce: bytes, measurement: str) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(private_key)
    return sk.sign(quote_message(node_id, nonce, measurement))


def verify_signature(public_key: bytes, node_id: str, nonce: bytes,
                     measurement: str, signature: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, quote_message(node_id, nonce, measurement))
        return True
    except (InvalidSignature, ValueError):
        return False


def provision_keys(node_ids: Iterable[str], key_dir: Path) -> None:
    """Fresh key pairs for one run: `<node>.key` (0600) for the attester,
    `<node>.pub` for the controller. Stands in for keys installed at
    manufacture; regenerated every run so no run can replay another's quotes."""
    key_dir.mkdir(parents=True, exist_ok=True)
    for node in node_ids:
        sk, pk = generate_keypair()
        key = key_dir / f'{node}.key'
        key.write_text(sk.hex())
        os.chmod(key, 0o600)
        (key_dir / f'{node}.pub').write_text(pk.hex())


# --------------------------------------------------------------------------- #
# Verifier (controller side)                                                   #
# --------------------------------------------------------------------------- #
@dataclass
class AttestationConfig:
    enabled: bool = False
    key_dir: str = 'logs/attest_keys'
    reattest_s: float = 30.0
    #: How long one good quote admits a node. Two missed re-attestations and a
    #: little slack, so one slow round does not evict an honest server.
    validity_s: float = 75.0
    nonce_ttl_s: float = NONCE_TTL_S
    #: Extra accepted composite measurements, besides the reference build.
    allowlist: Tuple[str, ...] = ()
    #: Where the reference build of the agent lives (the controller's own copy
    #: of the release; '' = this repository), and the interpreter it is meant
    #: to run under.
    reference_root: str = ''
    reference_interpreter: str = '/usr/bin/python3'

    @classmethod
    def from_config(cls, security_cfg: Optional[Dict]) -> 'AttestationConfig':
        a = dict((security_cfg or {}).get('attestation') or {})
        known = set(cls.__dataclass_fields__)
        unknown = set(a) - known
        if unknown:
            raise ValueError(f'security.attestation: unknown keys {sorted(unknown)}')
        if 'allowlist' in a:
            a['allowlist'] = tuple(a['allowlist'] or ())
        cfg = cls(**a)
        if cfg.validity_s <= cfg.reattest_s:
            raise ValueError('security.attestation.validity_s must exceed reattest_s')
        return cfg


def reference_components(cfg: AttestationConfig) -> List[Tuple[str, str]]:
    interp = Path(os.path.realpath(cfg.reference_interpreter))
    root = Path(cfg.reference_root) if cfg.reference_root else Path(__file__).resolve().parent.parent
    return measure_tree(root, AGENT_MODULE, interpreter=interp)


@dataclass
class Verdict:
    node: str
    verdict: str                 # ATTESTED or one of REFUSALS
    detail: str = ''
    measurement: str = ''
    mismatched: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.verdict == ATTESTED


class AttestationVerifier:
    """Nonce issue, quote verification and the admission table.

    A node is admitted while its last verdict is ATTESTED and younger than
    validity_s. Any refusal revokes admission at once; only a later good quote
    restores it. Thread-safe: the API handler threads and the controller's
    sweep loop share it.
    """

    def __init__(self, cfg: AttestationConfig, reference: Sequence[Tuple[str, str]],
                 expected_ips: Optional[Dict[str, str]] = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.cfg = cfg
        self.reference = list(reference)
        self.allowed = {extend(self.reference), *cfg.allowlist}
        self.expected_ips = dict(expected_ips or {})
        self._clock = clock
        self._lock = threading.Lock()
        self._nonces: Dict[str, Tuple[bytes, float]] = {}
        self._pubkeys: Dict[str, bytes] = {}
        self._admitted_at: Dict[str, float] = {}
        self._status: Dict[str, str] = {}

    # -- protocol ------------------------------------------------------------ #
    def issue_challenge(self, node: str) -> bytes:
        nonce = secrets.token_bytes(NONCE_BYTES)
        with self._lock:
            self._nonces[node] = (nonce, self._clock())
        return nonce

    def verify(self, node: str, components: Sequence[Sequence[str]],
               measurement: str, signature: bytes,
               source_ip: Optional[str] = None) -> Verdict:
        v = self._judge(node, components, measurement, signature, source_ip)
        with self._lock:
            if v.ok:
                self._admitted_at[node] = self._clock()
                self._status[node] = ATTESTED
            else:
                self._admitted_at.pop(node, None)
                self._status[node] = v.verdict
        return v

    def _judge(self, node, components, measurement, signature, source_ip) -> Verdict:
        with self._lock:
            entry = self._nonces.pop(node, None)
        if entry is None:
            return Verdict(node, NO_CHALLENGE)
        nonce, issued = entry
        if self._clock() - issued > self.cfg.nonce_ttl_s:
            return Verdict(node, NONCE_EXPIRED)
        expected_ip = self.expected_ips.get(node)
        if source_ip is not None and expected_ip is not None and source_ip != expected_ip:
            return Verdict(node, IP_PIN, f'{node} is at {expected_ip}, quote came from {source_ip}')
        try:
            comps = [(str(r), str(d)) for r, d in components]
            if extend(comps) != measurement:
                return Verdict(node, MALFORMED, 'components do not extend to the measurement')
        except (TypeError, ValueError) as exc:
            return Verdict(node, MALFORMED, str(exc))
        pk = self._pubkey(node)
        if pk is None:
            return Verdict(node, UNKNOWN_KEY, f'no {node}.pub in {self.cfg.key_dir}')
        if not verify_signature(pk, node, nonce, measurement, signature):
            return Verdict(node, BAD_SIGNATURE, measurement=measurement)
        if measurement not in self.allowed:
            ref = dict(self.reference)
            got = dict(comps)
            diff = sorted(r for r in set(ref) | set(got) if ref.get(r) != got.get(r))
            return Verdict(node, NOT_IN_ALLOWLIST, f'differs in {diff}',
                           measurement=measurement, mismatched=diff)
        return Verdict(node, ATTESTED, measurement=measurement)

    def report_unmeasurable(self, node: str, detail: str) -> Verdict:
        """The attester could not measure: refuse, as for a bad quote."""
        with self._lock:
            self._nonces.pop(node, None)
            self._admitted_at.pop(node, None)
            self._status[node] = UNMEASURABLE
        return Verdict(node, UNMEASURABLE, detail)

    def _pubkey(self, node: str) -> Optional[bytes]:
        with self._lock:
            pk = self._pubkeys.get(node)
        if pk is not None:
            return pk
        try:
            pk = bytes.fromhex((Path(self.cfg.key_dir) / f'{node}.pub').read_text().strip())
        except (OSError, ValueError):
            return None
        if len(pk) != 32:
            return None
        with self._lock:
            self._pubkeys[node] = pk
        return pk

    # -- admission ----------------------------------------------------------- #
    def is_admitted(self, node: str) -> bool:
        with self._lock:
            at = self._admitted_at.get(node)
            return at is not None and self._clock() - at <= self.cfg.validity_s

    def sweep(self) -> List[str]:
        """Nodes whose admission lapsed since the last sweep (no fresh quote
        within validity_s). Marks them expired and returns them."""
        now = self._clock()
        lapsed = []
        with self._lock:
            for node, at in list(self._admitted_at.items()):
                if now - at > self.cfg.validity_s:
                    del self._admitted_at[node]
                    self._status[node] = 'expired'
                    lapsed.append(node)
        return lapsed

    def status(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._status)
