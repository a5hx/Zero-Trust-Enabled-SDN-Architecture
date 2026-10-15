"""Derive a theta-sweep arm's config from its parent arm's config.

    python3 tools/derive_config.py scoreonly_t045 logs/params_scoreonly_t045.yaml

An arm named ``<parent>_tNNN`` is the parent arm (``scoreonly`` ->
config/params_trust_scoreonly.yaml, ``treat`` -> config/params_trust_full.yaml)
with exactly two lines changed:

    trust.isolation_threshold          -> NNN / 100   (t045 -> 0.45)
    controller.dashboard.record_path   -> data/events_<arm>.jsonl

Derived by text substitution, not by load-and-dump, so the output keeps every
comment and differs from its parent by those two lines and nothing else --
tests/test_derive_config.py diffs them. Generating it at run time, rather than
committing one file per theta, is what makes that true by construction: a
committed copy can be edited on its own, a derived one cannot.

Theta must stay at or below trust.initial_score. Every node starts at that
score, so a higher theta quarantines the whole fleet at start-up and the run
measures an outage, not a threshold. Refused here rather than discovered 5
minutes into a run.

Prints the recording path on stdout, so the runner knows where to collect it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PARENTS = {
    'scoreonly': 'config/params_trust_scoreonly.yaml',
    'treat': 'config/params_trust_full.yaml',
}
ARM_RE = re.compile(r'^(?P<parent>[a-z]+)_t(?P<theta>\d{3})$')


class DeriveError(ValueError):
    pass


def parse_arm(arm: str):
    m = ARM_RE.match(arm)
    if not m or m.group('parent') not in PARENTS:
        raise DeriveError(
            f'{arm!r} is not a sweep arm: expected <{"|".join(PARENTS)}>_tNNN, '
            f'e.g. scoreonly_t045 for theta = 0.45')
    return m.group('parent'), int(m.group('theta')) / 100.0


def _replace_one(text: str, pattern: str, repl: str, what: str) -> str:
    new, n = re.subn(pattern, repl, text, count=0, flags=re.MULTILINE)
    if n != 1:
        raise DeriveError(f'expected exactly one {what} line in the parent config, found {n}')
    return new


def derive(arm: str, root: Path = Path('.')):
    """Return (config_text, record_path, theta) for a sweep arm."""
    parent, theta = parse_arm(arm)
    text = (root / PARENTS[parent]).read_text()

    m = re.search(r'^  initial_score:\s*([0-9.]+)[ \t]*$', text, flags=re.MULTILINE)
    if not m:
        raise DeriveError('parent config has no trust.initial_score')
    initial = float(m.group(1))
    if not 0.0 < theta <= initial:
        raise DeriveError(
            f'theta {theta:.2f} is outside (0, initial_score={initial:.2f}]: every '
            f'node starts at T={initial:.2f}, so this would quarantine the whole '
            f'fleet at start-up')

    record_path = f'data/events_{arm}.jsonl'
    text = _replace_one(text, r'^(  isolation_threshold:)[ \t]*[0-9.]+[ \t]*$',
                        rf'\g<1> {theta:.2f}', 'trust.isolation_threshold')
    text = _replace_one(text, r'^(    record_path:)[ \t]*\S+[ \t]*$',
                        rf'\g<1> {record_path}', 'controller.dashboard.record_path')
    header = (f'# DERIVED by tools/derive_config.py for arm {arm} -- do not edit.\n'
              f'# = {PARENTS[parent]} with isolation_threshold {theta:.2f} and '
              f'record_path {record_path}.\n#\n')
    return header + text, record_path, theta


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    arm, out = argv
    try:
        text, record_path, _ = derive(arm)
    except DeriveError as exc:
        print(f'derive_config: {exc}', file=sys.stderr)
        return 1
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(text)
    print(record_path)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
