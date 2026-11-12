"""Run dashboard/index.html's script under node, for the dashboard tests.

The page has no build step, so nothing parses or executes its script before a
browser does -- and one syntax error blanks every panel at once
(memory: dashboard-js-has-no-build-step). quickjs, which the ledger tests use,
is not installed on every machine; node is the more common interpreter, so
these helpers drive it instead and skip cleanly where it is missing.

Two entry points:

* `syntax_check()` -- parse the script without executing it.
* `run_events(events, driver_tail)` -- execute the real script against a small
  DOM stub, feed `events` through the page's own `handle()`, flush the
  throttled renderers, and return what the panels drew.
"""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

HTML = Path('dashboard/index.html')


def script_source() -> str:
    src = HTML.read_text()
    m = re.search(r"<script>\n'use strict';\n(.*)</script>", src, re.S)
    if not m:
        raise AssertionError('dashboard script block not found')
    return m.group(1)


def node_or_skip() -> str:
    node = shutil.which('node')
    if node is None:                         # pragma: no cover - env dependent
        raise unittest.SkipTest('node not installed; cannot parse/execute page JS')
    return node


def syntax_check() -> subprocess.CompletedProcess:
    """`node --check` over the extracted script. Parses, never executes."""
    node = node_or_skip()
    with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False) as f:
        f.write("'use strict';\n" + script_source())
        path = f.name
    try:
        return subprocess.run([node, '--check', path], capture_output=True, text=True,
                              timeout=60)
    finally:
        Path(path).unlink(missing_ok=True)


# A DOM just deep enough for the page's renderers. Elements remember their
# innerHTML, and any id="..." written into it becomes fetchable, as in a
# browser. setTimeout callbacks are queued and run by __flush(), so the
# throttled renderers (charts, ledger, security) can be driven synchronously.
_SHIM = r"""
var __els = {};
var __timers = [];
function __mk(id) {
  var e = { id: id, _html: '', textContent: '', className: '', style: {},
    dataset: {}, onclick: null, children: [], classList: { add: function(){},
      remove: function(){}, toggle: function(){} },
    get innerHTML(){ return this._html; },
    set innerHTML(v){ this._html = String(v); __scan(this._html); },
    get lastChild(){ return this.children[this.children.length - 1]; },
    querySelectorAll: function(){ return []; },
    querySelector: function(){ return null; },
    append: function(){}, appendChild: function(c){ this.children.push(c); },
    prepend: function(c){ this.children.unshift(c); c._parent = this; },
    remove: function(){ if (this._parent) { var i = this._parent.children.indexOf(this);
      if (i >= 0) this._parent.children.splice(i, 1); } },
    addEventListener: function(){}, setAttribute: function(){},
    getAttribute: function(){ return null; }, removeAttribute: function(){},
    getTotalLength: function(){ return 0; },
    getPointAtLength: function(){ return {x: 0, y: 0}; },
    getBoundingClientRect: function(){ return {left:0, top:0, width:360, height:118}; } };
  return e;
}
function __scan(h) {
  var re = /id="([^"]+)"/g, mm;
  while ((mm = re.exec(h)) !== null) if (!__els[mm[1]]) __els[mm[1]] = __mk(mm[1]);
}
var document = {
  getElementById: function(id){ return __els[id] || (__els[id] = __mk(id)); },
  createElement: function(){ return __mk('_new'); },
  createElementNS: function(){ return __mk('_ns'); },
  querySelector: function(){ return null; },
  querySelectorAll: function(){ return []; },
  body: { appendChild: function(){} } };
var window = { innerWidth: 1600, addEventListener: function(){} };
var location = { search: __SEARCH__, port: __PORT__ };
function fetch(){ return new Promise(function(){}); }
function EventSource(){ return {}; }
function requestAnimationFrame(){ return 0; }
function setTimeout(fn){ __timers.push(fn); return __timers.length; }
function setInterval(){ return 0; }
function clearTimeout(){}
var performance = { now: function(){ return 0; } };
function __flush() {
  for (var guard = 0; __timers.length && guard < 50; guard++) {
    var q = __timers; __timers = [];
    q.forEach(function(fn){ fn(); });
  }
}
"""

_DRIVER = r"""
var __fs = require('fs');
var __lines = __fs.readFileSync(__EVENTS__, 'utf8').split('\n');
var __errors = [];
var __seen = {};
for (var __i = 0; __i < __lines.length; __i++) {
  if (!__lines[__i].trim()) continue;
  var __ev;
  try { __ev = JSON.parse(__lines[__i]); } catch (e) { continue; }
  __seen[__ev.type] = (__seen[__ev.type] || 0) + 1;
  try { handle(__ev); }
  catch (e) {
    if (__errors.length < 20) __errors.push(__ev.type + ': ' + (e && e.stack || e));
  }
  if (__i % 500 === 0) { try { __flush(); } catch (e) { __errors.push('flush: ' + e.stack); } }
}
try { __flush(); } catch (e) { __errors.push('flush: ' + e.stack); }
var __out = { errors: __errors, seen: __seen, html: {} };
['witness', 'security', 'trust', 'ledgerCluster', 'ledgerHead', 'throttledPill',
 'logNote', 'balance'].forEach(function(id){
  var e = document.getElementById(id);
  __out.html[id] = e.innerHTML || e.textContent || '';
});
var __logBox = document.getElementById('log');
__out.log = __logBox.children.map(function(c){ return c.innerHTML; });
__out.alerts = document.getElementById('alerts').children.map(function(c){ return c.innerHTML; });
__out.state = { quarantined: Array.from(S.quarantined).sort(), qRail: S.qRail,
  held: Object.keys(WIT.held).sort(), labels: Object.keys(SEC.labels).sort(),
  denials: SEC.denials.length, routeIgnored: SEC.routeIgnored };
__TAIL__
process.stdout.write(JSON.stringify(__out));
"""


def run_events(events: Iterable[Dict[str, Any]], *, replay: bool = True,
               tail: str = '', timeout: int = 300) -> Dict[str, Any]:
    """Execute the page and push `events` through `handle()`.

    `replay=True` makes the page believe it is under dashboard/replay.py (the
    `?replay` flag), which is the mode every recorded-run test should use: no
    endpoint is polled, and the panels must stand on events alone.
    `tail` is extra JS run before the result is printed; it may add keys to
    `__out`.
    """
    node = node_or_skip()
    with tempfile.TemporaryDirectory() as d:
        ev_path = Path(d) / 'events.jsonl'
        with open(ev_path, 'w') as f:
            for ev in events:
                f.write(json.dumps(ev) + '\n')
        shim = (_SHIM.replace('__SEARCH__', json.dumps('?replay' if replay else ''))
                     .replace('__PORT__', json.dumps('8082' if replay else '8081')))
        # The page's own URLSearchParams use: `new URLSearchParams(location.search).has('replay')`.
        # node has a real URLSearchParams, so nothing to stub there.
        js = (shim + "\n'use strict';\n" + script_source() + '\n'
              + _DRIVER.replace('__EVENTS__', json.dumps(str(ev_path))).replace('__TAIL__', tail))
        js_path = Path(d) / 'page.js'
        js_path.write_text(js)
        proc = subprocess.run([node, str(js_path)], capture_output=True, text=True,
                              timeout=timeout)
    if proc.returncode != 0:
        raise AssertionError(f'page script failed under node:\n{proc.stderr[-4000:]}')
    return json.loads(proc.stdout)


def load_jsonl(path: Path, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if limit is not None and len(out) >= limit:
                break
    return out


# --------------------------------------------------------------------------- #
# A quickjs-shaped context on node                                             #
# --------------------------------------------------------------------------- #
_NODE_REPL = r"""
const vm = require('vm');
const readline = require('readline');
const ctx = vm.createContext({});
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', line => {
  let reply;
  try {
    const v = vm.runInContext(JSON.parse(line), ctx);
    reply = { ok: true, value: (v === undefined || typeof v === 'function') ? null : v };
    JSON.stringify(reply);
  } catch (e) {
    reply = { ok: false, error: String(e && e.stack || e) };
  }
  let out;
  try { out = JSON.stringify(reply); }
  catch (e) { out = JSON.stringify({ ok: true, value: null }); }
  process.stdout.write(out + '\n');
});
"""


class NodeContext:
    """`eval(code)` with quickjs.Context's semantics, on a node subprocess.

    Each call runs as a separate vm Script in ONE context, so top-level
    `const`/`let`/`function` declarations persist from call to call -- the
    page's script is evaluated once and later calls see its globals, exactly
    as under quickjs. Values come back through JSON, which covers what the
    tests ask for (strings, numbers, booleans, and JSON.stringify output).
    """

    def __init__(self) -> None:
        node = node_or_skip()
        self._proc = subprocess.Popen([node, '-e', _NODE_REPL], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, text=True, bufsize=1)

    def eval(self, code: str) -> Any:
        assert self._proc.stdin and self._proc.stdout
        self._proc.stdin.write(json.dumps(code) + '\n')
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            raise RuntimeError('node context exited')
        reply = json.loads(line)
        if not reply['ok']:
            raise RuntimeError(reply['error'])
        return reply['value']

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.stdin.close()            # type: ignore[union-attr]
            self._proc.wait(timeout=10)

    def __del__(self) -> None:                  # pragma: no cover - best effort
        try:
            self.close()
        except Exception:
            pass
