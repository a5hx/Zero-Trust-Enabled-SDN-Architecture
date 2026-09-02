"""Tests for the dashboard's trust-ledger panel.

The panel's whole claim is that the BROWSER re-derives the chain rather than
rendering a verdict the controller handed it. That claim is only worth
something if the browser's digest actually equals the controller's, so the
central test here runs the page's JavaScript under a real interpreter and
compares its output against `hashlib` over blocks built by the real
`blockchain.block.build_block`.

Two implementations of one definition is the drift this project guards against
everywhere else (`interval_report` vs the chart binning, `PRIO_QUARANTINE_DROP`
across three copies). Here the second implementation is deliberate -- an
independent check is the point -- so what is pinned is that they AGREE, over
real blocks including the genesis one, whose integral float timestamp is the
case a naive JSON.stringify gets wrong.

`quickjs` is optional; where it is missing these tests skip rather than fail,
the same way the Mininet-dependent tests do.
"""

import hashlib
import json
import re
import unittest
from pathlib import Path

from blockchain.block import build_block
from blockchain.ledger import Ledger
from contracts.block_schema import Block
from contracts.trust_update import TrustUpdate

HTML = Path('dashboard/index.html')


def source():
    return HTML.read_text()


def js_context():
    """Evaluate the page's script under quickjs with a minimal DOM stub."""
    try:
        import quickjs
    except ImportError:                      # pragma: no cover - env dependent
        raise unittest.SkipTest('quickjs not installed; cannot execute page JS')

    src = source()
    m = re.search(r"<script>\n'use strict';\n(.*)</script>", src, re.S)
    if not m:
        raise AssertionError('dashboard script block not found')

    shim = """
    var __els = {};
    function __mk(id) {
      return { id: id, _html: '', textContent: '', className: '', style: {},
        dataset: {}, onclick: null,
        get innerHTML(){ return this._html; },
        set innerHTML(v){ this._html = v; __scan(v); },
        querySelectorAll: function(){ return []; },
        querySelector: function(){ return null; },
        appendChild: function(){}, addEventListener: function(){},
        setAttribute: function(){},
        getBoundingClientRect: function(){
          return {left:0, top:0, width:360, height:118}; } };
    }
    function __scan(h) {
      var re = /id="([^"]+)"/g, mm;
      while ((mm = re.exec(h)) !== null) if (!__els[mm[1]]) __els[mm[1]] = __mk(mm[1]);
    }
    var document = {
      getElementById: function(id){ return __els[id] || (__els[id] = __mk(id)); },
      createElement: function(){ return __mk('_new'); },
      body: { appendChild: function(){} } };
    var window = { innerWidth: 1600 };
    var location = { search: '', port: '8081' };
    function URLSearchParams(){ return { has: function(){ return false; } }; }
    function fetch(){ return new Promise(function(){}); }
    function EventSource(){ return {}; }
    function requestAnimationFrame(){ return 0; }
    function setTimeout(){ return 0; }
    var console = { error: function(){}, log: function(){} };
    var performance = { now: function(){ return 0; } };
    """
    ctx = quickjs.Context()
    ctx.eval(shim)
    ctx.eval(m.group(1))
    return ctx


def _updates(n, seed=0):
    return [
        TrustUpdate(
            device_id=f'iot{seed + i + 1}', edge_node_id=f'srv{(i % 8) + 1}',
            timestamp=1754899200.123456 + i * 0.017,
            task_status=('success', 'timeout', 'failure')[i % 3],
            cpu_usage=0.1 * (i % 7), reported_cpu=0.05 * (i % 5),
            latency_ms=12.5 + i, trust_score_before=0.5, trust_score_after=0.61,
            anomaly_flag=bool(i % 4 == 0),
        )
        for i in range(n)
    ]


class TestBrowserDigestMatchesPython(unittest.TestCase):
    """The page's SHA-256 and preimage must equal contracts/block_schema.py's.

    If these ever diverge the panel does not merely look wrong -- it accuses a
    healthy chain of being tampered with, which is worse than showing nothing.
    """

    def setUp(self):
        self.ctx = js_context()

    def _js_hash(self, header):
        return self.ctx.eval(
            f'sha256Hex(blockPreimage({json.dumps(header)}))'
        )

    def _js_preimage(self, header):
        return self.ctx.eval(f'blockPreimage({json.dumps(header)})')

    @staticmethod
    def _header(b: Block):
        return {
            'index': b.index, 'timestamp': b.timestamp,
            'previous_hash': b.previous_hash, 'merkle_root': b.merkle_root,
            'proposer_id': b.proposer_id, 'raft_term': b.raft_term,
        }

    def test_sha256_matches_hashlib_on_plain_strings(self):
        for s in ['', 'a', 'abc', 'hello world', 'x' * 55, 'x' * 56, 'x' * 63,
                  'x' * 64, 'x' * 65, 'x' * 1000, 'srv1→iot7 ✓']:
            with self.subTest(s=s[:20]):
                self.assertEqual(
                    self.ctx.eval(f'sha256Hex({json.dumps(s)})'),
                    hashlib.sha256(s.encode()).hexdigest(),
                )

    def test_preimage_is_byte_identical_to_python_json_dumps(self):
        """The digest can only match if the string being hashed matches."""
        block = build_block(
            index=1, previous_hash='a' * 64, updates=_updates(10),
            timestamp=1754899200.123456,
        )
        header = self._header(block)
        self.assertEqual(
            self._js_preimage(header),
            json.dumps(header, sort_keys=True),
        )

    def test_genesis_hash_is_reproduced_in_the_browser(self):
        """The case a naive JSON.stringify gets wrong.

        Genesis pins its timestamp to 0.0 so every replica agrees on it
        (blockchain/ledger.py). Python renders that float as `0.0`, JavaScript
        as `0` -- different preimages, different digests. The page anchors the
        whole chain on this block, so getting it wrong would make block 1's
        link check fail on every healthy run.
        """
        genesis = Ledger()._chain[0]
        js = self.ctx.eval('sha256Hex(blockPreimage(GENESIS))')
        self.assertEqual(js, genesis.hash)
        # And the constants themselves agree with the real genesis block.
        self.assertEqual(self.ctx.eval('GENESIS.merkle_root'), genesis.merkle_root)
        self.assertEqual(self.ctx.eval('GENESIS.proposer_id'), genesis.proposer_id)
        self.assertEqual(self.ctx.eval('GENESIS.previous_hash'), genesis.previous_hash)

    def test_digests_match_over_a_real_appended_chain(self):
        """End to end: build a chain the way the controller does, then verify
        every block through the browser's implementation."""
        ledger = Ledger()
        blocks = []
        for i in range(1, 8):
            b = build_block(
                index=ledger.get_chain_length(),
                previous_hash=ledger._chain[-1].hash,
                updates=_updates(10, seed=i * 10),
            )
            self.assertTrue(ledger.append(b), f'block {i} rejected by the ledger')
            blocks.append(b)

        for b in blocks:
            with self.subTest(index=b.index):
                self.assertEqual(self._js_hash(self._header(b)), b.hash)

    def test_integral_timestamps_do_not_break_the_digest(self):
        """Genesis is not the only integral float that can occur; a block
        committed on an exact second boundary is the same hazard."""
        for ts in (0.0, 1.0, 1754899200.0, -0.0):
            with self.subTest(ts=ts):
                b = build_block(index=3, previous_hash='b' * 64,
                                updates=_updates(4), timestamp=ts)
                self.assertEqual(self._js_hash(self._header(b)), b.hash)


class TestChainVerificationLogic(unittest.TestCase):
    """verifyChain()'s three verdicts: valid, broken, and unknown."""

    def setUp(self):
        self.ctx = js_context()
        ledger = Ledger()
        self.blocks = []
        for i in range(1, 6):
            b = build_block(
                index=ledger.get_chain_length(),
                previous_hash=ledger._chain[-1].hash,
                updates=_updates(10, seed=i * 10),
            )
            ledger.append(b)
            self.blocks.append({
                'index': b.index, 'timestamp': b.timestamp,
                'previous_hash': b.previous_hash, 'merkle_root': b.merkle_root,
                'proposer_id': b.proposer_id, 'raft_term': b.raft_term,
                'hash': b.hash, 'num_updates': len(b.trust_updates),
                'commit_ms': 0.42,
            })

    def _load(self, blocks=None):
        self.ctx.eval(
            f'LEDGER.blocks = {json.dumps(blocks if blocks is not None else self.blocks)};'
        )

    def _verify(self):
        return json.loads(self.ctx.eval('JSON.stringify(verifyChain())'))

    def test_a_healthy_chain_verifies_completely(self):
        self._load()
        rows = self._verify()
        self.assertEqual(len(rows), 5)
        for r in rows:
            self.assertTrue(r['selfOk'], f"block {r['block']['index']} self-check failed")
            self.assertTrue(r['linkOk'], f"block {r['block']['index']} link failed")

    def test_block_one_is_anchored_against_a_locally_built_genesis(self):
        """The first block's link is checkable without the controller sending
        genesis: the page builds it. That is what makes the anchor independent."""
        self._load()
        rows = self._verify()
        self.assertEqual(rows[0]['block']['index'], 1)
        self.assertTrue(rows[0]['linkOk'])

    def test_a_mid_run_page_reports_unknown_rather_than_valid(self):
        """A dashboard opened mid-run holds a suffix of the chain. The oldest
        block it has cannot be linked to anything, and claiming it verified
        would overstate what this page actually checked."""
        self._load(self.blocks[2:])
        rows = self._verify()
        self.assertIsNone(rows[0]['linkOk'], 'unlinkable block claimed a verdict')
        self.assertTrue(rows[0]['selfOk'], 'its own digest is still checkable')
        for r in rows[1:]:
            self.assertTrue(r['linkOk'])

    def test_editing_a_block_breaks_it_and_everything_after_it(self):
        """The property the tamper button demonstrates."""
        tampered = [dict(b) for b in self.blocks]
        tampered[2]['merkle_root'] = '0' + tampered[2]['merkle_root'][1:]
        self._load(tampered)
        rows = self._verify()
        self.assertTrue(rows[0]['selfOk'] and rows[1]['selfOk'])
        self.assertTrue(rows[1]['linkOk'])
        # The edited block no longer hashes to the digest it shipped with...
        self.assertFalse(rows[2]['selfOk'], 'edited block still self-verified')
        # ...and its successor's previous_hash no longer matches what block 3
        # actually hashes to now.
        self.assertFalse(rows[3]['linkOk'], 'tamper did not propagate forward')

    def test_the_link_check_uses_the_recomputed_hash_not_the_shipped_one(self):
        """The subtle one, and the reason the panel is worth building.

        If the link check compared previous_hash against the predecessor's
        SHIPPED hash field, a tampered block would still look correctly linked
        to its successor -- the edit would show up only on the block itself and
        would not cascade. Comparing against the RECOMPUTED hash is what makes
        the chain tamper-evident rather than merely checksummed.
        """
        tampered = [dict(b) for b in self.blocks]
        tampered[1]['merkle_root'] = '0' + tampered[1]['merkle_root'][1:]
        self._load(tampered)
        rows = self._verify()
        # Block 2's own `hash` field is untouched and still equals block 3's
        # previous_hash -- so a shipped-hash comparison would pass here.
        self.assertEqual(tampered[1]['hash'], tampered[2]['previous_hash'])
        self.assertFalse(rows[2]['linkOk'],
                         'link check trusted the shipped hash instead of recomputing')

    def test_tamper_and_restore_round_trips(self):
        self._load()
        self.ctx.eval('LEDGER.maxPerBlock = 10; toggleTamper();')
        rows = self._verify()
        self.assertTrue(any(r['selfOk'] is False for r in rows),
                        'tamper button changed nothing')
        self.ctx.eval('toggleTamper();')
        rows = self._verify()
        for r in rows:
            self.assertTrue(r['selfOk'])
            self.assertTrue(r['linkOk'])


class TestLedgerPanelStructure(unittest.TestCase):
    def test_the_panel_and_its_hosts_exist(self):
        src = source()
        self.assertIn('Trust ledger', src)
        for el in ('id="ledgerHead"', 'id="chain"', 'id="ledgerFoot"'):
            self.assertIn(el, src)

    def test_the_block_event_is_actually_handled(self):
        """It was published for months and dropped on the floor -- the panel
        exists because nothing consumed it."""
        src = source()
        self.assertIn("case 'block':", src)
        self.assertIn('ledgerIngest', src)

    def test_the_two_verdicts_are_reported_separately(self):
        """The controller auditing itself and this page re-deriving the chain
        are different claims. Merging them into one green tick would throw away
        the only reason to compute the second one."""
        src = source()
        self.assertIn('controller: chain valid', src)
        self.assertIn('browser:', src)

    def test_no_raft_consensus_is_claimed_on_the_live_panel(self):
        """docs/RAFT.md: "Nothing in the running controller uses this yet."

        The live path is TimingCommitBackend(LocalLedgerBackend()) -- single
        replica, raft_term pinned to 0. A leader/term/quorum display next to
        live charts would assert consensus that is not running.
        """
        src = source()
        panel = src[src.index('// ---------------------------------------------------------- trust ledger'):
                    src.index('// -------------------------------------------------------- scaling panel')]
        for claim in ('leader', 'quorum', 'election', 'follower', 'candidate'):
            self.assertNotIn(claim, panel.lower(),
                             f'ledger panel references RAFT concept {claim!r}')

    def test_the_tamper_demo_cannot_touch_the_real_ledger(self):
        """A demo that mutated real state to prove immutability would refute
        itself. The edit is local and the caption says so."""
        src = source()
        tamper = src[src.index('function toggleTamper()'):src.index('let _ledgerTimer')]
        for verb in ('fetch(', 'XMLHttpRequest', 'sendBeacon', 'WebSocket'):
            self.assertNotIn(verb, tamper)
        self.assertIn("the controller's ledger is untouched", src)

    def test_replay_is_not_asked_for_a_ledger_verdict(self):
        """dashboard/replay.py builds a throwaway TrustState purely to satisfy
        NorthboundAPI's signature. Its ledger holds genesis and nothing else --
        no block from the recording is ever appended to it -- so /ledger/verify
        there answers `{valid: true, chain_length: 1}` about an empty chain.

        Rendering that beside a ribbon of the recording's real blocks would be
        a green tick for something that was never checked. The browser-side
        verification still runs on replay, since the block events carry their
        own headers.
        """
        src = source()
        boot = src[src.index("// The controller's own verdict"):
                   src.index("const es = new EventSource")]
        self.assertIn('if (!S.replay)', boot)
        self.assertIn("/ledger/verify", boot)
        # And the pill says so rather than going blank.
        self.assertIn('n/a in replay', src)

    def test_the_batch_size_has_a_replay_fallback(self):
        """With /ledger/verify not consulted on replay, the pending gauge has
        no denominator from config. The largest block observed is that
        denominator -- TrustState commits at exactly max_updates_per_block, and
        a final partial flush is smaller, so it cannot inflate the estimate."""
        src = source()
        self.assertIn('observedMax', src)
        self.assertIn("(observed)", src)

    def test_redraw_is_throttled_like_the_charts(self):
        """Blocks commit every max_updates_per_block-th report -- a few per
        second under load. Rebuilding the ribbon per event would let traffic
        slow the dashboard, the same self-inflicted DoS the charts avoid."""
        src = source()
        self.assertIn('scheduleLedgerRender', src)
        self.assertIn('_ledgerTimer', src)


class TestBlockEventCarriesTheHashPreimage(unittest.TestCase):
    """The browser can only recompute a digest if it receives the preimage."""

    def test_every_hashed_header_field_is_published(self):
        tb = Path('controller/trust_balancer.py').read_text()
        emit = tb[tb.index('def _on_block_committed'):
                  tb.index('# Called by northbound_api.py -- dashboard')]
        # Exactly the fields contracts/block_schema.py hashes.
        for field in ('index', 'timestamp', 'previous_hash', 'merkle_root',
                      'proposer_id', 'raft_term', 'hash'):
            self.assertIn(f'{field}=', emit, f'block event omits {field!r}')

    def test_the_published_fields_are_the_hashed_fields(self):
        """Pinned against compute_hash itself, so adding a field to the header
        without adding it to the event is a test failure rather than a panel
        that quietly reports every block as tampered."""
        schema = Path('contracts/block_schema.py').read_text()
        header = schema[schema.index('header = {'):schema.index('return hashlib')]
        fields = set(re.findall(r"'(\w+)':", header))
        tb = Path('controller/trust_balancer.py').read_text()
        emit = tb[tb.index('def _on_block_committed'):
                  tb.index('# Called by northbound_api.py -- dashboard')]
        for field in fields:
            self.assertIn(f'{field}=', emit,
                          f'{field} is inside the hash but is not published')

    def test_the_timestamp_is_not_rounded(self):
        """It is inside the digest. A rounded copy hashes to something else,
        and every browser-side check would fail on a healthy chain."""
        tb = Path('controller/trust_balancer.py').read_text()
        emit = tb[tb.index('def _on_block_committed'):
                  tb.index('# Called by northbound_api.py -- dashboard')]
        self.assertIn('timestamp=(block.timestamp if block is not None else None)', emit)
        self.assertNotIn('round(block.timestamp', emit)

    def test_a_rejected_block_publishes_no_header(self):
        tb = Path('controller/trust_balancer.py').read_text()
        emit = tb[tb.index('def _on_block_committed'):
                  tb.index('# Called by northbound_api.py -- dashboard')]
        self.assertIn('accepted=block is not None', emit)
        # Every header field plus `hash` is None-guarded: a rejected commit
        # returned no Block, so there is nothing to report and a plausible
        # blank would be worse than an explicit null.
        schema = Path('contracts/block_schema.py').read_text()
        header = schema[schema.index('header = {'):schema.index('return hashlib')]
        expected = len(set(re.findall(r"'(\w+)':", header))) + 1   # + hash
        self.assertEqual(emit.count('if block is not None else None'), expected)


if __name__ == '__main__':
    unittest.main()
