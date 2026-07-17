"""Graduated response: trust bands and OpenFlow-meter attachment.

Band classification is pure and tested directly. The meter-attachment tests run
against the real os-ken OF1.3 parser with a mocked datapath (same approach as
tests/test_quarantine_drop.py), so the asserted instructions are exactly what a
live switch would receive.
"""

from pathlib import Path
from unittest import mock

import pytest
import yaml
from os_ken.ofproto import ofproto_v1_3, ofproto_v1_3_parser

from controller.edge_selector import (
    BAND_FULL, BAND_QUARANTINED, BAND_RATE_LIMITED, NodeState, trust_band,
)


# --- pure band classification ------------------------------------------------

def _ns(trust, anomaly=0.0):
    return NodeState(node_id='srv1', trust=trust, cpu_load=0.2, latency_ms=10, anomaly=anomaly)


def test_band_full_when_trusted_and_calm():
    assert trust_band(_ns(0.8, 0.0)) == BAND_FULL


def test_band_rate_limited_on_mid_trust():
    # trust in [isolation=0.3, rate_limit_trust=0.5)
    assert trust_band(_ns(0.4, 0.0)) == BAND_RATE_LIMITED


def test_band_rate_limited_on_mild_anomaly():
    # anomaly in [anomaly_warn=0.25, gate=0.5), trust still healthy
    assert trust_band(_ns(0.8, 0.3)) == BAND_RATE_LIMITED


def test_band_quarantined_below_isolation():
    assert trust_band(_ns(0.2, 0.0)) == BAND_QUARANTINED


def test_band_quarantined_over_gate_beats_rate_limit():
    # A high anomaly must quarantine even if trust looks fine -- rails win.
    assert trust_band(_ns(0.9, 0.6)) == BAND_QUARANTINED


# --- meter attachment on VIP install ----------------------------------------

@pytest.fixture()
def app(tmp_path, monkeypatch):
    cfg = yaml.safe_load(Path('config/params_trust_demo.yaml').read_text())
    cfg['controller']['dashboard'] = {'enabled': False}
    cfg_path = tmp_path / 'params_test.yaml'
    cfg_path.write_text(yaml.safe_dump(cfg))
    monkeypatch.setenv('ZTSDN_CONFIG', str(cfg_path))
    from controller.trust_balancer import TrustBalancerApp
    return TrustBalancerApp()


def _fake_datapath(dpid=1):
    dp = mock.Mock()
    dp.id = dpid
    dp.ofproto = ofproto_v1_3
    dp.ofproto_parser = ofproto_v1_3_parser
    return dp


def _meter_instructions(mods):
    """All OFPInstructionMeter objects across the given flow-mods."""
    out = []
    for m in mods:
        for inst in (m.instructions or []):
            if type(inst).__name__ == 'OFPInstructionMeter':
                out.append(inst)
    return out


def _push_into_rate_limited_band(app, node_id):
    # One raw anomaly sample of 0.35 -> EMA 0.85*0.35 = 0.2975, which is in
    # [anomaly_warn=0.25, gate=0.5): rate-limited but not quarantined.
    app.state.set_anomaly_raw(node_id, 0.35)
    assert app.state.band(node_id) == BAND_RATE_LIMITED


def test_rate_limited_node_gets_metered_forward_flow(app):
    dp = _fake_datapath()
    app._datapaths = {dp.id: dp}
    app._meters_ok[dp.id] = True          # switch reported meter support
    _push_into_rate_limited_band(app, 'srv1')

    app._install_vip_pair(dp, '10.0.0.5', 5000, 'srv1')

    mods = [c.args[0] for c in dp.send_msg.call_args_list]
    meters = _meter_instructions(mods)
    # Exactly the forward flow is metered, with srv1's meter id (its index).
    assert len(meters) == 1
    assert meters[0].meter_id == app._meter_id_for('srv1') == 1


def test_full_trust_node_is_not_metered(app):
    dp = _fake_datapath()
    app._datapaths = {dp.id: dp}
    app._meters_ok[dp.id] = True
    # srv1 left at its healthy initial trust -> BAND_FULL.
    assert app.state.band('srv1') == BAND_FULL

    app._install_vip_pair(dp, '10.0.0.5', 5000, 'srv1')

    mods = [c.args[0] for c in dp.send_msg.call_args_list]
    assert _meter_instructions(mods) == []


def test_no_meter_when_switch_lacks_meter_support(app):
    dp = _fake_datapath()
    app._datapaths = {dp.id: dp}
    app._meters_ok[dp.id] = False         # probe said unsupported
    _push_into_rate_limited_band(app, 'srv1')

    app._install_vip_pair(dp, '10.0.0.5', 5000, 'srv1')

    mods = [c.args[0] for c in dp.send_msg.call_args_list]
    # Degrades gracefully to unmetered service rather than crashing.
    assert _meter_instructions(mods) == []


def test_install_meters_is_idempotent_per_switch(app):
    dp = _fake_datapath()
    app._install_meters(dp)
    first = len([c for c in dp.send_msg.call_args_list])
    app._install_meters(dp)               # second call must be a no-op
    assert len(dp.send_msg.call_args_list) == first
