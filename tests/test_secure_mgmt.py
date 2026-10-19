"""Task 4: the management surface and the device keys.

* The harness-facing POST endpoints (/register, /topology/links,
  /monitor/pause) refuse requests without the bearer token when one is
  configured -- on both arms' APIs -- and stay open when none is, so Mininet
  runs are unchanged.
* A config that names a token or key variable which is unset refuses to
  start rather than silently running unprotected.
* Per-device keys: a device's derived key admits it and only it, so an
  insider holding its own key can no longer answer for another device.
"""

import json
import threading
import urllib.error
import urllib.request

import pytest

from controller.northbound_api import NorthboundAPI
from controller.trust_state import TrustState
from security.admin_auth import (
    ADMIN_PATHS,
    SecretConfigError,
    admin_headers,
    derive_device_key,
    is_authorized,
    load_admin_token,
    resolve_shared_key_hex,
)
from security.authenticator import AUTH_DENY_BAD_RESPONSE, AuthError, Present80Authenticator
from security.present_cipher import encrypt_bytes

MASTER = bytes.fromhex('00112233445566778899')


class _App:
    def __init__(self, token=None):
        self.admin_token = token
        self.paused = False

    def record_link_params(self, links):
        return len(links)

    def pause_monitor(self):
        self.paused = True
        return True

    def set_node_concurrency(self, node_id, n):  # baseline arm's /register
        pass


def _post(base, path, body, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code


@pytest.fixture
def api():
    servers = []

    def start(token=None, arm='treatment'):
        app = _App(token)
        if arm == 'treatment':
            srv = NorthboundAPI(app=app, state=TrustState(node_ids=['srv1']),
                                host='127.0.0.1', port=0)
        else:
            from base_model.baseline_api import BaselineAPI
            srv = BaselineAPI(app=app, host='127.0.0.1', port=0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return app, f'http://127.0.0.1:{srv.server_address[1]}'

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


_BODIES = {
    '/register': {'node_id': 'srv1', 'concurrency': 2},
    '/topology/links': {'links': []},
    '/monitor/pause': {},
}


class TestAdminEndpoints:
    def test_the_protected_set_is_exactly_the_harness_endpoints(self) -> None:
        assert ADMIN_PATHS == set(_BODIES)

    @pytest.mark.parametrize('arm', ['treatment', 'baseline'])
    def test_refused_without_the_token(self, api, arm) -> None:
        app, base = api('s3cret', arm)
        for path, body in _BODIES.items():
            assert _post(base, path, body) == 401, path
            assert _post(base, path, body, token='wrong') == 401, path
        assert app.paused is False          # verification was NOT switched off

    @pytest.mark.parametrize('arm', ['treatment', 'baseline'])
    def test_accepted_with_the_token(self, api, arm) -> None:
        app, base = api('s3cret', arm)
        for path, body in _BODIES.items():
            assert _post(base, path, body, token='s3cret') == 200, path
        assert app.paused is True

    def test_open_when_no_token_is_configured(self, api) -> None:
        app, base = api(None)
        assert _post(base, '/monitor/pause', {}) == 200
        assert app.paused is True

    def test_device_endpoints_are_not_gated(self, api) -> None:
        _, base = api('s3cret')
        # /auth/challenge is a device endpoint: no admin token, normal answer.
        assert _post(base, '/auth/challenge', {'device_id': 'iot1'}) != 401


class TestSecretLoading:
    def test_no_token_named_means_none(self) -> None:
        assert load_admin_token({'controller': {}}) is None
        assert admin_headers({'controller': {}}) == {}

    def test_named_but_unset_refuses_to_start(self, monkeypatch) -> None:
        monkeypatch.delenv('ZT_TEST_TOKEN', raising=False)
        with pytest.raises(SecretConfigError):
            load_admin_token({'controller': {'admin_token_env': 'ZT_TEST_TOKEN'}})

    def test_named_and_set(self, monkeypatch) -> None:
        monkeypatch.setenv('ZT_TEST_TOKEN', 'abc')
        cfg = {'controller': {'admin_token_env': 'ZT_TEST_TOKEN'}}
        assert load_admin_token(cfg) == 'abc'
        assert admin_headers(cfg) == {'Authorization': 'Bearer abc'}

    def test_is_authorized(self) -> None:
        assert is_authorized(None, None)
        assert is_authorized('Bearer t', 't')
        assert not is_authorized(None, 't')
        assert not is_authorized('Bearer x', 't')

    def test_shared_key_env_wins_over_the_config_file(self, monkeypatch) -> None:
        monkeypatch.setenv('ZT_TEST_KEY', 'aabbccddeeff00112233')
        sec = {'shared_key_env': 'ZT_TEST_KEY', 'shared_key_hex': '00112233445566778899'}
        assert resolve_shared_key_hex(sec) == 'aabbccddeeff00112233'
        assert resolve_shared_key_hex({'shared_key_hex': 'ff' * 10}) == 'ff' * 10
        monkeypatch.delenv('ZT_TEST_KEY')
        with pytest.raises(SecretConfigError):
            resolve_shared_key_hex(sec)


class TestPerDeviceKeys:
    def _answer(self, auth, device_id, key, ip):
        nonce = auth.issue_challenge(device_id)
        return auth.verify_response(device_id, encrypt_bytes(key, nonce), ip)

    def test_derived_keys_are_distinct_and_80_bits(self) -> None:
        k1, k2 = derive_device_key(MASTER, 'iot1'), derive_device_key(MASTER, 'iot2')
        assert len(k1) == 10 and k1 != k2 and k1 != MASTER

    def test_a_device_is_admitted_with_its_own_key(self) -> None:
        auth = Present80Authenticator(MASTER, per_device=True)
        assert self._answer(auth, 'iot1', derive_device_key(MASTER, 'iot1'), '10.0.0.1')

    def test_the_master_key_alone_no_longer_works(self) -> None:
        auth = Present80Authenticator(MASTER, per_device=True)
        with pytest.raises(AuthError):
            self._answer(auth, 'iot1', MASTER, '10.0.0.1')

    def test_an_insider_cannot_answer_for_another_device(self) -> None:
        """The spoof live run 9 let through: iot38 answering as iot1. With
        per-device keys it fails on the cryptography itself, before the
        source-IP pin is even consulted."""
        auth = Present80Authenticator(MASTER, per_device=True)
        with pytest.raises(AuthError) as exc:
            self._answer(auth, 'iot1', derive_device_key(MASTER, 'iot38'), '10.0.0.38')
        assert exc.value.kind == AUTH_DENY_BAD_RESPONSE

    def test_fleet_mode_is_unchanged(self) -> None:
        auth = Present80Authenticator(MASTER)
        assert self._answer(auth, 'iot1', MASTER, '10.0.0.1')

    def test_the_harness_provisions_each_device_its_own_key(self) -> None:
        import re
        import yaml
        from simulation.topology import _launch_trust_agents

        class _Host:
            def __init__(self, name, sink):
                self.name, self.sink = name, sink

            def cmd(self, c):
                self.sink[self.name] = c

        class _Net:
            def __init__(self):
                self.cmds = {}

            def get(self, name):
                return _Host(name, self.cmds)

        with open('config/params_trust_full.yaml') as fh:
            cfg = yaml.safe_load(fh)
        cfg['security']['key_derivation'] = 'per_device'
        net = _Net()
        _launch_trust_agents(net, cfg)
        key = lambda d: re.search(r'ZTSDN_DEVICE_KEY=([0-9a-f]+)', net.cmds[d]).group(1)
        assert key('iot1') == derive_device_key(MASTER, 'iot1').hex()
        assert key('iot38') == derive_device_key(MASTER, 'iot38').hex()   # its own, not iot1's
        assert key('iot39') != derive_device_key(MASTER, 'iot39').hex()   # wrong-key device
