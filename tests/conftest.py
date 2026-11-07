"""Shared fixtures. All SNMP/SSH I/O in this suite is mocked: tests never touch a switch or the net-snmp binaries."""
import atexit
import os
import shutil
import tempfile

import pytest

# The environment of the app modules, set before any of them is imported: config.Settings reads SECRET_KEY and DATA_DIR once, at
# import, into a frozen dataclass, and pytest imports this file before any test module. Both are forced, not defaulted, so that a
# shell or container exporting the real ones (DATA_DIR=/data, the production SECRET_KEY) never reaches a test: crypto encrypts with
# a test-only key, and a db() that no test pointed at its own tmp_path opens a throwaway database, never /data/switchview.db.
# COOKIE_SECURE is forced to its default for the same reason (Settings reads it whenever one is made): a shell exporting
# COOKIE_SECURE=always would put the Secure flag on every cookie, and a TestClient on http://testserver never sends those back.
TEST_SECRET_KEY = "switchview-tests-only-secret-key"
TEST_DATA_DIR = tempfile.mkdtemp(prefix="switchview-tests-")
atexit.register(shutil.rmtree, TEST_DATA_DIR, True)
os.environ["SECRET_KEY"] = TEST_SECRET_KEY
os.environ["DATA_DIR"] = TEST_DATA_DIR
os.environ["COOKIE_SECURE"] = "auto"


@pytest.fixture(scope="session", autouse=True)
def _test_environment():
    """Fails the run if config was imported before the variables above were set: then they would not have taken effect."""
    import config
    s = config.settings
    assert (s.secret_key, s.data_dir, s.cookie_secure) == (TEST_SECRET_KEY, TEST_DATA_DIR, "auto")

# A `show running-config` of a modular ProCurve (24-port module in slot A), 15.x layout with global port-access lines.
# What it contains, because tests/test_cfgparse.py asserts on it by hand:
#   VLANs 1 (default), 20 "Clients", 30 "Voice" (voice VLAN), 99 "Guest"; LACP trunk Trk1 = A5-A6, tagged in 20/30/99;
#   A1 = untagged 20 + tagged 30, name "Platz-107", 802.1X with client-limit 2 and unauth-vid 99; A3 = disabled;
#   RADIUS host 203.0.113.10 with key and dyn-authorization. Lines the parser has to skip (header, ip address,
#   "no untagged", snmp-server, ...) are real syntax on purpose.
SAMPLE_RUNNING_CONFIG = """\
Running configuration:

; J8697A Configuration Editor; Created on release #K.15.99.0001
; Ver #0e:0f.2a.f0.f0:78
hostname "SW-EK-01"
module 1 type J8702A
trunk A5-A6 Trk1 LACP
ip default-gateway 203.0.113.1
snmp-server community "public" Unrestricted
vlan 1
   name "DEFAULT_VLAN"
   untagged A2-A4,A7-A24
   ip address 203.0.113.21 255.255.255.0
   no untagged Trk1
   exit
vlan 20
   name "Clients"
   untagged A1
   tagged Trk1
   exit
vlan 30
   name "Voice"
   tagged A1,Trk1
   voice
   exit
vlan 99
   name "Guest"
   tagged Trk1
   exit
interface A1
   name "Platz-107"
   exit
interface A3
   disable
   name "unused"
   exit
radius-server host 203.0.113.10 key "S3cr3tRadiusKey"
radius-server host 203.0.113.10 dyn-authorization
aaa authentication port-access eap-radius
aaa port-access authenticator A1
aaa port-access authenticator A1 client-limit 2
aaa port-access authenticator A1 unauth-vid 99
aaa port-access authenticator active
"""


@pytest.fixture
def sample_running_config() -> str:
    return SAMPLE_RUNNING_CONFIG


@pytest.fixture
def login_api(tmp_path, monkeypatch):
    """A TestClient on main.app that sends the CSRF header, without dependency_overrides: every request goes through the real login
    and session code. Its database is a fresh one under tmp_path, set up by the app's own init_db; the settings switch on the
    emergency account of loginfix.GOOD and SSO (tenant "t", client "c"); the login throttle is a fresh one, no JWKS reload, no
    failed JWKS fetch and no used SSO nonce is on record, and the scheduler is booby-trapped (apifix.never). The client is created
    without `with`, so the app's lifespan never runs. The app modules are imported here, not at the top, like in _test_environment."""
    import asyncio

    from fastapi.testclient import TestClient

    import apifix
    import auth
    import config
    import db
    import main
    import throttle
    from loginfix import CSRF, GOOD

    s = config.Settings(data_dir=str(tmp_path), admin_user=GOOD["username"], admin_password=GOOD["password"], entra_tenant_id="t",
                        entra_client_id="c")
    for module in (db, auth, main):
        monkeypatch.setattr(module, "settings", s)
    monkeypatch.setattr(main, "_LOGIN", throttle.LoginThrottle())
    monkeypatch.setattr(auth, "_jwks_refreshed", {})
    monkeypatch.setattr(auth, "_jwks_failed", {})
    monkeypatch.setattr(auth, "_used_nonces", {})    # every login of a test starts without a remembered SSO nonce
    monkeypatch.setattr(main.scheduler, "start", apifix.never)
    asyncio.run(db.init_db())
    return TestClient(main.app, headers=CSRF)


@pytest.fixture
def entra(monkeypatch):
    """The tenant "t" of login_api with one RS256 signing key, kid "k1", served by a JWKS client that never leaves the process.
    Returns sign(**claims): an id_token for client "c", signed with that key, with the given claims added or replaced. The modules
    are imported here, not at the top, like the app modules in login_api."""
    import json
    import time
    import types

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    import auth

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.PyJWK({**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key())), "kid": "k1", "use": "sig"})
    client = types.SimpleNamespace(get_signing_keys=lambda refresh=False: [jwk], match_kid=jwt.PyJWKClient.match_kid)
    monkeypatch.setattr(auth, "_jwks_client", lambda tenant: client)
    now = int(time.time())
    base = {"iss": "https://login.microsoftonline.com/t/v2.0", "tid": "t", "aud": "c", "sub": "s", "iat": now, "exp": now + 600}
    return lambda **claims: jwt.encode({**base, **claims}, private, algorithm="RS256", headers={"kid": "k1"})


@pytest.fixture
async def net(tmp_path, monkeypatch):
    """The test network of tests/netfix.py (tests/test_uplinks.py, tests/test_lldp_trust.py): a fresh database under tmp_path, set up
    by the app's own init_db; snmp.walk answered by a netfix.Network from recorded walks; fresh poll and change locks. Defined here so
    that the test files take it without importing it (ruff F401/F811); netfix is imported here, not at the top, like the app modules
    in login_api."""
    import netfix
    return await netfix.fresh_network(tmp_path, monkeypatch)


@pytest.fixture
def ssh_env(tmp_path, monkeypatch):
    """One ProCurve with SSH access behind a fake sshcli.connect (tests/sshfix.py, SshEnv): a fresh database under tmp_path, set up by
    the app's own init_db; fresh switch locks and R27 marks; re-polls recorded, never run. Defined here so that the test files take it
    without importing it (ruff F401/F811); sshfix is imported here, not at the top, like netfix in net."""
    import sshfix
    return sshfix.make_ssh_env(tmp_path, monkeypatch)
