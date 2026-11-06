"""SNMP credentials never on the command line (Phase 2, Task 5, R45): what `ps` or /proc/<pid>/cmdline shows of a net-snmp call.

snmp.walk, snmp.get and snmp.set_vars put only what is no secret into the argv (version, user, security level, protocols). The
community and the v3 passphrases go into a snmp.conf that snmp._run writes for this one call (defCommunity, defAuthPassphrase,
defPrivPassphrase), readable by the app user only (0600), in a directory of its own that SNMPCONFPATH names for the child process;
the directory is removed when the call ends, however it ends.

  * A conf line quotes its value and escapes what net-snmp's config parser unquotes (read_config.c copy_nword: inside quotes a
    backslash takes the next character literally), so net-snmp gets exactly the stored value: spaces, quotes, backslashes, "#" and
    umlauts included (copy_nword below is that rule, rebuilt from its description).
  * A NUL, CR or LF would end the conf line and could start a directive of its own: refused before any process starts, and the switch
    API refuses to store such an SNMP credential in the first place.
  * No SnmpError carries a secret: _run replaces each one (snmp._secrets) by "***".

Nothing here starts a process or touches the network: create_subprocess_exec hands out a switchfix.FakeProcess (spawn), which reads
the conf file at the moment of the start, as net-snmp would. The conf directories go to a directory under tmp_path instead of /dev/shm
(snmp.SHM_DIR), and every test ends with it empty again: no call leaves a conf file behind.
"""
import asyncio
import os
import stat
import tempfile

import pytest
from fastapi.testclient import TestClient

import auth
import config
import db
import main
import snmp
from switchfix import HOST, IF_ADMIN, IF_NAME, FakeProcess

V2C = {"snmp_version": "2c", "snmp_community": "ro-s3cret"}
V3 = {"snmp_version": "3", "snmp_user": "mon", "snmp_auth_proto": "SHA", "snmp_auth_pass": "a-s3cret", "snmp_priv_proto": "AES",
      "snmp_priv_pass": "p-s3cret"}
SYS_NAME = "1.3.6.1.2.1.1.5.0"
IF_ADMIN_1 = IF_ADMIN + ".1"
CALLS = {"walk": lambda c: snmp.walk(HOST, c, IF_NAME), "get": lambda c: snmp.get(HOST, c, [SYS_NAME]),
         "set_vars": lambda c: snmp.set_vars(HOST, c, [(IF_ADMIN_1, "i", "2")])}
# Every SNMP credential field of the switch form, read and RW identity: the ones main._validate checks for NUL, CR and LF.
SNMP_FIELDS = ("snmp_community", "snmp_user", "snmp_auth_pass", "snmp_priv_pass", "snmp_rw_community", "snmp_rw_user", "snmp_rw_auth_pass",
               "snmp_rw_priv_pass")


def copy_nword(s: str) -> str:
    """The value net-snmp's config parser takes from s, a quoted word (read_config.c copy_nword): it runs from the opening quote to the
    next quote that no backslash escapes, and a backslash takes the character after it literally. Nothing may follow the closing
    quote (net-snmp would ignore it, so a line that relied on it would not mean what it says)."""
    assert s[:1] == '"', s
    out, i = [], 1
    while i < len(s) and s[i] != '"':
        if s[i] == "\\" and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
        else:
            out.append(s[i])
            i += 1
    assert i < len(s), f"no closing quote in {s!r}"
    assert s[i + 1:] == "", f"text behind the closing quote in {s!r}"
    return "".join(out)


class _Spawn:
    """The faked create_subprocess_exec. At every start it records in `last` what the started process would see: (argv, env, the
    lines of <SNMPCONFPATH>/snmp.conf, that file's permission bits), in `dir_mode` the permission bits of the conf directory, and
    appends the argv to `started`. It hands out the process answer() set last, without one a process that prints nothing and
    exits 0."""

    def __init__(self):
        self.started: list[tuple] = []
        self.last: tuple | None = None
        self.dir_mode: int | None = None
        self._next = FakeProcess()

    def answer(self, proc: FakeProcess) -> FakeProcess:
        self._next = proc
        return proc

    async def exec(self, *argv, env=None, **kwargs) -> FakeProcess:
        self.started.append(argv)
        conf = os.path.join(env["SNMPCONFPATH"], "snmp.conf")
        with open(conf, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.last = (argv, env, lines, stat.S_IMODE(os.stat(conf).st_mode))
        self.dir_mode = stat.S_IMODE(os.stat(env["SNMPCONFPATH"]).st_mode)
        proc, self._next = self._next, FakeProcess()
        return proc


@pytest.fixture
def shm(tmp_path, monkeypatch) -> str:
    """A writable directory that stands in for /dev/shm (snmp.SHM_DIR). It must be empty again when the test ends."""
    path = tmp_path / "shm"
    path.mkdir()
    monkeypatch.setattr(snmp, "SHM_DIR", str(path))
    yield str(path)
    assert os.listdir(path) == [], "a conf directory outlived its call"


@pytest.fixture
def spawn(monkeypatch, shm) -> _Spawn:
    """The real snmp.walk / get / set_vars / _run; only the process they would start is faked (see _Spawn)."""
    spawner = _Spawn()
    monkeypatch.setattr(snmp.asyncio, "create_subprocess_exec", spawner.exec)
    return spawner


# ── The switch API, as in tests/test_switch_api.py (copied: an imported fixture trips ruff F401/F811) ─────────────────────────────
USER = {"username": "tester", "name": "Tester", "method": "local"}


def _never(*args, **kwargs):
    raise AssertionError("the scheduler must not start in a test (no background polling, no network)")


@pytest.fixture
def api(tmp_path, monkeypatch):
    """A TestClient on main.app against a fresh database under tmp_path (the app's own init_db); lifespan and scheduler never run."""
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    monkeypatch.setattr(main.scheduler, "start", _never)
    asyncio.run(db.init_db())
    main.app.dependency_overrides[auth.current_user] = lambda: USER
    try:
        yield TestClient(main.app, headers={"X-Requested-With": "SwitchView"})
    finally:
        main.app.dependency_overrides.pop(auth.current_user, None)


def body(**fields) -> dict:
    return {"name": "SW-VK-02", "host": "203.0.113.42", "zone": "VK", **fields}


def create(api, **fields) -> int:
    r = api.post("/api/switches", json=body(**fields))
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ── The tests of the plan ────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("cred, conf", [(V2C, ['defCommunity "ro-s3cret"']),
                                         (V3, ['defAuthPassphrase "a-s3cret"', 'defPrivPassphrase "p-s3cret"'])])
@pytest.mark.parametrize("call", ["walk", "get", "set_vars"])
async def test_no_secret_on_the_command_line(spawn, cred, conf, call):        # R45: Prozessliste
    await CALLS[call](cred)
    argv, env, seen, mode = spawn.last
    assert not any(s in a for a in argv for s in ("ro-s3cret", "a-s3cret", "p-s3cret"))
    assert seen == conf and mode == 0o600 and not os.path.exists(env["SNMPCONFPATH"])


@pytest.mark.parametrize("secret", ['a"b', "c\\d", "e f", "#g", "Ümläut-ß", 'x\\"y'])
def test_conf_escapes_what_net_snmp_unquotes(secret):                         # Review Focus 4
    (line,) = snmp._conf_lines({"snmp_version": "2c", "snmp_community": secret})
    assert line.startswith('defCommunity "') and copy_nword(line[len("defCommunity "):]) == secret


@pytest.mark.parametrize("bad", ["a\nb", "a\rb", "a\x00b"])
async def test_a_line_break_in_a_secret_never_starts_a_process(spawn, bad):
    with pytest.raises(snmp.SnmpError, match="Steuerzeichen"):
        await snmp.walk(HOST, {"snmp_version": "2c", "snmp_community": bad}, IF_NAME)
    assert spawn.started == []


async def test_errors_never_carry_a_secret(spawn):
    spawn.answer(FakeProcess(err=b"snmpget: Authentication failure (p-s3cret)\n", returncode=1))
    with pytest.raises(snmp.SnmpError) as e:
        await snmp.get(HOST, V3, [SYS_NAME])
    assert "p-s3cret" not in str(e.value) and "***" in str(e.value)


async def test_the_conf_dir_is_removed_on_timeout(spawn):
    proc = spawn.answer(FakeProcess(hang=True))
    with pytest.raises(snmp.SnmpError, match="Zeitüberschreitung"):
        await snmp.walk(HOST, V2C, IF_NAME, timeout=0.05)
    assert proc.killed and not os.path.exists(spawn.last[1]["SNMPCONFPATH"])


def test_switch_api_refuses_a_line_break_in_an_snmp_secret(api):             # Fixture wie tests/test_switch_api.py
    for r in (api.post("/api/switches", json=body(snmp_rw_community="a\nb")), api.put(f"/api/switches/{create(api)}", json=body(snmp_user="m\rx"))):
        assert r.status_code == 422 and "Zeilenumbrüche" in r.text


# ── Beyond the plan's list: each pins a rule of the task that the tests above leave open ─────────────────────────────────────────
@pytest.mark.parametrize("cred, argv, conf", [
    pytest.param({"snmp_version": "2c"}, ["-v2c"], ['defCommunity "public"'], id="v2c-without-community"),
    pytest.param({"snmp_version": "2c", "snmp_community": ""}, ["-v2c"], ['defCommunity "public"'], id="v2c-empty-community"),
    pytest.param(V2C, ["-v2c"], ['defCommunity "ro-s3cret"'], id="v2c"),
    pytest.param(V3, ["-v3", "-u", "mon", "-l", "authPriv", "-a", "SHA", "-x", "AES"],
                 ['defAuthPassphrase "a-s3cret"', 'defPrivPassphrase "p-s3cret"'], id="authPriv"),
    pytest.param({**V3, "snmp_priv_pass": ""}, ["-v3", "-u", "mon", "-l", "authNoPriv", "-a", "SHA"], ['defAuthPassphrase "a-s3cret"'],
                 id="authNoPriv"),
    pytest.param({**V3, "snmp_priv_proto": None}, ["-v3", "-u", "mon", "-l", "authNoPriv", "-a", "SHA"], ['defAuthPassphrase "a-s3cret"'],
                 id="authNoPriv-priv-pass-without-protocol"),
    pytest.param({**V3, "snmp_auth_pass": None}, ["-v3", "-u", "mon", "-l", "noAuthNoPriv"], [], id="noAuthNoPriv"),
    pytest.param({**V3, "snmp_auth_proto": None}, ["-v3", "-u", "mon", "-l", "noAuthNoPriv"], [], id="noAuthNoPriv-passes-without-auth-protocol"),
])
async def test_each_security_level_splits_into_argv_and_conf(spawn, cred, argv, conf):
    """The levels as before (authPriv with both pairs, authNoPriv with the auth pair, otherwise noAuthNoPriv): the argv keeps version,
    user, level and protocols, the conf gets exactly the passphrases that level uses, and noAuthNoPriv gets an empty file. The
    community "public" for a v2c cred without one is no secret, but goes the same way: net-snmp needs one."""
    assert snmp._auth_args(cred) == argv and snmp._conf_lines(cred) == conf
    await snmp.get(HOST, cred, [SYS_NAME])
    started, env, seen, mode = spawn.last
    assert started == ("snmpget", *argv, "-On", "-Oq", "-Oe", "-Ot", "-t", "3", "-r", "1", HOST, SYS_NAME)
    assert seen == conf and mode == 0o600 and spawn.dir_mode == 0o700
    assert env["MIBS"] == "" and os.path.basename(env["SNMPCONFPATH"]).startswith("switchview-snmp-")


@pytest.mark.parametrize("secret", ["a\tb", "\x01x\x7f", "  padded  ", "'single'", "ends with \\", "-v1", '"'])
def test_conf_takes_tabs_and_every_other_character(secret):
    """E20: only NUL, CR and LF end a conf line; every other character of a secret reaches net-snmp as it is, in all three directives."""
    v3 = {**V3, "snmp_auth_pass": secret, "snmp_priv_pass": secret}
    lines = snmp._conf_lines({"snmp_version": "2c", "snmp_community": secret}) + snmp._conf_lines(v3)
    assert [line.split(" ", 1)[0] for line in lines] == ["defCommunity", "defAuthPassphrase", "defPrivPassphrase"]
    assert all(copy_nword(line.split(" ", 1)[1]) == secret for line in lines)


@pytest.mark.parametrize("field", ["snmp_community", "snmp_auth_pass", "snmp_priv_pass"])
@pytest.mark.parametrize("bad", ["\n", "\r", "\x00"])
def test_every_conf_value_refuses_nul_cr_lf(field, bad):
    cred = {**(V2C if field == "snmp_community" else V3), field: f"x{bad}y"}
    with pytest.raises(snmp.SnmpError, match="^SNMP-Zugangsdaten enthalten ein unzulässiges Steuerzeichen$"):
        snmp._conf_lines(cred)


def test_secrets_are_the_passphrases_and_any_community_but_public():
    assert snmp._secrets(V2C) == ("ro-s3cret",)
    assert snmp._secrets(V3) == ("a-s3cret", "p-s3cret")
    assert snmp._secrets({**V3, "snmp_community": "c", "snmp_auth_pass": ""}) == ("c", "p-s3cret")
    for public in ("public", " PUBLIC ", "\tPublic\n", "", None):
        assert snmp._secrets({"snmp_version": "2c", "snmp_community": public}) == ()


async def test_a_secret_inside_a_longer_one_is_masked_whole(spawn):
    """Each secret becomes "***" in full, also when another secret is part of it (the longer one is masked first)."""
    cred = {**V3, "snmp_auth_pass": "s3cret", "snmp_priv_pass": "s3cret-and-more"}
    spawn.answer(FakeProcess(err=b"snmpget: decryption error with s3cret-and-more, auth s3cret\n", returncode=1))
    with pytest.raises(snmp.SnmpError) as e:
        await snmp.get(HOST, cred, [SYS_NAME])
    assert str(e.value) == "snmpget: decryption error with ***, auth ***"


async def test_a_community_public_is_not_masked(spawn):
    """R-T: "public" is no secret, and masking it would garble every message that names it."""
    spawn.answer(FakeProcess(err=b"Timeout: No Response from public-sw\n", returncode=1))
    with pytest.raises(snmp.SnmpError, match="^Timeout: No Response from public-sw$"):
        await snmp.get(HOST, {"snmp_version": "2c", "snmp_community": "public"}, [SYS_NAME])


async def test_the_conf_dir_is_removed_on_an_error_and_on_a_cancel(spawn):
    spawn.answer(FakeProcess(err=b"Timeout: No Response from 203.0.113.21\n", returncode=1))
    with pytest.raises(snmp.SnmpError):
        await snmp.set_vars(HOST, V2C, [(IF_ADMIN_1, "i", "2")])
    assert not os.path.exists(spawn.last[1]["SNMPCONFPATH"])
    spawn.answer(FakeProcess(hang=True))
    task = asyncio.create_task(snmp.walk(HOST, V3, IF_NAME))
    while len(spawn.started) < 2:
        await asyncio.sleep(0)
    assert os.path.exists(spawn.last[1]["SNMPCONFPATH"])
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not os.path.exists(spawn.last[1]["SNMPCONFPATH"])


@pytest.mark.parametrize("broken", ["no directory", "a conf file there already"])
async def test_a_conf_that_cannot_be_made_is_an_snmp_error_and_starts_nothing(spawn, shm, monkeypatch, broken):
    """A full temporary directory, or a snmp.conf that is there before the call writes its own (the call creates its file and never
    opens one that exists), is an SnmpError like any other failed call (the callers expect one), before a start; a directory made
    before the write failed is gone again (the shm fixture checks)."""
    made = tempfile.mkdtemp

    def mkdtemp(*args, **kwargs):
        if broken == "no directory":
            raise OSError(28, "No space left on device")
        path = made(*args, **kwargs)
        with open(os.path.join(path, "snmp.conf"), "w", encoding="utf-8") as f:
            f.write('defCommunity "planted"\n')
        return path

    monkeypatch.setattr(snmp.tempfile, "mkdtemp", mkdtemp)
    with pytest.raises(snmp.SnmpError, match="ließ sich nicht anlegen"):
        await snmp.set_vars(HOST, V2C, [(IF_ADMIN_1, "i", "2")])
    assert spawn.started == []


@pytest.mark.parametrize("usable", [True, False])
async def test_the_conf_dir_lives_in_ram_when_it_can(spawn, tmp_path, monkeypatch, usable):
    """In /dev/shm (snmp.SHM_DIR) when that is a writable directory, so the secret never reaches a disk; otherwise in the default
    temporary directory."""
    shm = tmp_path / "other-shm"
    if usable:
        shm.mkdir()
    monkeypatch.setattr(snmp, "SHM_DIR", str(shm))
    await snmp.walk(HOST, V2C, IF_NAME)
    conf_dir = spawn.last[1]["SNMPCONFPATH"]
    assert os.path.dirname(conf_dir) == (str(shm) if usable else tempfile.gettempdir())
    assert not os.path.exists(conf_dir)


async def test_an_inherited_snmpconfpath_is_replaced(spawn, monkeypatch):
    """Whatever SNMPCONFPATH the app was started with, net-snmp reads only the call's own directory."""
    monkeypatch.setenv("SNMPCONFPATH", "/etc/snmp")
    await snmp.get(HOST, V2C, [SYS_NAME])
    assert os.path.basename(spawn.last[1]["SNMPCONFPATH"]).startswith("switchview-snmp-")


@pytest.mark.parametrize("field", SNMP_FIELDS)
@pytest.mark.parametrize("bad", ["\n", "\r", "\x00"])
def test_every_snmp_credential_field_refuses_nul_cr_lf(api, field, bad):
    r = api.post("/api/switches", json=body(**{field: f"x{bad}y"}))
    assert r.status_code == 422 and "SNMP-Zugangsdaten dürfen keine Zeilenumbrüche oder Nullzeichen enthalten" in r.text
    assert api.get("/api/switches").json() == []      # the refused POST stored nothing
    sid = create(api, snmp_user="mon")
    r = api.put(f"/api/switches/{sid}", json=body(**{field: f"x{bad}y"}))
    assert r.status_code == 422 and "Zeilenumbrüche" in r.text
    assert api.get("/api/switches").json()[0]["snmp_user"] == "mon"     # the refused PUT changed nothing


def test_the_switch_api_takes_tabs_quotes_and_umlauts_in_snmp_secrets(api):
    assert create(api, snmp_community='a\t"b" \\c #ü', snmp_rw_auth_pass="x\ty") > 0
