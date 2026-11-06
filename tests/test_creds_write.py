"""poller.creds_of(row, write=True): the single place that decides which SNMP identity a SET goes out with.

Spec anti-goal: read-only SNMP credentials never become write-capable silently. write=True therefore returns a cred only when the
switch has snmp_write on AND a real identity to write with, in this order:
  1. a separate RW identity: the v3 user snmp_rw_user (with snmp_rw_auth_* / snmp_rw_priv_*), which wins over the v2c
     snmp_rw_community;
  2. otherwise the read identity, but only a real one: v3 with a user, or v2c with a NON-EMPTY community;
and raises snmp.SnmpError with the reason otherwise. Above all it never returns a cred that snmp._conf_lines turns into the default
community "public" (it does that with an empty v2c community: right for polling, fatal for writing). A stored secret that does not
decrypt, and a v3 password that the call would silently not use (snmp._auth_args, snmp._conf_lines), are refusals too, never a quiet
fall back to another identity or a weaker security level. write=False is the read identity exactly as before. What a cred becomes for
net-snmp is checked in both parts (R45): the argv (_auth_args, no secret) and the call's snmp.conf (_conf_lines, the secrets).

Rows are plain dicts with the switches columns creds_of reads; secrets are stored the way the API stores them (crypto.encrypt with the
test SECRET_KEY of conftest.py).
"""
import itertools
import re

import pytest
from cryptography.fernet import Fernet

import crypto
import poller
import snmp

SECRETS = ("snmp_community", "snmp_auth_pass", "snmp_priv_pass", "snmp_rw_community", "snmp_rw_auth_pass", "snmp_rw_priv_pass")
OFF = "SNMP-Schreiben ist für diesen Switch nicht aktiviert"
NO_CREDS = "Keine SNMP-Schreib-Zugangsdaten hinterlegt"
PUBLIC = "Community 'public' wird nicht zum Schreiben verwendet – bitte eine eigene Schreib-Community hinterlegen"


def is_public(arg: str) -> bool:
    return arg.strip().lower() == "public"


def writes_public(cred: dict) -> bool:
    """Whether a call with cred hands net-snmp the community "public": in its argv, or as the value of its snmp.conf's defCommunity."""
    communities = [line[len('defCommunity "'):-1] for line in snmp._conf_lines(cred) if line.startswith("defCommunity ")]
    return any(is_public(a) for a in snmp._auth_args(cred) + communities)

RO, RW = "ro-c0mmunity", "rw-c0mmunity"
READ_V3 = {"snmp_version": "3", "snmp_user": "monitor", "snmp_auth_proto": "SHA", "snmp_auth_pass": "ro-auth-pass",
           "snmp_priv_proto": "AES", "snmp_priv_pass": "ro-priv-pass"}
RW_V3 = {"snmp_rw_user": "svwrite", "snmp_rw_auth_proto": "SHA-256", "snmp_rw_auth_pass": "rw-auth-pass",
         "snmp_rw_priv_proto": "AES-256", "snmp_rw_priv_pass": "rw-priv-pass"}


def row(raw: dict | None = None, **columns) -> dict:
    """A switches row: nothing set, snmp_write off, v2c. `columns` override, secrets given in plain text and stored encrypted; `raw`
    sets columns as stored, unencrypted (for secrets that do not decrypt)."""
    r = {"snmp_version": "2c", "snmp_community": None, "snmp_user": None, "snmp_auth_proto": None, "snmp_auth_pass": None,
         "snmp_priv_proto": None, "snmp_priv_pass": None, "snmp_write": 0, "snmp_rw_community": None, "snmp_rw_user": None,
         "snmp_rw_auth_proto": None, "snmp_rw_auth_pass": None, "snmp_rw_priv_proto": None, "snmp_rw_priv_pass": None}
    for k, v in columns.items():
        assert k in r, k
        r[k] = crypto.encrypt(v) if k in SECRETS and v is not None else v
    for k, v in (raw or {}).items():
        assert k in r, k
        r[k] = v
    return r


def v2c(community: str) -> dict:
    return {"snmp_version": "2c", "snmp_community": community, "snmp_user": None, "snmp_auth_proto": None, "snmp_auth_pass": None,
            "snmp_priv_proto": None, "snmp_priv_pass": None}


def v3(user: str, ap=None, apass=None, pp=None, ppass=None) -> dict:
    return {"snmp_version": "3", "snmp_community": None, "snmp_user": user, "snmp_auth_proto": ap, "snmp_auth_pass": apass,
            "snmp_priv_proto": pp, "snmp_priv_pass": ppass}


def v2c_call(community: str) -> tuple[list[str], list[str]]:
    """What a v2c cred becomes for net-snmp: the version in the argv, the community in the call's snmp.conf."""
    return ["-v2c"], [f'defCommunity "{community}"']


RW_V3_CRED = v3("svwrite", "SHA-256", "rw-auth-pass", "AES-256", "rw-priv-pass")
RW_V3_CALL = (["-v3", "-u", "svwrite", "-l", "authPriv", "-a", "SHA-256", "-x", "AES-256"],
              ['defAuthPassphrase "rw-auth-pass"', 'defPrivPassphrase "rw-priv-pass"'])
READ_V3_CRED = v3("monitor", "SHA", "ro-auth-pass", "AES", "ro-priv-pass")
READ_V3_CALL = (["-v3", "-u", "monitor", "-l", "authPriv", "-a", "SHA", "-x", "AES"],
                ['defAuthPassphrase "ro-auth-pass"', 'defPrivPassphrase "ro-priv-pass"'])

# (case, columns besides snmp_write=1, the write cred, (its net-snmp auth arguments, its snmp.conf lines))
WRITABLE = [
    ("rw v2c community", {"snmp_community": RO, "snmp_rw_community": RW}, v2c(RW), v2c_call(RW)),
    ("rw v3 user", {"snmp_community": RO, **RW_V3}, RW_V3_CRED, RW_V3_CALL),
    ("rw v3 wins over rw v2c", {"snmp_community": RO, "snmp_rw_community": RW, **RW_V3}, RW_V3_CRED, RW_V3_CALL),
    ("rw v3 beside a read v3", {**READ_V3, **RW_V3}, RW_V3_CRED, RW_V3_CALL),
    ("rw v2c beside a read v3", {**READ_V3, "snmp_rw_community": RW}, v2c(RW), v2c_call(RW)),
    ("rw v3 authNoPriv", {"snmp_rw_user": "svwrite", "snmp_rw_auth_proto": "SHA", "snmp_rw_auth_pass": "rw-auth-pass"},
     v3("svwrite", "SHA", "rw-auth-pass"), (["-v3", "-u", "svwrite", "-l", "authNoPriv", "-a", "SHA"], ['defAuthPassphrase "rw-auth-pass"'])),
    # the switch form always sends both protocol selects; without the passwords that is noAuthNoPriv, as _auth_args has it
    ("rw v3 noAuthNoPriv, protocols as the form leaves them", {"snmp_rw_user": "svwrite", "snmp_rw_auth_proto": "SHA",
     "snmp_rw_priv_proto": "AES"}, v3("svwrite", "SHA", None, "AES"), (["-v3", "-u", "svwrite", "-l", "noAuthNoPriv"], [])),
    ("empty rw user is no rw user", {"snmp_rw_user": "", "snmp_rw_community": RW}, v2c(RW), v2c_call(RW)),
    ("rw passwords without rw user are no rw identity", {"snmp_community": RO, "snmp_rw_auth_proto": "SHA",
     "snmp_rw_auth_pass": "rw-auth-pass"}, v2c(RO), v2c_call(RO)),
    ("read v2c community", {"snmp_community": RO}, v2c(RO), v2c_call(RO)),
    ("read v3 user", dict(READ_V3), READ_V3_CRED, READ_V3_CALL),
    ("read v2c, an unused v3 user beside it", {"snmp_community": RO, "snmp_user": "monitor", "snmp_auth_proto": "SHA",
     "snmp_auth_pass": "ro-auth-pass"}, v2c(RO), v2c_call(RO)),
    # R25 refuses the community "public" only where it would write: "private" is a community like any other (shown insecure)
    ("rw v2c 'private'", {"snmp_rw_community": "private"}, v2c("private"), v2c_call("private")),
    ("read v2c 'private'", {"snmp_community": "private"}, v2c("private"), v2c_call("private")),
    # ... and a "public" that does not write is no reason to refuse: the rw v3 user wins over the community, which stays unread
    ("rw v3 wins over a rw 'public'", {"snmp_rw_community": "public", **RW_V3}, RW_V3_CRED, RW_V3_CALL),
    ("read v3, an unused read 'public' beside it", {**READ_V3, "snmp_community": "public"}, READ_V3_CRED, READ_V3_CALL),
]


@pytest.mark.parametrize("columns, cred, call", [c[1:] for c in WRITABLE], ids=[c[0] for c in WRITABLE])
def test_write_identity(columns, cred, call):
    r = row(snmp_write=1, **columns)

    got = poller.creds_of(r, write=True)

    assert got == cred
    assert (snmp._auth_args(got), snmp._conf_lines(got)) == call
    assert not writes_public(got)


# (case, columns besides snmp_write=1): R25, the community "public" (any case, surrounding blanks) never writes
PUBLIC_REFUSED = [
    ("rw 'public'", {"snmp_rw_community": "public"}),
    ("rw 'PUBLIC'", {"snmp_rw_community": "PUBLIC"}),
    ("rw ' public '", {"snmp_rw_community": " public "}),
    ("rw 'Public' between tab and newline", {"snmp_rw_community": "\tPublic\n"}),
    ("rw 'public' beside a real read community", {"snmp_community": RO, "snmp_rw_community": "public"}),   # no fall back to it
    ("rw 'public' beside a read v3 user", {**READ_V3, "snmp_rw_community": "public"}),
    ("read fallback 'public'", {"snmp_community": "public"}),
    ("read fallback ' PUBLIC'", {"snmp_community": " PUBLIC"}),
]


@pytest.mark.parametrize("columns", [c[1] for c in PUBLIC_REFUSED], ids=[c[0] for c in PUBLIC_REFUSED])
def test_community_public_never_writes(columns):
    with pytest.raises(snmp.SnmpError) as e:
        poller.creds_of(row(snmp_write=1, **columns), write=True)
    assert str(e.value) == PUBLIC


# (case, columns besides snmp_write=1): no identity to write with
NO_IDENTITY = [
    ("nothing at all", {}),
    ("read v2c with an empty community", {"snmp_community": ""}),
    ("read v3 without a user, a community beside it", {"snmp_version": "3", "snmp_community": RO}),
    ("read v3 with an empty user", {"snmp_version": "3", "snmp_user": "", "snmp_auth_proto": "SHA", "snmp_auth_pass": "x" * 8}),
    ("read v2c without a community, only a v3 user", {"snmp_user": "monitor", "snmp_auth_proto": "SHA", "snmp_auth_pass": "x" * 8}),
    ("empty rw user, nothing else", {"snmp_rw_user": ""}),
    ("rw passwords without a rw user, nothing else", {"snmp_rw_auth_proto": "SHA", "snmp_rw_auth_pass": "rw-auth-pass"}),
]


@pytest.mark.parametrize("columns", [c[1] for c in NO_IDENTITY], ids=[c[0] for c in NO_IDENTITY])
def test_write_refused_without_an_identity(columns):
    """Above all the first two: _conf_lines would write with the community "public"."""
    with pytest.raises(snmp.SnmpError) as e:
        poller.creds_of(row(snmp_write=1, **columns), write=True)
    assert str(e.value) == NO_CREDS


@pytest.mark.parametrize("snmp_write", [0, None, False])
@pytest.mark.parametrize("columns", [c[1] for c in WRITABLE], ids=[c[0] for c in WRITABLE])
def test_write_refused_while_snmp_write_is_off(columns, snmp_write):
    with pytest.raises(snmp.SnmpError) as e:
        poller.creds_of(row(snmp_write=snmp_write, **columns), write=True)
    assert str(e.value) == OFF


FOREIGN_TOKEN = Fernet(Fernet.generate_key()).encrypt(b"rw-c0mmunity").decode()    # encrypted under another SECRET_KEY

# (case, columns besides snmp_write=1, columns stored as is): a secret of the chosen identity that does not decrypt
UNREADABLE = [
    ("rw community", {"snmp_community": RO}, {"snmp_rw_community": FOREIGN_TOKEN}),     # never the read community instead
    ("rw community, not even a token", {"snmp_community": RO}, {"snmp_rw_community": "not-a-fernet-token"}),
    ("rw v3 auth password", {**RW_V3, "snmp_community": RO}, {"snmp_rw_auth_pass": FOREIGN_TOKEN}),  # never noAuthNoPriv instead
    ("rw v3 priv password", dict(RW_V3), {"snmp_rw_priv_pass": FOREIGN_TOKEN}),    # never authNoPriv instead
    ("read community", {}, {"snmp_community": FOREIGN_TOKEN}),     # never "public" instead
    ("read v3 auth password", dict(READ_V3), {"snmp_auth_pass": FOREIGN_TOKEN}),
]


@pytest.mark.parametrize("columns, raw", [c[1:] for c in UNREADABLE], ids=[c[0] for c in UNREADABLE])
def test_write_refused_when_a_secret_does_not_decrypt(columns, raw):
    r = row(raw, snmp_write=1, **columns)
    with pytest.raises(snmp.SnmpError, match="lässt sich nicht entschlüsseln"):
        poller.creds_of(r, write=True)


def test_an_unreadable_rw_community_behind_a_rw_v3_user_is_not_used():
    """The v3 user wins, so the community is never decrypted and cannot fail."""
    r = row({"snmp_rw_community": FOREIGN_TOKEN}, snmp_write=1, **RW_V3)
    assert poller.creds_of(r, write=True) == RW_V3_CRED


# (case, columns besides snmp_write=1): a v3 password that _auth_args would leave out, writing at a lower level than configured
UNUSED_PASSWORD = [
    ("rw auth password without auth protocol", {"snmp_rw_user": "svwrite", "snmp_rw_auth_pass": "rw-auth-pass"}),
    ("rw priv password without priv protocol", {"snmp_rw_user": "svwrite", "snmp_rw_auth_proto": "SHA",
                                                 "snmp_rw_auth_pass": "rw-auth-pass", "snmp_rw_priv_pass": "rw-priv-pass"}),
    ("rw priv without auth", {"snmp_rw_user": "svwrite", "snmp_rw_priv_proto": "AES", "snmp_rw_priv_pass": "rw-priv-pass"}),
    ("rw priv with an auth protocol but no auth password", {"snmp_rw_user": "svwrite", "snmp_rw_auth_proto": "SHA",
                                                            "snmp_rw_priv_proto": "AES", "snmp_rw_priv_pass": "rw-priv-pass"}),
    ("read auth password without auth protocol", {"snmp_version": "3", "snmp_user": "monitor", "snmp_auth_pass": "ro-auth-pass"}),
]


@pytest.mark.parametrize("columns", [c[1] for c in UNUSED_PASSWORD], ids=[c[0] for c in UNUSED_PASSWORD])
def test_write_refused_when_a_v3_password_would_go_unused(columns):
    with pytest.raises(snmp.SnmpError, match="unvollständig"):
        poller.creds_of(row(snmp_write=1, **columns), write=True)


def test_read_identity_is_unchanged():
    """write=False is today's creds_of: the read identity, decrypted, whatever the RW columns and snmp_write say."""
    want = {"snmp_version": "2c", "snmp_community": RO, "snmp_user": "monitor", "snmp_auth_proto": "SHA", "snmp_auth_pass": None,
            "snmp_priv_proto": "AES", "snmp_priv_pass": None}
    for r in (row(snmp_community=RO, snmp_user="monitor", snmp_auth_proto="SHA", snmp_priv_proto="AES"),
              row(snmp_community=RO, snmp_user="monitor", snmp_auth_proto="SHA", snmp_priv_proto="AES", snmp_write=1,
                  snmp_rw_community=RW, **RW_V3)):
        assert poller.creds_of(r) == want
        assert poller.creds_of(r, write=False) == want
    assert poller.creds_of(row(**READ_V3, snmp_write=1, **RW_V3)) == READ_V3_CRED
    # an empty community stays what it always was for polling (snmp._conf_lines reads it as "public"): write=True alone refuses it
    assert poller.creds_of(row()) == v2c(None)
    assert poller.creds_of(row({"snmp_community": FOREIGN_TOKEN}))["snmp_community"] is None


@pytest.mark.parametrize("raw, want", [
    ({"snmp_community": ""}, None),                                          # "" as stored by hand or by an old release
    ({"snmp_rw_community": "", "snmp_community": crypto.encrypt(RO)}, v2c(RO)),
    ({"snmp_rw_user": "", "snmp_rw_community": crypto.encrypt(RW)}, v2c(RW)),
])
def test_empty_strings_are_unset(raw, want):
    r = row(raw, snmp_write=1)
    if want is None:
        with pytest.raises(snmp.SnmpError, match=NO_CREDS):
            poller.creds_of(r, write=True)
    else:
        assert poller.creds_of(r, write=True) == want


def _oracle(write, version, ro, user, read_auth, rw, rw_user, rw_auth, rw_priv):
    """What write=True must yield for a combination, written as the spec's decision table: (cred, None) or (None, reason fragment)."""
    if not write:
        return None, OFF
    if rw_user:                                    # 1. a separate RW identity: the v3 user first ...
        if rw_priv and not rw_auth:
            return None, "unvollständig"
        return v3("svwrite", *(rw_auth or (None, None)), *(rw_priv or (None, None))), None
    if rw:                                         # ... then the v2c community, never "public" (R25)
        return (None, PUBLIC) if is_public(rw) else (v2c(rw), None)
    if version == "3" and user:                    # 2. the read identity, if it is a real one
        return v3("monitor", *(read_auth or (None, None))), None
    if version == "2c" and ro:
        return (None, PUBLIC) if is_public(ro) else (v2c(ro), None)
    return None, NO_CREDS


def test_write_identity_exhaustively():
    """Every combination of the identity columns, against the decision table: never a "public", never a default user, never the
    read identity while a RW identity is configured, and write=False untouched by any RW column."""
    combos = itertools.product((0, 1), ("2c", "3"), (None, RO, "public"), (None, "monitor"), (None, ("SHA", "ro-auth-pass")),
                               (None, RW, " PUBLIC "), (None, "", "svwrite"), (None, ("SHA-256", "rw-auth-pass")),
                               (None, ("AES", "rw-priv-pass")))
    seen = {"cred": 0, "refused": 0}
    for write, version, ro, user, read_auth, rw, rw_user, rw_auth, rw_priv in combos:
        r = row(snmp_write=write, snmp_version=version, snmp_community=ro, snmp_user=user, snmp_rw_community=rw, snmp_rw_user=rw_user)
        for prefix, pair in (("snmp_auth", read_auth), ("snmp_rw_auth", rw_auth), ("snmp_rw_priv", rw_priv)):
            if pair:
                r[prefix + "_proto"], r[prefix + "_pass"] = pair[0], crypto.encrypt(pair[1])
        want, reason = _oracle(write, version, ro, user, read_auth, rw, rw_user, rw_auth, rw_priv)
        case = (write, version, ro, user, read_auth, rw, rw_user, rw_auth, rw_priv)
        if reason:
            with pytest.raises(snmp.SnmpError, match=re.escape(reason)):
                poller.creds_of(r, write=True)
            seen[reason] = seen.get(reason, 0) + 1
            seen["refused"] += 1
        else:
            got = poller.creds_of(r, write=True)
            assert got == want, case
            args, conf = snmp._auth_args(got), snmp._conf_lines(got)
            assert not writes_public(got), case
            assert (got["snmp_community"] in (RO, RW)) if got["snmp_version"] == "2c" else (got["snmp_user"] in ("monitor", "svwrite"))
            if rw_user or rw:
                assert f'defCommunity "{RW}"' in conf or "svwrite" in args, case
            seen["cred"] += 1
        read = poller.creds_of(r)
        assert read["snmp_version"] == version and read["snmp_community"] == ro and read["snmp_user"] == user, case
    assert seen["cred"] > 100 and seen["refused"] > 100 and seen[PUBLIC] > 50, seen
