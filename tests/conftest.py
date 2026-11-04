"""Shared fixtures. All SNMP/SSH I/O in this suite is mocked: tests never touch a switch or the net-snmp binaries."""
import pytest

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
