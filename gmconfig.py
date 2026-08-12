#!/usr/bin/env python3
r"""
gmconfig - the single source of truth for which machines exist.

Everything reads this one file: the SSH bootstrapper, the health checker, the
tray dashboard. Add a machine here and it appears in all three; there is no
second list to keep in sync, which is the usual way a fleet monitor ends up
quietly not watching the newest box.

    <app dir>/machines.json   (next to the exe when frozen; see gmpaths)

The `gpu` field is deliberately DETECTED, not declared. Host names may suggest
which boxes have cards but names lie - a machine gets repurposed, a card gets
pulled - and a monitor that decides "this is a GPU machine" from a string will
cheerfully report a healthy nvidia-smi on a box that has no GPU, or skip the
check on one that does. Bootstrap and the health checker set it from what
nvidia-smi actually says, and `null` means "not yet determined". GPU checks are
entirely optional and per-machine; a fleet with no GPUs never touches them.

`scope` decides whether the network gate applies:
  local  - reachable only from a private network you have told the gate about.
           Polled ONLY when you are on a known network. Off that network a
           private address (10.x / 172.16.x / 192.168.x) is either unroutable
           or, worse, somebody else's machine, so probing would be both useless
           and rude - and would report the whole fleet as down for no reason.
  public - reachable from anywhere on the internet. ALWAYS polled; the gate
           is irrelevant to it, and skipping it while off-network would mean
           missing a genuine outage.

`bootstrapped` records that key auth has been verified. It exists because a
FAILED key auth still counts toward fail2ban: offering our key to a machine
that has never seen it is not a free read-only probe, it is a failed login
that can get us banned. So we only ever attempt key auth where we have
evidence it should work.
"""

import copy, json, os, re, sys, ipaddress

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gmpaths

# Next to the exe when frozen, next to this file when running from source.
# See gmpaths - getting this wrong makes every saved setting vanish on exit.
CONFIG_PATH = os.path.join(gmpaths.APP_DIR, "machines.json")

DEFAULTS = {
    "version": 1,
    # Local machines are polled only when you are on one of these networks. Off
    # them a private address is either unroutable or, worse, SOMEONE ELSE'S
    # machine - so probing would be both useless and rude. Empty by default:
    # add your own networks, or mark machines "public" if they are reachable
    # from anywhere. Used only by the legacy public-IP fallback below.
    "gate_domains": [],
    # HOW THE GATE ACTUALLY DECIDES, as of the local-gate change. Each entry is
    # {name, gateway_mac, gateway_ip} learned by running `--learn-gate` while
    # standing on that network. Matching the current default gateway's MAC
    # answers "am I home?" with no packet leaving the machine - where the old
    # answer cost a request to api.ipify.org every poll. Empty means the gate
    # cannot tell where we are, and local machines go unpolled until you learn
    # a network here. See gmcheck.gate_ok.
    "gate_fingerprints": [],
    # The old public-IP gate, kept but OFF. Turning it on restores a request to
    # a third party on every poll cycle - a standing presence beacon for
    # wherever you are - so it is a deliberate choice, not a silent fallback. The "my
    # public IP" button in the stealth tab still works regardless; that one is
    # you asking, which is the difference that matters.
    "gate_public_ip_fallback": False,
    # fail2ban ignoreip pushed to every machine. The machines see the monitoring
    # host's address on their own network, so these are the ranges that matter.
    # Loopback plus the RFC1918 private ranges are safe generic defaults.
    "allowlist": ["127.0.0.1/8", "::1",
                  "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "poll_seconds": 120,
    "ssh_timeout": 12,
    # Name of a machine in `machines` used to reach local machines that have no
    # explicit `via`. Empty means every machine is reached directly. See
    # sshconn.py for why a relay is sometimes the gentler design.
    "jump_host": "",
    # Any SSH session from outside these ranges, or as a user not listed here,
    # is reported as a possible intrusion rather than ignored. Empty
    # expected_login_users means "do not judge on username, only on source".
    "expected_login_cidrs": ["127.0.0.0/8",
                             "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "expected_login_users": ["root"],
    # Start with Windows. THE SETTING WINS: gmautostart reconciles the registry
    # to this value on every launch, in both directions, so turning it off here
    # (or from the tray menu) stays off instead of being quietly re-registered
    # by the next start. A monitor nobody remembered to launch is a monitor
    # that was not watching, so the default is on.
    "autostart": True,
    # The same "is anyone else in here?" question, asked about THIS laptop -
    # the one machine the SSH checks can never see. See gmlocal.py.
    "local_watch": {
        "enabled": True,
        # Faster than the fleet: this costs no network, and an inbound
        # connection can open and close inside a two-minute fleet cycle.
        "poll_seconds": 60,
        # Signatures that make a binary part of the OS rather than merely
        # software. Empty means gmlocal's built-in Microsoft list.
        "trusted_publishers": [],
        # Full image paths you have judged and accepted. This is the one knob
        # that silences a row for good, so it holds paths rather than process
        # names - names are trivially reused, paths are not.
        "trusted_images": [],
        # Extra peers that are us. The fleet in `machines` and the gate
        # networks are already trusted without being listed here.
        "trusted_peers": [],
        # An unrecognised process calling OUT is the usual shape of a
        # compromise, so it alerts by default.
        "alert_outbound": True,
        # Processes we could not identify at all are NOT alerted by default:
        # unelevated, that is every SYSTEM-owned non-service process on the
        # box, and a nightly toast listing lsass and wininit would train you
        # to dismiss the one that matters.
        "alert_unverified": False,
    },
    "machines": [],
}

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,30}$")
SCOPES = {"local", "public"}


class ConfigError(Exception):
    pass


def validate_machine(name, ip, user, alias=None):
    if not NAME_RE.match(name or ""):
        raise ConfigError(f"bad name {name!r}: letters/digits/.-_ only")
    # A machine reached by alias through a relay legitimately has no IP we
    # know - the relay's ssh config resolves it. Demanding one would force a
    # placeholder, and placeholders collide with each other and read as real.
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ConfigError(f"bad IP {ip!r}")
    elif not alias:
        raise ConfigError(f"{name}: needs either an IP or an alias+via relay")
    if not re.match(r"^[a-z_][a-z0-9_-]*$", user or ""):
        raise ConfigError(f"bad username {user!r}")


def exists(path=CONFIG_PATH):
    """Whether there is a config file at all.

    `load()` deliberately falls back to defaults with an empty fleet so the app
    can start and be configured. But "no config file" and "a config listing
    zero machines" must never render the same: the first is a broken install
    and the second is a deliberate state, and reporting either as a healthy
    fleet is an all-clear nobody earned."""
    return os.path.isfile(path)


def load(path=CONFIG_PATH):
    # Defaults are DEEP-COPIED in. Handing out the module-level objects means
    # every config that omits a key shares one list, so appending a trusted
    # image would edit DEFAULTS itself and leak into the next load in this
    # process - a setting that appears from nowhere and cannot be found in any
    # file is the worst kind of bug to chase.
    if not os.path.isfile(path):
        return copy.deepcopy(dict(DEFAULTS, machines=[]))
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    for k, v in DEFAULTS.items():
        data.setdefault(k, copy.deepcopy(v))
    return data


def save(data, path=CONFIG_PATH):
    """Write via a temp file and replace, so an interrupted write cannot leave
    a truncated machines.json - which would silently empty the fleet."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")
    os.replace(tmp, path)


def find(data, key):
    key = (key or "").strip().lower()
    if not key:
        return None
    for m in data["machines"]:
        if m["name"].lower() == key or (m.get("ip") and m["ip"] == key):
            return m
    return None


def add(data, name, ip, user, gpu=None, enabled=True, scope="local",
        via=None, alias=None):
    validate_machine(name, ip, user, alias)
    if scope not in SCOPES:
        raise ConfigError(f"scope must be one of {sorted(SCOPES)}")
    if find(data, name):
        raise ConfigError(f"{name} already exists - use 'remove' first")
    if ip and find(data, ip):
        raise ConfigError(f"{ip} is already registered as "
                          f"{find(data, ip)['name']}")
    data["machines"].append({"name": name, "ip": ip, "user": user,
                             "scope": scope, "via": via, "alias": alias,
                             "gpu": gpu, "enabled": enabled,
                             "bootstrapped": False})
    return data


def remove(data, key):
    m = find(data, key)
    if not m:
        raise ConfigError(f"no machine matches {key!r}")
    data["machines"].remove(m)
    return m


def set_enabled(data, key, on):
    m = find(data, key)
    if not m:
        raise ConfigError(f"no machine matches {key!r}")
    m["enabled"] = bool(on)
    return m


def active(data):
    """Every machine that is enabled, regardless of the gate."""
    return [m for m in data["machines"] if m.get("enabled", True)]


def scope_of(m):
    return m.get("scope", "local")


def relay_of(cfg, m):
    """Which machine relays commands to this one, or None for direct.

    Explicit `via` wins; otherwise local machines fall back to `jump_host`.
    A relay never relays through itself - that would prove nothing about it
    and would deadlock the pass if it were the thing that was down."""
    via = m.get("via")
    if via is None and scope_of(m) == "local":
        via = cfg.get("jump_host")
    return None if via == m["name"] else via


def target_spec(m):
    """How the RELAY should address this machine.

    An alias is preferred when present: the relay's own ~/.ssh/config already
    knows the user, port and key for it, which is how we reach datacenter
    boxes whose addresses we were never told. Falling back to user@ip covers
    machines the relay has no entry for."""
    if m.get("alias"):
        return m["alias"]
    return f"{m['user']}@{m['ip']}"


def pollable(data, gate_ok):
    """The machines to poll right now.

    `gate_ok` is whether our public IP currently matches a gate domain. Local
    machines are polled only when it does; public machines are always polled.
    Returning them separately from `active()` is what keeps an off-network
    laptop from firing thirteen false 'machine down' alerts."""
    return [m for m in active(data)
            if scope_of(m) == "public" or gate_ok]


def skipped_by_gate(data, gate_ok):
    """Local machines we are deliberately NOT polling, so the UI can say
    'not checked - off network' instead of showing them as healthy."""
    if gate_ok:
        return []
    return [m for m in active(data) if scope_of(m) == "local"]
