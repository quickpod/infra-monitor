#!/usr/bin/env python3
r"""
gmstealth - is this address invisible from outside, or does it answer?

WHY THIS CANNOT RUN ON THE MACHINE IT IS CHECKING
A stealth check asks what a stranger's packets get back. Asked from the machine
itself, every answer is a lie: the connection never leaves the box, the Windows
firewall's inbound rules are not consulted for a loopback path, and the NAT and
the router in front of it are not in the path at all. A local scan of your own
address reports every listener OPEN and concludes you are wide open, when from
the internet the same machine may be answering nothing whatsoever.

So the probe runs on a RELAY - the same relays the fleet check already uses,
reached the same way, over the one SSH connection that is already trusted to
leave this laptop. That is a genuinely external vantage point, which is the
entire difference between a stealth check and a self-portrait.

The vantage is chosen to match the target rather than fixed, because relays sit
in different places and only one of them may be outside any given target:
  a PRIVATE target   -> a relay that is ON that private network
  a PUBLIC target    -> a relay that is on the internet
Probing a public address from a relay behind the same NAT the monitoring host
sits behind would hairpin back through it - a path most consumer routers do not
implement, which returns "stealth" for every port and would read as a perfect
result when nothing was actually tested.

Probing from THIS PC is still offered, because it is the right answer for a
different question - "what can I reach on that other box" - but a scan of this
machine's own address from this machine is labelled, loudly, as not a stealth
result. A check that cannot see must say so rather than return an all-clear it
did not earn.

THE THREE ANSWERS, AND WHY "CLOSED" IS NOT GOOD NEWS
  OPEN     the handshake completed. Something is listening AND reachable.
  CLOSED   the host sent RST. Nothing is listening - but the host answered,
           which tells a scanner that this address is live and worth a longer
           look. This is the state most people mistake for safe.
  STEALTH  nothing came back at all. The packet was dropped. From outside,
           the address is indistinguishable from unused space.

Only the third is stealth. A firewall set to "block" is stealth; one set to
"reject", or absent behind a router that answers, is not - and the two are
invisibly different from the inside, which is the whole reason this tab exists.

WHAT IS PROBED
  every privileged port, 1-1023            - the whole reserved range, not a
                                             sample; a sampled sweep that finds
                                             nothing has proved nothing
  a curated set of common service ports    - the high ports that actually carry
                                             services (3389, 5432, 27017, ...)
  every port THIS machine is listening on  - taken live from the gmlocal
                                             snapshot, so a listener that
                                             appeared five minutes ago is in
                                             this sweep without anyone editing
                                             a list
  every Windows SERVICE listener port      - the same snapshot, restricted to
                                             sockets owned by a process the SCM
                                             has registered. These are the ones
                                             above 49152 that a "well-known
                                             ports" list silently misses, and
                                             RPC, SMB and WinRM all live there.

A loopback-only listener is included on purpose. It should come back stealth
from every external vantage, and if it does not, something is forwarding it -
which is precisely the finding that no amount of looking at the local socket
table can produce.

A CONTROL, BECAUSE ALL-STEALTH IS AMBIGUOUS
"Every port dropped" and "the host is switched off" produce byte-for-byte
identical results. So the vantage also pings the target and reports whether ANY
port answered anything. With no evidence the host is up, the verdict is
reported as UNCONFIRMED rather than as a clean bill of health.

RATE
The sweep is deliberately fast - a few hundred sockets in flight - because the
operator asked for fast. That is a real trade: ~1100 connection attempts in a
few seconds is the exact shape of a port scan, and some networks have a gateway
that silently drops port 22 for ten minutes when it sees a burst. If the relay
stops answering after a sweep, that is why; lower `concurrency`.
"""

import base64, errno, ipaddress, json, os, re, select, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gmconfig, gmlocal, gmpaths, sshconn

# select() carries a hard FD_SETSIZE ceiling - 1024 on Linux, 512 in Python's
# Windows build - and exceeding it does not raise, it silently corrupts the
# descriptor set. 400 leaves headroom under the smaller of the two.
MAX_CONCURRENCY = 400

# Two speeds, because the fast one is genuinely provocative and the choice
# belongs to whoever is holding the consequences.
#
# ~1100 connection attempts in five seconds is not merely *like* a port scan,
# it is one, and some networks have a gateway that silently drops port 22 for
# ten minutes when it sees a burst - the reason the whole app can relay through
# a jump host instead of connecting directly. fail2ban's `portscan` jails and
# any IDS worth the name key on exactly this rate.
#
# Gentle trades wall-clock for invisibility: a couple of dozen sockets at a
# time with a pause between batches is indistinguishable from ordinary traffic,
# and takes minutes rather than seconds. Same ports, same verdicts - the only
# thing that changes is how loud the asking is.
SWEEP_MODES = {
    "fast": {
        "concurrency": 200, "timeout": 2.0, "pace": 0.0,
        "label": "fast - seconds, but looks exactly like a port scan",
    },
    "gentle": {
        "concurrency": 25, "timeout": 2.5, "pace": 0.15,
        "label": "gentle - minutes, paced to stay under IDS and fail2ban",
    },
}
DEFAULT_MODE = "fast"


def mode_settings(mode):
    """The knobs for a named speed, falling back to fast rather than to
    nothing: an unrecognised mode must still run a sweep."""
    return dict(SWEEP_MODES.get(mode or DEFAULT_MODE,
                                SWEEP_MODES[DEFAULT_MODE]))


def estimate_seconds(nports, mode):
    """Roughly how long a sweep will take if EVERY port is stealthed - the
    worst case, and the one a well-configured target actually produces. Shown
    before the sweep starts, because 'gentle' costing three minutes is
    something to find out before pressing the button, not after."""
    s = mode_settings(mode)
    batches = max(1, int(nports / max(1, s["concurrency"])))
    return int(batches * (s["timeout"] + s["pace"])) + 5

# High ports that carry real services. NOT a "top 1000" list: every entry here
# is something that, found open on an address that should be dark, is a finding
# on its own. The privileged range is swept in full separately, so nothing
# below 1024 belongs in here.
COMMON_PORTS = {
    1080: "socks", 1099: "java-rmi", 1194: "openvpn", 1433: "mssql",
    1434: "mssql-mon", 1521: "oracle", 1723: "pptp", 1883: "mqtt",
    1900: "ssdp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2086: "whm", 2087: "whm-ssl", 2181: "zookeeper", 2222: "ssh-alt",
    2375: "docker", 2376: "docker-tls", 2379: "etcd", 2380: "etcd-peer",
    3000: "dev-http", 3128: "squid", 3268: "globalcat", 3269: "globalcat-ssl",
    3306: "mysql", 3389: "rdp", 3690: "svn", 4000: "dev-http",
    4040: "spark-ui", 4444: "metasploit", 4500: "ipsec-nat", 4786: "cisco-smi",
    5000: "upnp/flask", 5001: "dev-http", 5060: "sip", 5061: "sip-tls",
    5222: "xmpp", 5353: "mdns", 5357: "wsdapi", 5432: "postgres",
    5555: "adb", 5601: "kibana", 5672: "amqp", 5800: "vnc-http",
    5900: "vnc", 5901: "vnc-1", 5902: "vnc-2", 5903: "vnc-3",
    5985: "winrm", 5986: "winrm-ssl", 6000: "x11", 6001: "x11-1",
    6379: "redis", 6443: "kubernetes", 6667: "irc", 7001: "weblogic",
    7070: "realserver", 7443: "https-alt", 7547: "tr-069", 8000: "http-alt",
    8006: "proxmox", 8008: "http-alt", 8009: "ajp", 8080: "http-proxy",
    8081: "http-alt", 8082: "http-alt", 8083: "http-alt", 8086: "influxdb",
    8088: "http-alt", 8089: "splunkd", 8090: "http-alt", 8123: "home-assistant",
    8161: "activemq", 8443: "https-alt", 8500: "consul", 8834: "nessus",
    8888: "http-alt", 9000: "http-alt", 9001: "supervisor", 9042: "cassandra",
    9090: "prometheus", 9091: "http-alt", 9100: "jetdirect", 9200: "elastic",
    9300: "elastic-tx", 9418: "git", 9999: "http-alt", 10000: "webmin",
    10250: "kubelet", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 27018: "mongodb-shard", 27019: "mongodb-cfg",
    28017: "mongodb-web", 32768: "rpc-dynamic", 33060: "mysqlx",
    49152: "msrpc-dyn", 49153: "msrpc-dyn", 49154: "msrpc-dyn",
    49155: "msrpc-dyn", 49156: "msrpc-dyn", 49157: "msrpc-dyn",
}

# Open on an address reachable from the internet, each of these is an incident
# rather than a note. Kept short and defensible: file sharing, remote control,
# remote administration, and unauthenticated-by-default datastores.
NEVER_PUBLIC = {
    21: "FTP - credentials in clear",
    22: "SSH - brute-forced continuously on any public address",
    23: "telnet - no encryption at all",
    25: "SMTP - open relays get the address blocklisted",
    53: "DNS - reflection/amplification if it answers recursively",
    110: "POP3 - credentials in clear",
    135: "MSRPC - the Windows endpoint mapper; never internet-facing",
    137: "NetBIOS name service",
    138: "NetBIOS datagram",
    139: "NetBIOS session",
    143: "IMAP - credentials in clear",
    161: "SNMP - device inventory, often on a default community string",
    445: "SMB - file shares; this is the ransomware front door",
    1433: "MSSQL",
    1521: "Oracle",
    2375: "Docker API - unauthenticated root on the host",
    2376: "Docker API",
    3306: "MySQL",
    3389: "RDP - credential stuffing and BlueKeep-class bugs",
    5432: "PostgreSQL",
    5555: "ADB - unauthenticated shell",
    5900: "VNC - frequently unauthenticated",
    5985: "WinRM - remote PowerShell",
    5986: "WinRM",
    6379: "Redis - no auth by default",
    9200: "Elasticsearch - no auth by default",
    10250: "kubelet - runs commands in containers",
    11211: "memcached - amplification source",
    27017: "MongoDB - no auth by default",
}

STATE_ORDER = {"open": 0, "closed": 1, "unreachable": 2, "blocked": 3,
               "error": 4, "stealth": 5}
SEV_ORDER = {"CRIT": 0, "HIGH": 1, "WARN": 2, "INFO": 3, "OK": 4}


# --------------------------------------------------------------- the probe
# ONE implementation of the actual scanning, used two ways: exec'd in-process
# for the local vantage, and shipped to the relay as a file for the remote one.
# Written as source text rather than as a function because the relay has no
# copy of this repository and a frozen build has no .py file to send - and
# because two hand-maintained copies of a scanner would eventually disagree
# about what "stealth" means, which is the one thing that must not happen.
#
# It is plain Python 3.4-era code on purpose: these relays are whatever distro
# they shipped with, and an f-string would turn a stealth check into a syntax
# error on the one box that matters.
PROBE_SRC = r'''
import errno, json, re, select, socket, subprocess, sys, time

# errno numbers differ between Linux and Windows and the symbolic names are not
# all defined on both, so both spellings are matched by number.
REFUSED = (errno.ECONNREFUSED, 111, 10061)
TIMEDOUT = (errno.ETIMEDOUT, 110, 10060)
UNREACH = (errno.EHOSTUNREACH, errno.ENETUNREACH, 113, 101, 10065, 10051)
INPROGRESS = (errno.EINPROGRESS, errno.EWOULDBLOCK, 115, 36, 10035)
DENIED = (errno.EACCES, errno.EPERM, 13, 1, 10013)


def state_for(err):
    if err in REFUSED:
        return "closed", "RST - host answered; nothing listening"
    if err in TIMEDOUT:
        return "stealth", "no response - packet dropped"
    if err in UNREACH:
        return "unreachable", "no route from this vantage"
    if err in DENIED:
        return "blocked", "the vantage itself refused to send"
    return "error", "errno %d" % err


def sweep(ip, ports, timeout, conc, pace=0.0):
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    out = {}
    todo = list(ports)
    live = {}                                   # fd -> [sock, port, started]
    while todo or live:
        launched = 0
        while todo and len(live) < conc:
            p = todo.pop()
            try:
                s = socket.socket(fam, socket.SOCK_STREAM)
                s.setblocking(False)
            except OSError as ex:
                out[p] = ("error", 0, str(ex)[:80])
                continue
            started = time.time()
            try:
                rc = s.connect_ex((ip, p))
            except OSError as ex:
                out[p] = ("error", 0, str(ex)[:80])
                s.close()
                continue
            if rc == 0:
                # Connected before the syscall returned. Only happens on
                # loopback and on a very close LAN peer, but it is a real
                # answer and must not be waited on.
                out[p] = ("open", 0, "handshake completed")
                s.close()
            elif rc in INPROGRESS:
                live[s.fileno()] = [s, p, started]
                launched += 1
            else:
                st, why = state_for(rc)
                out[p] = (st, int((time.time() - started) * 1000), why)
                s.close()
        # Paced between batches, not between individual sockets: the thing an
        # IDS counts is SYNs per second, and a gap after each batch flattens
        # that rate without multiplying the wall-clock by the port count.
        if pace and launched:
            time.sleep(pace)
        if not live:
            continue
        socks = [v[0] for v in live.values()]
        try:
            _r, w, x = select.select([], socks, socks, 0.2)
        except (OSError, ValueError):
            # A descriptor died under us. Fall through to the timeout sweep
            # rather than aborting: a scanner that gives up mid-run and
            # reports what it has would call the unscanned ports stealth.
            w, x = [], []
        now = time.time()
        settled = set()
        for s in set(w) | set(x):
            fd = s.fileno()
            if fd not in live:
                continue
            port, started = live[fd][1], live[fd][2]
            try:
                err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            except OSError:
                err = -1
            ms = int((now - started) * 1000)
            if err == 0:
                out[port] = ("open", ms, "handshake completed")
            else:
                st, why = state_for(err)
                out[port] = (st, ms, why)
            settled.add(fd)
        for fd in list(live):
            s, port, started = live[fd]
            if fd in settled:
                s.close()
                del live[fd]
            elif (now - started) >= timeout:
                # Nothing came back inside the window. THIS is stealth: not an
                # error, not a failure to scan - an answered question whose
                # answer is silence.
                out[port] = ("stealth", int((now - started) * 1000),
                             "no response in %.1fs - packet dropped" % timeout)
                s.close()
                del live[fd]
    return out


def ping(ip):
    """Whether ICMP comes back. Not a security verdict - plenty of correctly
    configured hosts drop it - but the difference between 'everything is
    stealthed' and 'nothing is there' has to come from somewhere."""
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", "2000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "2", ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=8)
        return "reply" if r.returncode == 0 else "no reply"
    except Exception:
        return "not attempted"


def arp(ip):
    """The target's MAC, if it is on the same segment as this vantage.

    This is the control that makes a GOOD result reportable. A properly
    hardened host drops ICMP as well as TCP, so ping alone can never tell it
    apart from an absent one - which would leave the best possible outcome
    permanently reported as 'could not confirm', and a verdict that cannot be
    earned is a verdict nobody trusts.

    A host cannot answer ARP without being powered on and on the wire, and the
    sweep we just ran is itself what populates the cache. It only resolves for
    an on-link address - a routed target simply returns nothing - so it cannot
    accidentally report the gateway's MAC as the target's."""
    if sys.platform.startswith("win"):
        cmds = [["arp", "-a", ip]]
    else:
        cmds = [["ip", "neigh", "show", ip], ["arp", "-n", ip]]
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=6)
            text = r.stdout.decode("utf-8", "replace")
        except Exception:
            continue
        # FAILED/incomplete entries carry no address and mean the opposite of
        # what a matched line would, so the MAC itself is the only evidence
        # taken - never the mere presence of a row.
        for line in text.splitlines():
            if ip not in line:
                continue
            if "FAILED" in line or "incomplete" in line.lower():
                continue
            m = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
            if m and m.group(0).lower() not in ("00:00:00:00:00:00",
                                                "00-00-00-00-00-00",
                                                "ff:ff:ff:ff:ff:ff",
                                                "ff-ff-ff-ff-ff-ff"):
                return m.group(0).lower()
    return ""


def main():
    req = json.loads(sys.stdin.read())
    ip = req["ip"]
    t0 = time.time()
    try:
        res = sweep(ip, req["ports"], float(req.get("timeout", 2.0)),
                    int(req.get("concurrency", 200)),
                    float(req.get("pace", 0.0)))
        ok, err = True, ""
    except Exception as ex:
        res, ok, err = {}, False, "%s: %s" % (type(ex).__name__, ex)
    # Liveness is read AFTER the sweep, never before: the sweep is what puts
    # the target in this vantage's ARP cache, so asking first would return
    # nothing on exactly the hosts the control exists to confirm.
    print(json.dumps({
        "ok": ok, "error": err, "elapsed": round(time.time() - t0, 1),
        "ping": ping(ip) if req.get("ping", True) else "",
        "arp": arp(ip) if req.get("ping", True) else "",
        "results": [[p, v[0], v[1], v[2]] for p, v in sorted(res.items())]}))


main()
'''

# The relay runs the probe from a file rather than from `python3 -c`: the
# script is 4KB of quotes, braces and backslashes travelling through an SSH
# command line and two shells, and every one of those characters is a chance
# for something in the path to reinterpret it. base64 in, file out, no quoting
# question at any hop.
RELAY_SH = r"""
set -e
D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
printf '%%s' '%(probe)s' | base64 -d > "$D/probe.py"
printf '%%s' '%(input)s'  | base64 -d > "$D/in.json"
if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else echo '{"ok":false,"error":"no python interpreter on this relay"}'; exit 0; fi
"$PY" "$D/probe.py" < "$D/in.json"
"""


def _b64(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


# ------------------------------------------------------------- the port set
def port_plan(lsnap=None, include=("privileged", "common", "listener", "service")):
    """{port: {"sources": [...], "name": str, "svc": str, "bind": str}}.

    Provenance is kept per port because it is what makes a result actionable:
    "3389 is open" is a fact, "3389 is open AND it is TermService listening on
    0.0.0.0 on this machine" is an instruction. Sources accumulate rather than
    overwrite - a port is routinely both privileged and one of ours, and
    dropping either half loses the reason it was worth probing."""
    plan = {}

    def note(port, source, name="", svc="", bind=""):
        if not (0 < port < 65536):
            return
        e = plan.setdefault(port, {"sources": [], "name": "", "svc": "",
                                   "bind": ""})
        if source not in e["sources"]:
            e["sources"].append(source)
        # First non-empty wins for each field: the local snapshot is consulted
        # after the static tables and genuinely knows better, so it is applied
        # by overwriting explicitly below rather than by ordering luck.
        if name and not e["name"]:
            e["name"] = name
        if svc:
            e["svc"] = svc
        if bind:
            e["bind"] = bind

    if "privileged" in include:
        for p in range(1, 1024):
            note(p, "privileged", gmlocal.port_label(p).partition(" ")[2])
    if "common" in include:
        for p, n in COMMON_PORTS.items():
            note(p, "common", n)

    for r in (lsnap or {}).get("rows", []):
        if r.get("dir") != "LISTEN" or r.get("proto") != "TCP":
            continue
        # `peer` on a LISTEN row is the exposure word the local scan computed -
        # "world", "loopback", or this host's LAN address. Carried through
        # verbatim so the two tabs cannot disagree about how wide a door is.
        bind = r.get("peer") or ""
        if "listener" in include:
            note(r["lport"], "listener", "", r.get("svc", ""), bind)
        if "service" in include and r.get("svc"):
            note(r["lport"], "service", "", r.get("svc", ""), bind)
    return plan


def _target_ip(target):
    """(ip, note). A name is resolved here so the relay is handed an address:
    the relay's DNS is not ours, and 'stealth' arrived at by resolving a
    different host is not a result, it is a mistake."""
    t = (target or "").strip()
    if not t:
        return "", "no target given"
    try:
        ipaddress.ip_address(t)
        return t, ""
    except ValueError:
        pass
    try:
        info = socket.getaddrinfo(t, None, socket.AF_INET)
        return info[0][4][0], f"{t} resolved to {info[0][4][0]}"
    except socket.gaierror as ex:
        return "", f"{t} did not resolve: {ex}"


def local_addresses():
    """Every address this machine answers on, as best we can enumerate it.

    Used for one decision only: whether a probe launched from here is actually
    leaving the machine. It does not have to be exhaustive - a missed address
    costs a caveat that should have been shown, never a finding that should
    have been suppressed."""
    out = {"127.0.0.1", "::1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            out.add(info[4][0])
    except (socket.gaierror, UnicodeError):
        pass
    return out


def is_self_probe(vantage_name, ip):
    """True when the packets never actually leave the target.

    This is the distinction that decides whether a result means anything.
    Probing another host from this laptop is a perfectly valid external
    vantage - we are outside THAT machine. Probing this laptop from this
    laptop is not a vantage at all, and every 'reachable' it reports is an
    artifact of the loopback path rather than evidence about the firewall."""
    if vantage_name != "local":
        return False
    try:
        if ipaddress.ip_address(ip).is_loopback:
            return True
    except ValueError:
        return False
    return ip in local_addresses()


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved)


# ------------------------------------------------------------- the vantages
def vantages(cfg=None):
    """Where a probe can be launched from, best first.

    A relay is any machine another machine is routed through - the configured
    jump host, plus anything named in a `via`. Derived rather than listed for
    the same reason the peer networks are: a second list is a list that goes
    stale, and a stealth check launched from a relay that was removed last
    month would fail in a way that looks like the target being unreachable."""
    cfg = cfg or gmconfig.load()
    names = []
    if cfg.get("jump_host"):
        names.append(cfg["jump_host"])
    for m in cfg.get("machines", []):
        if m.get("via") and m["via"] not in names:
            names.append(m["via"])
    out = []
    for n in names:
        m = gmconfig.find(cfg, n)
        if not m or not m.get("enabled", True):
            continue
        out.append({"name": n, "ip": m.get("ip", ""),
                    "scope": gmconfig.scope_of(m),
                    "ready": bool(m.get("bootstrapped")),
                    "kind": "relay"})
    out.append({"name": "local", "ip": "", "scope": "local", "ready": True,
                "kind": "local"})
    return out


def default_vantage(cfg, ip):
    """The relay that is actually OUTSIDE this target.

    Public target -> a relay on the internet. Private target -> a relay on that
    same private fabric, which can reach it at all. Getting this backwards is
    not a slow scan, it is a wrong answer: a public address probed from inside
    our own NAT comes back entirely stealth because the packets never left."""
    want = "public" if is_public(ip) else "local"
    vs = vantages(cfg)
    for v in vs:
        if v["kind"] == "relay" and v["ready"] and v["scope"] == want:
            return v["name"]
    for v in vs:
        if v["kind"] == "relay" and v["ready"]:
            return v["name"]
    return "local"


# ---------------------------------------------------------------- executing
def _probe_local(payload):
    """Run the probe in this process.

    exec of the same source the relay gets, rather than a second local
    implementation, so there is exactly one definition of what each state
    means. It is fed through the same JSON stdin/stdout contract as well, so
    the only thing that differs between the two vantages is where the packets
    leave from."""
    import io
    ns = {"__name__": "__probe__"}
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(json.dumps(payload))
    sys.stdout = io.StringIO()
    try:
        exec(compile(PROBE_SRC, "<probe>", "exec"), ns)
        return json.loads(sys.stdout.getvalue().strip() or "{}")
    finally:
        sys.stdin, sys.stdout = old_in, old_out


def _probe_relay(cfg, relay_name, payload, timeout):
    relay = gmconfig.find(cfg, relay_name)
    if not relay:
        return {"ok": False, "error": f"vantage {relay_name!r} is not configured"}
    script = RELAY_SH % {"probe": _b64(PROBE_SRC),
                         "input": _b64(json.dumps(payload))}
    cli = None
    try:
        cli = sshconn.connect(cfg, relay, password=None, jump=None,
                              timeout=cfg.get("ssh_timeout", 15))
        _rc, out, err = sshconn.run(cli, script, timeout=timeout)
    except Exception as ex:
        return {"ok": False,
                "error": f"vantage {relay_name} unavailable: {type(ex).__name__}: {ex}"[:220]}
    finally:
        sshconn.close(cli)
    line = ""
    for ln in (out or "").splitlines():
        # The probe's only stdout is one JSON object, but a login banner or an
        # MOTD on the relay lands on the same stream. Take the JSON, not the
        # first line.
        if ln.strip().startswith("{"):
            line = ln.strip()
    if not line:
        return {"ok": False,
                "error": ("vantage returned no result: "
                          + ((err or out or "").strip()[:200] or "empty output"))}
    try:
        return json.loads(line)
    except ValueError as ex:
        return {"ok": False, "error": f"unparseable result from vantage: {ex}"}


# ------------------------------------------------------------------- verdict
def _row_severity(port, state, meta, target_public, self_probe=False):
    """How loudly one port should shout.

    Exposure is the axis. An open port that this machine deliberately listens
    on is a fact to confirm; the same port open on an address that should be
    dark is a finding; a port bound to loopback here and answering from outside
    is neither - it is evidence that something is forwarding, and it outranks
    both.

    None of which holds for a self-probe. Asked from the machine itself, every
    listener answers by construction - so an OPEN there is not a finding of any
    severity, and dressing it as one would put five CRIT rows on screen for a
    laptop whose firewall is doing exactly its job."""
    bind = meta.get("bind", "")
    if state == "open" and self_probe:
        return "INFO", ("answered over loopback, from this same machine - "
                        "expected for anything listening, and no evidence at "
                        "all about reachability from elsewhere")
    if state == "open":
        if bind == "loopback":
            return "CRIT", ("bound to loopback on this PC yet reachable from "
                            "the vantage - something is forwarding this port")
        if target_public and port in NEVER_PUBLIC:
            return "CRIT", f"reachable from the internet - {NEVER_PUBLIC[port]}"
        if port in NEVER_PUBLIC:
            return "HIGH", NEVER_PUBLIC[port]
        return "HIGH", "reachable from the vantage"
    if state == "closed":
        return "WARN", ("host answered with RST - not stealth; the address is "
                        "confirmed live to anyone who asks")
    if state in ("unreachable", "blocked", "error"):
        return "INFO", "not probed conclusively"
    return "OK", ""


def scan(target, cfg=None, vantage=None, lsnap=None, mode=DEFAULT_MODE,
         timeout=None, concurrency=None, include=None, ping=True):
    """One stealth check. Never raises: a scanner that dies quietly would leave
    the tab showing an all-clear it did not earn, so every failure comes back
    as a populated `error` with `ok` false and no rows at all."""
    cfg = cfg or gmconfig.load()
    t0 = time.time()
    # An explicit timeout or concurrency overrides the mode's; the mode is a
    # named preset, not a cage.
    ms = mode_settings(mode)
    if timeout is not None:
        ms["timeout"] = float(timeout)
    if concurrency is not None:
        ms["concurrency"] = int(concurrency)
    ip, note = _target_ip(target)
    base = {"ok": False, "error": "", "target": target, "ip": ip, "note": note,
            "mode": mode if mode in SWEEP_MODES else DEFAULT_MODE,
            "vantage": "", "vantage_kind": "", "rows": [], "counts": {},
            "ping": "", "arp": "", "verdict": "", "verdict_note": "", "caveat": "",
            "checked_at": time.time(), "elapsed": 0.0, "requested": 0}
    if not ip:
        base["error"] = note or "no target given"
        return base

    plan = port_plan(lsnap, include or ("privileged", "common", "listener",
                                        "service"))
    ports = sorted(plan)
    base["requested"] = len(ports)
    if not ports:
        base["error"] = "no ports selected"
        return base

    vname = vantage or default_vantage(cfg, ip)
    base["vantage"] = vname
    base["vantage_kind"] = "local" if vname == "local" else "relay"
    payload = {"ip": ip, "ports": ports, "ping": ping,
               "timeout": float(ms["timeout"]), "pace": float(ms["pace"]),
               "concurrency": max(1, min(int(ms["concurrency"]),
                                         MAX_CONCURRENCY))}

    # Worst case is every port timing out: batches * (timeout + pace), plus the
    # SSH round trip. Generous rather than tight - a sweep killed by its own
    # deadline reports the unscanned remainder as nothing at all, and on gentle
    # a tight budget would abort every single run.
    budget = int(len(ports) / max(1, payload["concurrency"])
                 * (ms["timeout"] + ms["pace"])) + 120
    try:
        if vname == "local":
            res = _probe_local(payload)
        else:
            res = _probe_relay(cfg, vname, payload, budget)
    except Exception as ex:
        base["error"] = f"{type(ex).__name__}: {ex}"[:300]
        base["elapsed"] = round(time.time() - t0, 1)
        return base

    if not res.get("ok"):
        base["error"] = res.get("error") or "the vantage reported failure"
        base["elapsed"] = round(time.time() - t0, 1)
        return base

    base["ping"] = res.get("ping", "")
    base["arp"] = res.get("arp", "")
    target_public = is_public(ip)
    self_probe = is_self_probe(vname, ip)
    base["self_probe"] = self_probe
    rows, seen = [], set()
    for port, state, ms, why in res.get("results", []):
        port = int(port)
        seen.add(port)
        meta = plan.get(port, {"sources": [], "name": "", "svc": "", "bind": ""})
        sev, note_ = _row_severity(port, state, meta, target_public, self_probe)
        rows.append({
            "port": port, "proto": "TCP", "state": state, "sev": sev,
            "ms": int(ms), "why": why,
            "name": meta["name"] or COMMON_PORTS.get(port, ""),
            "svc": meta["svc"], "bind": meta["bind"],
            "sources": list(meta["sources"]),
            "source": "+".join(meta["sources"]) or "-",
            "note": note_,
            "local": bool({"listener", "service"} & set(meta["sources"])),
        })
    # A port that was asked about and not answered for is NOT stealth - it was
    # not tested. Saying so is the difference between a gap and an all-clear.
    for port in ports:
        if port in seen:
            continue
        meta = plan[port]
        rows.append({
            "port": port, "proto": "TCP", "state": "error", "sev": "INFO",
            "ms": 0, "why": "the vantage returned no result for this port",
            "name": meta["name"] or COMMON_PORTS.get(port, ""),
            "svc": meta["svc"], "bind": meta["bind"],
            "sources": list(meta["sources"]),
            "source": "+".join(meta["sources"]) or "-",
            "note": "not probed conclusively",
            "local": bool({"listener", "service"} & set(meta["sources"])),
        })

    rows.sort(key=lambda r: (SEV_ORDER.get(r["sev"], 9),
                             STATE_ORDER.get(r["state"], 9), r["port"]))

    def n(pred):
        return sum(1 for r in rows if pred(r))

    counts = {
        "total": len(rows),
        "open": n(lambda r: r["state"] == "open"),
        "closed": n(lambda r: r["state"] == "closed"),
        "stealth": n(lambda r: r["state"] == "stealth"),
        "untested": n(lambda r: r["state"] in ("error", "unreachable", "blocked")),
        "privileged": n(lambda r: "privileged" in r["sources"]),
        "listeners": n(lambda r: r["local"]),
        # Ports this machine listens on that the vantage could actually reach.
        # The single number the tab exists to produce.
        "listeners_open": n(lambda r: r["local"] and r["state"] == "open"),
        "services_open": n(lambda r: "service" in r["sources"]
                           and r["state"] == "open"),
        "crit": n(lambda r: r["sev"] == "CRIT"),
        "high": n(lambda r: r["sev"] == "HIGH"),
    }
    counts["stealth_pct"] = (round(100.0 * counts["stealth"] / len(rows), 1)
                             if rows else 0.0)

    verdict, vnote, caveat = _verdict(counts, base, res, target_public, vname,
                                      self_probe)
    base.update({"ok": True, "rows": rows, "counts": counts, "verdict": verdict,
                 "verdict_note": vnote, "caveat": caveat,
                 "elapsed": round(time.time() - t0, 1),
                 "checked_at": time.time()})
    return base


def _verdict(counts, base, res, target_public, vname, self_probe=False):
    """(verdict, note, caveat). The caveat is not decoration - it is the part
    that stops a result being over-read, and every path that can produce a
    clean-looking answer for the wrong reason sets one."""
    caveat = ""
    if self_probe:
        caveat = ("NOT A STEALTH RESULT. This PC probed itself, so the packets "
                  "never left the machine: the firewall's inbound rules, the "
                  "router and any NAT were never in the path. Every listener "
                  "answers over loopback by construction. Re-run it from a "
                  "relay to learn anything about what the outside world sees.")
    elif vname == "local":
        caveat = ("Probed from this PC rather than from a relay. That is a "
                  "valid outside vantage for another host, but it only shows "
                  "what THIS machine can reach - a different network's view "
                  "of the target may be nothing like it.")
    elif not target_public and base["vantage_kind"] == "relay":
        caveat = ("Probed from inside the private fabric. This is what a "
                  "neighbour on the LAN sees, which is the right question for "
                  "a LAN address and says nothing about the internet.")

    # A self-probe has no verdict to give. Calling it EXPOSED because fourteen
    # of our own listeners answered over loopback would be alarming and wrong,
    # and calling it STEALTH would be worse - so it gets its own word rather
    # than being forced into a scale it does not belong on.
    if self_probe:
        return ("SELF-PROBE",
                f"{counts['open']} of this PC's own listener(s) answered over "
                f"loopback, as they must. Nothing here is evidence about what "
                f"any other machine can reach.", caveat)
    if counts["open"]:
        note = (f"{counts['open']} port(s) answered a full handshake"
                + (f", {counts['listeners_open']} of them listeners on this PC"
                   if counts["listeners_open"] else ""))
        return "EXPOSED", note, caveat
    if counts["closed"]:
        return ("NOT STEALTH",
                f"{counts['closed']} port(s) answered with RST. Nothing is "
                f"listening on them, but the host confirms it exists - a "
                f"scanner learns this address is live and worth revisiting.",
                caveat)
    # Everything dropped. That is either a perfect result or an absent host,
    # and the two are byte-identical on the wire - so the verdict turns on
    # whether anything OTHER than TCP proved the target was there.
    if res.get("arp"):
        return ("STEALTH",
                f"every probed port dropped. The host answered ARP "
                f"({res['arp']}), so it is powered on and on the wire - it is "
                f"silent by configuration, not by absence.", caveat)
    if res.get("ping") == "reply":
        return ("STEALTH",
                "every probed port dropped, and the host answered ICMP - so it "
                "is up and deliberately silent on TCP.", caveat)
    extra = ("Nothing answered at all - no port, no ICMP, and no ARP entry, so "
             "there is no evidence the host was reachable during the sweep. A "
             "powered-off machine and a perfectly stealthed one look identical "
             "from here. If the target is not on the same segment as the "
             "vantage, ARP cannot resolve it and this is the expected result.")
    return "UNCONFIRMED", extra, (caveat + "  " + extra if caveat else extra)


# ------------------------------------------------------------------ findings
def findings(snap):
    """The rows worth telling somebody about, as (key, severity, text).

    Same contract as gmlocal.findings, so the notifier treats a port that
    should not be reachable exactly like a process that should not be
    connected. The key omits the timing so a port that stays open is one
    persistent finding rather than a new alert every sweep."""
    if not snap.get("ok"):
        return []
    # A machine probing itself proves nothing about reachability, so it raises
    # nothing. Alerting on it would put "port 49664 is OPEN" in the problem log
    # every time somebody ran the check against 127.0.0.1 to see what the tab
    # did - and an alert that fires on a no-op is one people learn to ignore.
    if snap.get("self_probe"):
        return []
    out = []
    for r in snap.get("rows", []):
        if r["sev"] not in ("CRIT", "HIGH"):
            continue
        what = f"{r['port']}" + (f" {r['name']}" if r["name"] else "")
        who = f" ({r['svc']})" if r["svc"] else ""
        text = (f"{snap['ip']}: TCP {what}{who} is {r['state'].upper()} from "
                f"{snap['vantage']} - {r['note']}")
        out.append((f"stealth|{snap['ip']}|{r['port']}", r["sev"], text))
    if snap["verdict"] == "NOT STEALTH":
        out.append((f"stealth|{snap['ip']}|rst", "WARN",
                    f"{snap['ip']} is not stealthed: {snap['counts']['closed']} "
                    f"port(s) answer with RST from {snap['vantage']}"))
    return out


# ---------------------------------------------------------------------- cli
def _cli():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__.strip().splitlines()[0])
        print("\nusage: gmstealth.py <ip|host> [--vantage NAME] [--gentle|--fast]"
              " [--all]\n"
              "                    [--json] [--no-local-ports] [--timeout S] "
              "[--concurrency N]")
        print("\nvantages:")
        for v in vantages():
            print(f"  {v['name']:<10} {v['scope']:<8}"
                  f"{'ready' if v['ready'] else 'NOT bootstrapped'}")
        print("\nmodes:")
        for name, s in SWEEP_MODES.items():
            print(f"  --{name:<8} {s['label']}"
                  + ("   (default)" if name == DEFAULT_MODE else ""))
        return 0

    def opt(name, default=None):
        return args[args.index(name) + 1] if name in args else default

    cfg = gmconfig.load()
    include = ("privileged", "common") if "--no-local-ports" in args else None
    lsnap = None
    if include is None:
        print("scanning this PC's listeners first...", file=sys.stderr)
        lsnap = gmlocal.scan(cfg)
        if not lsnap.get("ok"):
            print(f"  local scan failed ({lsnap.get('error')}) - continuing "
                  f"without this PC's listener ports", file=sys.stderr)
            lsnap = None

    mode = "gentle" if ("--gentle" in args or "--slow" in args) else "fast"
    plan_n = len(port_plan(lsnap, include or ("privileged", "common",
                                              "listener", "service")))
    print(f"{mode} sweep of {plan_n} ports - up to about "
          f"{estimate_seconds(plan_n, mode)}s if the target is fully stealthed",
          file=sys.stderr)
    s = scan(args[0], cfg=cfg, vantage=opt("--vantage"), lsnap=lsnap, mode=mode,
             timeout=(float(opt("--timeout")) if "--timeout" in args else None),
             concurrency=(int(opt("--concurrency")) if "--concurrency" in args
                          else None),
             include=include)

    if "--json" in args:
        print(json.dumps(s, indent=2))
        return 0 if s["ok"] else 1
    if not s["ok"]:
        print("stealth check FAILED:", s["error"])
        return 1
    c = s["counts"]
    print(f"\n{s['ip']}  from {s['vantage']} ({s['vantage_kind']})  "
          f"{c['total']} ports {s['mode']} in {s['elapsed']}s  "
          f"icmp: {s['ping'] or 'n/a'}"
          + (f"  arp: {s['arp']}" if s["arp"] else ""))
    print(f"\n{s['verdict']}: {s['verdict_note']}")
    if s["caveat"]:
        print(f"\nCAVEAT: {s['caveat']}")
    print(f"\nstealth {c['stealth']} ({c['stealth_pct']}%)   closed {c['closed']}"
          f"   OPEN {c['open']}   untested {c['untested']}")
    print(f"this PC's listeners probed {c['listeners']}, "
          f"reachable {c['listeners_open']}\n")
    show = s["rows"] if "--all" in args else \
        [r for r in s["rows"] if r["state"] != "stealth"]
    print(f"{'SEV':<5}{'PORT':<8}{'STATE':<12}{'SERVICE':<18}{'SOURCE':<26}WHY")
    print("-" * 118)
    for r in show:
        svc = (r["svc"] or r["name"] or "")[:17]
        print(f"{r['sev']:<5}{r['port']:<8}{r['state']:<12}{svc:<18}"
              f"{r['source'][:25]:<26}{(r['note'] or r['why'])[:44]}")
    print(f"\n{len(show)} row(s) shown"
          + ("" if "--all" in args else f" (+{c['stealth']} stealth, --all to list)"))
    fs = findings(s)
    if fs:
        print(f"\n{len(fs)} would alert:")
        for _k, sev, t in fs:
            print(f"  {sev:<5} {t[:110]}")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
