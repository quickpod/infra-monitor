#!/usr/bin/env python3
r"""
gmcheck - collect health and metrics for the whole fleet in one pass.

TRANSPORT, AND WHY IT IS SHAPED LIKE THIS
Direct SSH from the monitoring host to some private networks is unreliable:
it works, then port 22 silently DROPS for a while (ICMP still answers, so a
machine looks up but unreachable). Bursts of connections can provoke a gateway
rate-limiter or an IDS. When a machine is configured with a relay (`via`, or
the fleet-wide `jump_host`), it is reached through that relay as a COMMAND
RELAY - not a tunnel.

`allowtcpforwarding no` and `allowagentforwarding no` are often set on hardened
hosts, so ProxyJump/direct-tcpip may not work at all. What always works is
running `ssh` ON the relay and letting it use its own key.

The shape that follows is also the gentlest one available: ONE connection
leaves the monitoring host per poll, and the relay fans out to the fleet in
parallel from inside its own network. A burst of outbound connections per cycle
is precisely what gets a monitoring host dropped or banned.

Public machines are reached directly - and always, regardless of which network
the monitoring host is on.

WHAT IS COLLECTED
  reachable | quickpod service | nvidia-smi actually working | cpu/mem/disk
  | GPU utilisation, memory and temperature | logged-in sessions and
  established SSH peers, so a login from outside our own ranges is reported
  rather than ignored.
"""

import base64, ipaddress, json, os, re, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gmconfig, sshconn

RELAY_KEY = "/root/.ssh/id_ed25519"

# Runs ON each target. Emits KEY=VALUE lines - trivially parseable and immune
# to locale or column-order changes in the tools it calls.
METRIC_SH = r"""
echo "HOST=$(hostname)"
echo "UPTIME=$(cut -d. -f1 /proc/uptime 2>/dev/null)"

# CPU from two /proc/stat samples. Parsing `top` is locale-dependent and its
# first sample is since-boot, which reads as a wrong-but-plausible number.
read -r _ a b c d _ < /proc/stat; i1=$d; t1=$((a+b+c+d))
sleep 0.3
read -r _ a b c d _ < /proc/stat; i2=$d; t2=$((a+b+c+d))
awk -v i1="$i1" -v t1="$t1" -v i2="$i2" -v t2="$t2" \
  'BEGIN{n=t2-t1; if(n<=0){print "CPU=0"}else{printf "CPU=%.0f\n",100*(1-(i2-i1)/n)}}'

awk '/^MemTotal:/{t=$2}/^MemAvailable:/{a=$2}END{if(t>0){
  printf "MEM=%.0f\nMEM_USED_MB=%d\nMEM_TOTAL_MB=%d\n",100*(t-a)/t,(t-a)/1024,t/1024}}' /proc/meminfo

df -P / 2>/dev/null | awk 'NR==2{gsub("%","",$5);
  printf "DISK=%s\nDISK_USED_GB=%.0f\nDISK_TOTAL_GB=%.0f\n",$5,$3/1048576,$2/1048576}'

# Optional service check (check_quickpod): a systemd unit on some boxes, a
# container or a bare process on others. Look for all three rather than assume
# one shape. This is an optional per-machine capability - a box that does not
# run the service simply reports it absent and the check can be turned off.
QP=""
for u in $(systemctl list-units --all --type=service --no-legend --no-pager 2>/dev/null \
           | awk '{print $1}' | grep -i quickpod); do
  QP="$u:$(systemctl is-active "$u" 2>/dev/null)"
done
if [ -z "$QP" ] && command -v docker >/dev/null 2>&1; then
  c=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i quickpod | head -1)
  [ -n "$c" ] && QP="docker:$c:running"
fi
if [ -z "$QP" ] && pgrep -f quickpod >/dev/null 2>&1; then QP="process:running"; fi
echo "QUICKPOD=${QP:-absent}"

# nvidia-smi PRESENT is not nvidia-smi WORKING. A box can have the binary and
# still fail with "couldn't communicate with the NVIDIA driver" - exactly the
# outage worth alerting on, and exactly what a `command -v` check misses.
if command -v nvidia-smi >/dev/null 2>&1; then
  if nvidia-smi --query-gpu=index --format=csv,noheader >/dev/null 2>&1; then
    echo "NVIDIA=ok"
    nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu \
      --format=csv,noheader,nounits 2>/dev/null | sed 's/^/GPU=/'
  else
    echo "NVIDIA=failed"
    echo "NVIDIA_ERR=$(nvidia-smi 2>&1 | head -1 | cut -c1-120)"
  fi
else
  echo "NVIDIA=absent"
fi

who 2>/dev/null | sed 's/^/WHO=/'

# ONLY POST-AUTHENTICATION SESSIONS.
# A raw "ss state established sport = :22" list is NOT a list of logins: a
# brute-forcer mid-handshake holds an ESTABLISHED TCP socket too, and an
# earlier version duly reported such a peer as a foreign SESSION on a box it
# never got into. Alerting on failed attacks is worse than useless - an
# internet-facing host is attacked continuously, so the panel would be
# permanently red and the one real intrusion would be invisible in the noise.
#
# sshd names its per-connection processes: post-auth is "sshd: user@pts/0" or
# "sshd: user@notty"; pre-auth is "sshd: unknown [net]" / "[accepted]". The
# "@" is the authentication boundary, so we key on it.
ss -tnpH state established '( sport = :22 )' 2>/dev/null | while read -r l; do
  peer=$(printf '%s' "$l" | awk '{print $4}')
  pid=$(printf '%s' "$l" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
  [ -z "$pid" ] && continue
  # The process can exit between ss listing it and us reading it - a short
  # session ending mid-scan. Skip it rather than letting the shell spew a
  # "No such file" onto the output we are about to parse.
  [ -r "/proc/$pid/cmdline" ] || continue
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
  case "$cmd" in
    *"sshd:"*"@"*) echo "SSHPEER=$peer" ;;
  esac
done
# If ss gave us no pid at all we are not root and cannot tell auth from
# pre-auth. Say so rather than guessing: `who` still covers real logins, and a
# silent downgrade would look identical to "nobody is connected".
ss -tnpH state established '( sport = :22 )' 2>/dev/null | grep -q 'pid=' \
  || echo "PEERSCAN=unprivileged"
"""


def _b64(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


# Fans out from the relay. Each target is probed in a background subshell
# writing to its own temp file, then the files are concatenated - so one slow
# or dead machine costs its own timeout, never the whole pass.
RELAY_SH = r"""
PAYLOAD='%(payload)s'
K="-i %(key)s -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -o ServerAliveInterval=5"
D=$(mktemp -d)
%(jobs)s
wait
for f in "$D"/*; do echo "===$(basename "$f")==="; cat "$f"; done
rm -rf "$D"
"""

JOB = ('( timeout %(t)d ssh -n $K %(spec)s "echo $PAYLOAD | base64 -d | bash" '
       '>"$D/%(name)s" 2>/dev/null || echo "UNREACHABLE=1" >>"$D/%(name)s" ) &')


# ---------------------------------------------------------------- network gate
#
# WHY THIS NO LONGER ASKS A STRANGER
# The gate answers one question: are the private-network machines in `machines`
# actually MINE right now? It used to answer it by fetching our public IP from
# api.ipify.org and comparing against the gate domains. That worked, but
# check_all() called it at the top of EVERY cycle with no cache - 396 requests
# in the 22 hours of log that prompted this change, one every ~2.4 minutes.
#
# Nothing secret is sent; the GET has no body and the reply is our own address.
# The PATTERN is the leak. A third party receiving a request from this address
# every couple of minutes learns when the laptop is awake and when each house
# is occupied, indefinitely. For a utility whose entire job is watching which
# process talks to which stranger, being that traffic is the wrong shape - and
# it was the one non-SSH destination this program had.
#
# The default gateway's MAC answers the same question with nothing leaving the
# machine. It is neither secret nor a security boundary: anyone controlling a
# network you join who knows your router's MAC can forge it. But the public IP
# was equally forgeable by whoever ran the network, and the gate was never a
# boundary - it decides whether probing private addresses is SENSIBLE, nothing more.
#
# The thing that SHOULD stop us handing credentials to a stranger is host-key
# verification, and right now it does not: sshconn._client() sets AutoAddPolicy
# on a client that never loads a known_hosts file, so every host key is
# "missing", silently accepted, and not persisted to be checked next time. That
# is a separate bug and a real one - bootstrap_ssh sends a password - but it is
# not made better or worse by which signal the gate reads.

GATEWAY_PS = r"""
$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
     Sort-Object RouteMetric, ifMetric | Select-Object -First 1
if (-not $r) { '{}'; exit }
$n = Get-NetNeighbor -IPAddress $r.NextHop -ErrorAction SilentlyContinue |
     Where-Object { $_.LinkLayerAddress } | Select-Object -First 1
[pscustomobject]@{ gateway = $r.NextHop; mac = $n.LinkLayerAddress } |
    ConvertTo-Json -Compress
"""


def _norm_mac(s):
    """Canonical AA-BB-CC-DD-EE-FF, or None if that is not a usable MAC.

    Windows spells these with hyphens, colons and either case depending on
    which tool produced them. A fingerprint that fails to match on punctuation
    reads as 'you are not home', which silently stops the fleet being polled -
    so both sides of every comparison go through here."""
    h = re.sub(r"[^0-9A-Fa-f]", "", s or "").upper()
    if len(h) != 12 or h == "0" * 12:
        return None
    return "-".join(h[i:i + 2] for i in range(0, 12, 2))


def gateway_fingerprint(timeout=10):
    """(mac, gateway_ip) for the current default route; (None, None) if we
    cannot tell - no default route, a VPN or tether with no ARP neighbour, or
    PowerShell failing. 'Cannot tell' must never read as a match."""
    # Function-level, as gmnotify does: gmlocal is the heavy module and only
    # this one helper is wanted. It also keeps the import off gmcheck's CLI
    # path, which runs fine without it.
    if os.name != "nt":
        return _gateway_fingerprint_linux(timeout)
    import gmlocal
    try:
        d = gmlocal._run_ps(GATEWAY_PS, timeout)
    except Exception:
        return None, None
    if not isinstance(d, dict):
        return None, None
    return _norm_mac(d.get("mac")), (d.get("gateway") or None)


def _gateway_fingerprint_linux(timeout=10):
    """The Linux half of the same question, via `ip` instead of PowerShell.

    Without this the whole feature was dead on Linux: gateway_fingerprint ran
    PowerShell, so it returned (None, None) on every call, learn_gate raised
    "no default gateway with a MAC address here", and "Trust this network" could
    never succeed — which is exactly what it looked like from the tray (owner,
    2026-08-17: "Trust this network doesnt stay check does it work?"). It did not.
    """
    import subprocess

    def run(args):
        try:
            return subprocess.run(args, capture_output=True, text=True,
                                  timeout=timeout).stdout
        except (OSError, subprocess.TimeoutExpired):
            return ""

    gw = None
    for line in run(["ip", "-4", "route", "show", "default"]).splitlines():
        parts = line.split()
        if "via" in parts:
            gw = parts[parts.index("via") + 1]
            break
    if not gw:
        return None, None

    def mac_of(addr):
        # `ip neigh` is the live ARP cache; /proc/net/arp is the fallback for
        # stripped images where iproute2's neigh output differs.
        for line in run(["ip", "neigh", "show", addr]).splitlines():
            parts = line.split()
            if "lladdr" in parts:
                return parts[parts.index("lladdr") + 1]
        try:
            with open("/proc/net/arp", errors="replace") as fh:
                for row in fh.read().splitlines()[1:]:
                    f = row.split()
                    if len(f) >= 4 and f[0] == addr and f[3] != "00:00:00:00:00:00":
                        return f[3]
        except OSError:
            pass
        return None

    mac = mac_of(gw)
    if not mac:
        # The neighbour may simply not be cached yet on a freshly booted
        # machine; one ping populates it. Never fatal — an un-fingerprintable
        # gateway must read as "cannot tell", not as a match.
        run(["ping", "-c", "1", "-W", "1", gw])
        mac = mac_of(gw)
    if not mac:
        return None, gw
    return _norm_mac(mac), gw


def public_ip(timeout=6):
    """Our address as the internet sees it. Returns None when offline - which
    must read as 'unknown', never as 'gate passed'.

    NO LONGER ON THE POLL PATH. This reaches a third party, so it now runs only
    when you ask for it - the "my public IP" button in the stealth tab - or if
    `gate_public_ip_fallback` is turned back on deliberately."""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            import urllib.request
            with urllib.request.urlopen(url, timeout=timeout) as r:
                ip = r.read().decode().strip()
                ipaddress.ip_address(ip)
                return ip
        except Exception:
            continue
    return None


def gate_ok(cfg):
    """(on_network, identity, why) - decided locally, with no network call.

    Fails CLOSED: if we cannot tell where we are, local machines are not
    probed. The alternative - assuming we are on-network - means probing
    private addresses while attached to some other network, where those
    addresses belong to strangers.

    `identity` is whatever we learned about our location (a gateway MAC, or a
    public IP if the legacy fallback ran) and exists only so the UI can show
    what the decision was based on."""
    fps = cfg.get("gate_fingerprints") or []

    # FIRST RUN: adopt the network we are on right now.
    #
    # Failing closed (below) is right once we know somewhere, but with nothing
    # learned it made a fresh install monitor NOTHING and say so by naming a
    # Windows binary and a command-line flag:
    #     OFF-NETWORK (no known network yet - run InfraMonitor.exe --learn-gate…)
    # — on Linux, in a product whose rules forbid telling users to use a
    # terminal (owner, field report 2026-08-17: "no working out of the box needs
    # fixing"). The machine the user installs on is, by definition, a network
    # they trust, so record it and carry on. Every OTHER network still has to be
    # trusted explicitly, which is the property the fail-closed design was
    # protecting: we never probe private addresses on a stranger's LAN.
    if not fps and not cfg.get("gate_adopt_disabled"):
        try:
            _cfg, mac, label, added = learn_gate(cfg=cfg, name="this network")
            if added:
                fps = _cfg.get("gate_fingerprints") or []
        except RuntimeError:
            pass                      # no gateway to fingerprint: fall through

    if fps:
        mac, _gw = gateway_fingerprint()
        if not mac:
            return False, None, "no default gateway (offline?)"
        for f in fps:
            if _norm_mac(f.get("gateway_mac")) == mac:
                return True, mac, f"on {f.get('name') or 'a known network'}"
        return False, mac, "unknown gateway - not a known network"

    # Nothing learned yet. Falling back to the public-IP gate would quietly
    # restore the every-two-minutes beacon, so it happens only if explicitly
    # enabled. Otherwise say plainly what to do rather than showing a fleet
    # that looks healthy because nothing was checked.
    if cfg.get("gate_public_ip_fallback"):
        mine = public_ip()
        if not mine:
            return False, None, "public IP unknown (offline?)"
        for d in cfg.get("gate_domains", []):
            try:
                for info in socket.getaddrinfo(d, None):
                    if info[4][0] == mine:
                        return True, mine, f"on {d} (public-IP fallback)"
            except socket.gaierror:
                continue
        return False, mine, "not on a known network (public-IP fallback)"
    # Reached only when there is no default gateway to adopt at all.
    return False, None, ("not on a network yet - connect, then use "
                         "Settings -> Trust this network")


def learn_gate(cfg=None, name=None):
    """Record the current default gateway as one of our networks.

    Returns (cfg, mac, label, added). `added` is False when this gateway was
    already known, so the caller can say 'already learned' rather than silently
    doing nothing."""
    cfg = cfg or gmconfig.load()
    mac, gw = gateway_fingerprint()
    if not mac:
        raise RuntimeError("no default gateway with a MAC address here - "
                           "not on a network, or on a VPN/tether that has no "
                           "ARP neighbour to fingerprint")
    fps = cfg.setdefault("gate_fingerprints", [])
    for f in fps:
        if _norm_mac(f.get("gateway_mac")) == mac:
            return cfg, mac, f.get("name") or "a known network", False
    label = name or f"network via {gw}"
    fps.append({"name": label, "gateway_mac": mac, "gateway_ip": gw})
    gmconfig.save(cfg)
    return cfg, mac, label, True


# ------------------------------------------------------------------- parsing
def parse_metrics(text):
    d = {"gpus": [], "who": [], "ssh_peers": []}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k == "GPU":
            parts = [p.strip() for p in v.split(",")]
            if len(parts) >= 6:
                try:
                    d["gpus"].append({"index": int(parts[0]), "name": parts[1],
                                      "util": int(parts[2]), "mem_used": int(parts[3]),
                                      "mem_total": int(parts[4]), "temp": int(parts[5])})
                except ValueError:
                    pass
        elif k == "WHO":
            d["who"].append(v)
        elif k == "SSHPEER":
            d["ssh_peers"].append(re.sub(r":\d+$", "", v).strip("[]"))
        elif k in ("CPU", "MEM", "DISK", "UPTIME", "MEM_USED_MB", "MEM_TOTAL_MB",
                   "DISK_USED_GB", "DISK_TOTAL_GB"):
            try:
                d[k.lower()] = int(float(v))
            except ValueError:
                pass
        else:
            d[k.lower()] = v
    return d


def foreign_sessions(cfg, m):
    """Any logged-in session or established SSH peer from outside our expected
    ranges, or as an unexpected user. This is the 'is anyone else in here?'
    check - a machine can be perfectly healthy and still compromised."""
    nets = []
    for c in cfg.get("expected_login_cidrs", []):
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    # The gate domains are OUR networks - a session arriving from one of them
    # is us. Resolved live rather than hard-coded because these are often
    # dynamic addresses; pinning yesterday's IP would start flagging our own
    # logins as intrusions the moment the ISP rotated it, and an intrusion
    # alert that cries wolf is worse than none.
    for d in cfg.get("gate_domains", []):
        try:
            for info in socket.getaddrinfo(d, None):
                nets.append(ipaddress.ip_network(info[4][0] + "/32", strict=False))
        except (socket.gaierror, ValueError):
            continue
    # Explicit allowlist, plus EVERY machine we already monitor. A session
    # arriving from another box in our own fleet is not an intruder. Deriving
    # this from the fleet list means adding a machine allowlists it
    # automatically and nobody has to remember to keep a second list in step.
    for c in cfg.get("allowed_peers", []):
        try:
            nets.append(ipaddress.ip_network(str(c).strip(), strict=False))
        except ValueError:
            pass
    for other in cfg.get("machines", []):
        addr = other.get("ip")
        if not addr:
            continue
        try:
            nets.append(ipaddress.ip_network(addr + "/32", strict=False))
        except ValueError:
            # A machine may now be addressed by HOSTNAME, which is not an IP and
            # must not silently drop it from the allowed-peer set — resolve it,
            # and if resolution fails leave it out rather than crashing the pass.
            try:
                for info in socket.getaddrinfo(addr, None):
                    nets.append(ipaddress.ip_network(info[4][0] + "/32",
                                                     strict=False))
            except (socket.gaierror, ValueError):
                pass
    ok_users = {u.lower() for u in cfg.get("expected_login_users", [])}

    def known(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return True          # not an IP (local console) - not a foreign peer
        return any(a in n for n in nets)

    out = []
    # These are already filtered to authenticated sessions by the collector -
    # a failed brute-force attempt never reaches this list. That is deliberate:
    # the question this check answers is "is someone else IN?", not "is anyone
    # knocking?". Knocking is constant on an internet-facing host and is
    # fail2ban's job, not an operator's.
    for peer in set(m.get("ssh_peers", [])):
        if peer and not known(peer):
            out.append(f"authenticated ssh from {peer}")
    for w in m.get("who", []):
        parts = w.split()
        if not parts:
            continue
        user = parts[0].lower()
        ipm = re.search(r"\(([^)]+)\)", w)
        src = ipm.group(1) if ipm else ""
        # THE SOURCE DECIDES, NOT THE USERNAME.
        # This used to alert on any user outside expected_login_users even when
        # the session came from a fully allowlisted address - so every routine
        # login from an already-trusted fleet peer raised an intrusion alert,
        # and the allowlist appeared to do nothing. An allowlisted origin is
        # trusted; which local account it lands on is that machine's business.
        if not src:
            continue                    # console/tty login, not a remote peer
        if known(src):
            continue
        who_txt = f"login by {parts[0]} from {src}"
        if ok_users and user not in ok_users:
            who_txt += " (unexpected account)"
        out.append(who_txt)
    return sorted(set(out))


# -------------------------------------------------------------------- checking
def check_via_relay(cfg, machines, relay_name, timeout=25):
    """One connection out; the relay fans out to everything behind it.

    Works for any relay. Machines addressed by alias use the relay's own ssh
    config, so a box whose IP we were never told is still reachable."""
    relay = gmconfig.find(cfg, relay_name)
    if not relay:
        return {m["name"]: {"error": f"relay {relay_name} not configured"} for m in machines}
    # -i is a DEFAULT here, not an override: an alias whose own IdentityFile is
    # set in the relay's config still wins, because ssh prefers the config's
    # identity for a matched Host block.
    key = relay.get("relay_key", RELAY_KEY)
    jobs, payload = [], _b64(METRIC_SH)
    for m in machines:
        jobs.append(JOB % {"t": timeout, "name": m["name"],
                           "spec": gmconfig.target_spec(m)})
    script = RELAY_SH % {"payload": payload, "key": key,
                         "jobs": "\n".join(jobs)}
    cli = None
    try:
        cli = sshconn.connect(cfg, relay, password=None, jump=None,
                              timeout=cfg.get("ssh_timeout", 15))
        _rc, out, _err = sshconn.run(cli, script, timeout=timeout + 30)
    except Exception as ex:
        return {m["name"]: {"error": f"relay unavailable: {type(ex).__name__}"}
                for m in machines}
    finally:
        sshconn.close(cli)

    blocks, cur = {}, None
    for line in out.splitlines():
        h = re.match(r"^===(.+)===$", line.strip())
        if h:
            cur = h.group(1)
            blocks[cur] = []
        elif cur:
            blocks[cur].append(line)
    return {name: "\n".join(v) for name, v in blocks.items()}


def check_direct(cfg, m, timeout=20):
    cli = None
    try:
        cli = sshconn.connect(cfg, m, password=None, jump=None,
                              timeout=cfg.get("ssh_timeout", 15))
        _rc, out, _err = sshconn.run(
            cli, f"echo {_b64(METRIC_SH)} | base64 -d | bash", timeout=timeout)
        return out
    except Exception as ex:
        return f"UNREACHABLE=1\nERR={type(ex).__name__}"
    finally:
        sshconn.close(cli)


def check_all(cfg=None):
    cfg = cfg or gmconfig.load()
    ok, gate_id, why = gate_ok(cfg)
    relay_name = cfg.get("jump_host") or "direct"

    results, t0 = [], time.time()
    machines = gmconfig.active(cfg)
    local = [m for m in machines if gmconfig.scope_of(m) == "local"]
    public = [m for m in machines if gmconfig.scope_of(m) == "public"]

    # Group by relay. Machines with no relay - and every relay itself - are
    # probed directly: a relay checked through itself proves nothing, and if it
    # is the thing that is down we would have no path to say so.
    raw, by_relay, direct = {}, {}, []
    for m in machines:
        if gmconfig.scope_of(m) == "local" and not ok:
            continue                       # gate closed; reported as skipped
        rname = gmconfig.relay_of(cfg, m)
        if rname:
            by_relay.setdefault(rname, []).append(m)
        else:
            direct.append(m)

    for rname, group in by_relay.items():
        raw.update(check_via_relay(cfg, group, rname))
    for m in direct:
        raw[m["name"]] = check_direct(cfg, m)

    for m in machines:
        scope = gmconfig.scope_of(m)
        r = {"name": m["name"], "ip": m["ip"], "scope": scope,
             "checked": True, "up": False, "problems": [], "metrics": {}}
        if scope == "local" and not ok:
            r.update(checked=False, note=f"skipped - {why}")
            results.append(r)
            continue
        text = raw.get(m["name"], "")
        if isinstance(text, dict):
            # The RELAY failed, not this machine. We lost the vantage point, so
            # the honest answer is "unknown" - reporting DOWN would fire
            # thirteen "machine down" alerts every time one relay blips, and a
            # monitor that cries wolf thirteen times gets muted. checked=False
            # makes the notifier skip it, exactly like the gate does; the relay
            # is itself a monitored machine and alerts on its own behalf.
            r.update(checked=False,
                     note=text.get("error", "no data") + " - state unknown")
            results.append(r)
            continue
        if not text or "UNREACHABLE=1" in text:
            r["problems"].append("unreachable over SSH")
            results.append(r)
            continue

        met = parse_metrics(text)
        r["up"] = True
        r["metrics"] = met

        # Per-machine switches. A check that does not apply to a box is worse
        # than useless: it produces a permanent warning that teaches you to
        # ignore the panel. The optional service check is OPT-IN (default OFF):
        # most fleets do not run this particular service, so warning about it by
        # default would be pure noise. Turn it on per machine where it applies.
        qp = met.get("quickpod", "absent")
        if m.get("check_quickpod", False):
            if qp == "absent" or qp.endswith(":inactive") or qp.endswith(":failed"):
                r["problems"].append(f"quickpod not running ({qp})")

        # nvidia-smi judgement depends on whether this box is KNOWN to have
        # cards. Some machines ship the binary with no GPU behind it, so a bare
        # "nvidia-smi failed" alert on them is pure noise - and an alert people
        # learn to ignore is worse than no alert. Only a machine we have
        # previously seen report GPUs raises this.
        nv = met.get("nvidia", "absent")
        known_gpu = bool(m.get("gpu"))
        if not m.get("check_nvidia", True):
            nv = "skipped"
        if nv == "ok" and met.get("gpus"):
            r["gpu_detected"] = True       # persisted by the caller
        elif nv == "failed":
            if known_gpu:
                r["problems"].append("nvidia-smi FAILING: " +
                                     met.get("nvidia_err", "driver error")[:70])
            else:
                r["notes"] = r.get("notes", []) + [
                    "nvidia-smi present but not working (no GPU known here)"]
        elif nv == "absent" and known_gpu:
            r["problems"].append("nvidia-smi missing on a GPU machine")

        for f in foreign_sessions(cfg, met):
            r["problems"].append("FOREIGN SESSION: " + f)

        for gp in met.get("gpus", []):
            if gp.get("temp", 0) >= 88:
                r["problems"].append(f"GPU{gp['index']} at {gp['temp']}C")
        if met.get("disk", 0) >= 92:
            r["problems"].append(f"disk {met['disk']}% full")
        results.append(r)

    # Learn which machines really have GPUs, so the next pass can tell a broken
    # driver from a box that never had a card. Written once, only on change.
    dirty = False
    for r in results:
        if r.get("gpu_detected"):
            tgt = gmconfig.find(cfg, r["name"])
            if tgt is not None and not tgt.get("gpu"):
                tgt["gpu"] = True
                dirty = True
    if dirty:
        try:
            gmconfig.save(cfg)
        except OSError:
            pass

    # `gate_id` replaces the old `public_ip`: normally a gateway MAC, and only
    # an IP if the legacy fallback ran. Renamed rather than reused, so nothing
    # downstream can label a MAC as "your public IP".
    return {"gate_ok": ok, "gate_id": gate_id, "gate_note": why,
            "relay": relay_name, "elapsed": round(time.time() - t0, 1),
            "checked_at": time.time(), "machines": results}


if __name__ == "__main__":
    snap = check_all()
    if "--json" in sys.argv:
        print(json.dumps(snap, indent=2))
        sys.exit(0)
    g = "PASS" if snap["gate_ok"] else "FAIL"
    print(f"gate {g} ({snap['gate_note']}, via {snap['gate_id']})  "
          f"relay={snap['relay']}  {snap['elapsed']}s\n")
    print(f"{'NAME':<7}{'SCOPE':<8}{'STATE':<8}{'CPU':>5}{'MEM':>5}{'DISK':>6}  "
          f"{'GPU':<22}{'QUICKPOD':<22}PROBLEMS")
    print("-" * 120)
    for r in snap["machines"]:
        m = r["metrics"]
        if not r["checked"]:
            state = "skipped"
        elif r["up"]:
            state = "UP" if not r["problems"] else "WARN"
        else:
            state = "DOWN"
        gpus = m.get("gpus", [])
        gtxt = (f"{len(gpus)}x {gpus[0]['name'][:14]} {gpus[0]['util']}%"
                if gpus else m.get("nvidia", "-"))
        print(f"{r['name']:<7}{r['scope']:<8}{state:<8}"
              f"{m.get('cpu','-'):>4}%{m.get('mem','-'):>4}%{m.get('disk','-'):>5}%  "
              f"{gtxt:<22}{m.get('quickpod','-')[:21]:<22}"
              f"{'; '.join(r['problems'])[:60]}")
    bad = [r for r in snap["machines"] if r["checked"] and (not r["up"] or r["problems"])]
    print(f"\n{len(bad)} of {len(snap['machines'])} need attention")
