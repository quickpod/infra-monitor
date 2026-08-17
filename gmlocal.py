#!/usr/bin/env python3
r"""
gmlocal - who is talking to THIS laptop, and which of it is accounted for.

The fleet checks answer "is anyone else in *those* machines?". This answers the
same question about the machine the monitor runs on, which is the one box the
SSH checks can never see.

WHAT COUNTS AS A CONNECTION *TO* THIS MACHINE
Three different things, and conflating them is what makes a connection list
unreadable:

  IN      an established TCP session whose local port is one WE are listening
          on, owned by the same process as the listener. Somebody reached us.
  LISTEN  an open door - a socket bound and waiting. Nobody is through it yet,
          but it is the thing that lets them be.
  OUT     a session we opened. Not, strictly, a connection *to* this machine -
          but an unrecognised process beaconing outward is the most common
          shape of a compromise, so it is collected and shown, just never
          counted in the headline "exposed" number.

Direction is decided by matching (local port, owning pid) against the listener
table, not by port number. "Low port = server" is wrong on Windows, where RPC
services routinely listen above 49152.

WHAT COUNTS AS ACCOUNTED FOR
In descending order of how much it is worth trusting:

  system      the process is a service registered with the SCM, or lives under
              %SystemRoot%, AND carries a valid signature from a trusted
              publisher. This is the "valid registered system service" case.
  allowed     you told us to trust this image, or this peer.
  signed      a valid signature from some other publisher - Chrome, Discord, a
              vendor updater. Real software, but NOT a registered system
              service, so it is listed for review rather than hidden.
  unknown     unsigned, signature invalid, or running from a staging
              directory. THIS is what the tab exists to show.
  unverified  we could not read the process image at all. Reported as its own
              class and never folded into "accounted for": a check that cannot
              see must say so rather than return an all-clear it did not earn.

IDENTIFYING A PROCESS WITHOUT BEING ADMINISTRATOR
Win32_Process.ExecutablePath is empty for every process owned by SYSTEM when
the caller is not elevated - which is most of what listens on a Windows box.
`QueryFullProcessImageNameW` through ctypes fails on exactly the same set, so
it buys nothing. What DOES work unelevated is Win32_Service.PathName: the SCM
will tell anyone which image backs a registered service. That covers every
svchost - the bulk of the listeners on a laptop - and names the service while
it is at it, which is the question being asked anyway.

The remainder (lsass, wininit, services.exe, csrss, dasHost, PID 4) are
SYSTEM-owned non-service processes. They are reported `unverified`, not
guessed at from their name, and the tab offers a one-click elevated rescan
that resolves them properly.

WHY THE SIGNATURE RESULT IS CACHED ON DISK
Get-AuthenticodeSignature performs certificate revocation checking, which
reaches the network and can block for seconds per file when a CRL endpoint is
slow. Verifying forty images every minute would turn a background monitor into
a background stall. Results are keyed on (path, size, mtime), so a binary that
is replaced is re-verified and one that is not, is not.

NOISE CONTROL
Loopback-only listeners are collected but never counted as exposed: half the
developer tooling on a laptop binds 127.0.0.1, none of it is reachable from
another machine, and letting forty such rows into the headline number would
hide the one row that matters.
"""

import base64, ipaddress, json, os, re, socket, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gmconfig, gmpaths

HERE = gmpaths.APP_DIR
SIGCACHE_PATH = os.path.join(HERE, "sigcache.json")

# Ceiling on how many images are signature-checked in one pass. Each check can
# reach the network for a revocation list; leftovers are picked up next pass
# and reported as unverified until then, which is honest and bounded.
MAX_VERIFY_PER_PASS = 60

# Publishers whose signature makes a binary a first-class citizen of the OS.
# Matched against the CN and the O of the signing certificate.
DEFAULT_TRUSTED_PUBLISHERS = [
    "Microsoft Corporation",
    "Microsoft Windows",
    "Microsoft Windows Publisher",
    "Microsoft Windows Hardware Compatibility Publisher",
]

# A signed binary running from one of these is still worth a second look: they
# are where droppers stage, and a valid signature on a binary copied out to a
# temp directory proves only that somebody else compiled it.
STAGING_DIRS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\downloads\\",
                "\\$recycle.bin\\", "\\users\\public\\", "\\perflogs\\")

SEV_ORDER = {"CRIT": 0, "HIGH": 1, "WARN": 2, "INFO": 3, "OK": 4}
DIR_ORDER = {"IN": 0, "LISTEN": 1, "OUT": 2}
ACCOUNTED = ("system", "allowed")
UNACCOUNTED = ("unknown", "unverified")

# Reverse lookups run off-thread and are read from this cache on the NEXT pass.
# A name resolution that blocks is a name resolution that freezes the poller,
# and the address is already on screen - the name is an upgrade, not a
# prerequisite.
_rdns = {}
_rdns_inflight = set()
_rdns_lock = threading.Lock()


# --------------------------------------------------------------- powershell
PS_COLLECT = r"""
$ErrorActionPreference='SilentlyContinue'
$ProgressPreference='SilentlyContinue'
$out=[ordered]@{ok=$true;error='';admin=$false;host=$env:COMPUTERNAME;conns=@();procs=@{}}

$idn=[Security.Principal.WindowsIdentity]::GetCurrent()
$out.admin=(New-Object Security.Principal.WindowsPrincipal($idn)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$tcp=@(); $udp=@()
try { $tcp=@(Get-NetTCPConnection -ErrorAction Stop) }
catch { $out.ok=$false; $out.error="Get-NetTCPConnection failed: $($_.Exception.Message)" }
try { $udp=@(Get-NetUDPEndpoint -ErrorAction Stop) } catch { }

# Only processes that own a socket are described. Enumerating command lines
# for every process on the box costs more and answers nothing.
$pids=New-Object 'System.Collections.Generic.HashSet[int]'
foreach($c in $tcp){ [void]$pids.Add([int]$c.OwningProcess) }
foreach($c in $udp){ [void]$pids.Add([int]$c.OwningProcess) }

# The SCM answers an unelevated caller, so this is also the only route to an
# image path for a SYSTEM-owned service host. svchost runs many services under
# one pid; all of their names matter, because "which service is this" is the
# entire question.
$svcName=@{}; $svcPath=@{}
foreach($s in Get-CimInstance Win32_Service){
  if($s.ProcessId -and $pids.Contains([int]$s.ProcessId)){
    $k=[string]$s.ProcessId
    if($svcName.ContainsKey($k)){ $svcName[$k]=$svcName[$k]+','+$s.Name } else { $svcName[$k]=$s.Name }
    if(-not $svcPath.ContainsKey($k) -and $s.PathName){ $svcPath[$k]=[string]$s.PathName }
  }
}

foreach($p in Get-CimInstance Win32_Process){
  $pp=[int]$p.ProcessId
  if(-not $pids.Contains($pp)){ continue }
  $k=[string]$pp
  $path=[string]$p.ExecutablePath
  $src='process'
  if(-not $path -and $svcPath.ContainsKey($k)){ $path=$svcPath[$k]; $src='service' }
  $out.procs[$k]=[ordered]@{
    name=[string]$p.Name; rawpath=$path; pathsrc=$src
    cmd=[string]$p.CommandLine; ppid=[int]$p.ParentProcessId
    svc=$(if($svcName.ContainsKey($k)){$svcName[$k]}else{''})
  }
}

function Stamp($d){
  # A socket with no usable creation time is normal for some kernel endpoints;
  # 0 means "unknown", which the UI renders blank rather than as 1970.
  try{ if($d -and $d.Year -gt 2000){ return [int64]([DateTimeOffset]$d).ToUnixTimeSeconds() } }catch{}
  return 0
}
$rows=New-Object System.Collections.ArrayList
foreach($c in $tcp){
  # 'Bound' is a socket that has an address and nothing else - the ephemeral
  # half of an outbound connection that is ALSO listed properly as
  # Established. Keeping both doubles the table and invents a second row for
  # every browser tab.
  #
  # 'TimeWait' is a connection that has already closed and is being held down
  # by the TCP stack for 2MSL. Its owning process is gone - the pid is always
  # 0 - so it can never be attributed to anything, and reporting seventeen
  # unattributable sockets as unidentified connections is exactly the false
  # alarm that gets a security panel ignored.
  if([string]$c.State -eq 'Bound' -or [string]$c.State -eq 'TimeWait'){ continue }
  [void]$rows.Add([ordered]@{proto='TCP';la=[string]$c.LocalAddress;lp=[int]$c.LocalPort
    ra=[string]$c.RemoteAddress;rp=[int]$c.RemotePort;state=[string]$c.State
    pid=[int]$c.OwningProcess;since=(Stamp $c.CreationTime)})
}
foreach($c in $udp){
  [void]$rows.Add([ordered]@{proto='UDP';la=[string]$c.LocalAddress;lp=[int]$c.LocalPort
    ra='';rp=0;state='Bound';pid=[int]$c.OwningProcess;since=(Stamp $c.CreationTime)})
}
$out.conns=@($rows)
$out | ConvertTo-Json -Depth 5 -Compress
"""

# Paths arrive through a file, not the command line: a command line long enough
# to carry sixty absolute paths runs into the shell's own length limit, and one
# containing a quote character would rewrite the script.
PS_VERIFY = r"""
$ErrorActionPreference='SilentlyContinue'
# [string[]], not @(): ConvertFrom-Json on PowerShell 5.1 emits an array as ONE
# object rather than enumerating it, so @() wraps the whole list in a
# single-element array. The loop then handed all sixty paths to
# Get-AuthenticodeSignature at once and came back with one result keyed on
# every path joined by spaces - which cached nothing and left every binary
# permanently "unverified". The cast flattens it properly.
[string[]]$paths=(Get-Content -LiteralPath $env:GMLOCAL_PATHS -Raw | ConvertFrom-Json)
$res=@{}
foreach($p in $paths){
  if(-not $p){ continue }
  try{
    $s=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
    $subj=''
    if($s.SignerCertificate){ $subj=[string]$s.SignerCertificate.Subject }
    $res[[string]$p]=@{status=[string]$s.Status;signer=$subj}
  }catch{
    $res[[string]$p]=@{status='Unreadable';signer=''}
  }
}
$res | ConvertTo-Json -Depth 3 -Compress
"""


def _run_ps(script, timeout, env_extra=None):
    """Run PowerShell with no console window and return parsed JSON.

    -EncodedCommand rather than -Command: the script is full of quotes, braces
    and dollar signs, and every one of them is a chance for the shell to
    reinterpret something. Base64 removes the question."""
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    env = dict(os.environ, **(env_extra or {}))
    # stdin is pinned to DEVNULL, not inherited. A --windowed PyInstaller build
    # has no console, so the inherited standard handles are invalid and a child
    # that touches stdin can fail in ways that never show up when running from
    # a terminal.
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
         "Bypass", "-EncodedCommand", enc],
        capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout, env=env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    out = (r.stdout or b"").decode("utf-8", "replace").strip()
    if not out:
        err = (r.stderr or b"").decode("utf-8", "replace").strip()
        raise RuntimeError(err[:200] or f"powershell exited {r.returncode} with no output")
    return json.loads(out)


def _int(v, default=0):
    """int() that treats missing as `default` but keeps a real zero."""
    if v is None or v == "":
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _aslist(v):
    """ConvertTo-Json emits a bare object, not a one-element array, when a
    collection happens to hold exactly one item. Every consumer here wants a
    list, so the shape is normalised once, at the boundary."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _exe_of(pathname):
    """The image out of a service PathName, which is a command line.

    `"C:\\Program Files\\X\\svc.exe" -k net` and
    `C:\\WINDOWS\\system32\\svchost.exe -k netsvcs` are both valid and only one
    of them is quoted, so quoting cannot be assumed either way."""
    s = (pathname or "").strip()
    if not s:
        return ""
    if s.startswith('"'):
        end = s.find('"', 1)
        return s[1:end] if end > 0 else s[1:]
    m = re.match(r"^(.*?\.exe)(\s|$)", s, re.IGNORECASE)
    return m.group(1) if m else s.split(" ")[0]


# ------------------------------------------------------------ signature cache
def _load_sigcache(path=SIGCACHE_PATH):
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_sigcache(cache, path=SIGCACHE_PATH):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=0)
        os.replace(tmp, path)
    except OSError:
        pass                                # a cold cache is slow, not wrong


def _signatures(procs, cache):
    """Verify every image we have not already verified. Returns (cache, deferred).

    Keyed on (size, mtime) as well as path, so replacing a trusted binary with
    an untrusted one at the same location is re-checked rather than inheriting
    the old verdict - which is precisely the substitution this exists to
    catch."""
    want = []
    for p in procs.values():
        path = p.get("path")
        if not path:
            continue
        c = cache.get(path)
        if (c and c.get("size") == p.get("size")
                and c.get("mtime") == p.get("mtime")):
            continue
        if path not in want:
            want.append(path)
    if not want:
        return cache, 0
    todo = want[:MAX_VERIFY_PER_PASS]
    deferred = max(0, len(want) - MAX_VERIFY_PER_PASS)
    listfile = os.path.join(HERE, "sigcheck.tmp")
    try:
        with open(listfile, "w", encoding="utf-8") as f:
            json.dump(todo, f)
        res = _run_ps(PS_VERIFY, timeout=180,
                      env_extra={"GMLOCAL_PATHS": listfile})
    except Exception:
        # Nothing verified this pass. Those images stay `unverified`, which is
        # the correct answer - the alternative is calling them clean.
        return cache, deferred + len(todo)
    finally:
        try:
            os.remove(listfile)
        except OSError:
            pass
    meta = {p["path"]: p for p in procs.values() if p.get("path")}
    asked = {p.lower(): p for p in todo}
    for path, v in (res or {}).items():
        # Only cache verdicts for images we actually asked about. A collector
        # that answers a question we did not ask has misunderstood the input,
        # and caching that answer would attach a signature verdict to the wrong
        # binary - the one mistake this whole file exists to avoid.
        if path.lower() not in asked:
            continue
        m = meta.get(path, {})
        cache[path] = {"size": m.get("size", 0), "mtime": m.get("mtime", 0),
                       "status": v.get("status", "Unreadable"),
                       "signer": v.get("signer", ""), "at": int(time.time())}
    # Entries are dropped only when the file itself is gone. A program that is
    # merely closed right now will be back, and re-verifying it every time it
    # restarts would defeat the point of caching.
    for path in list(cache):
        if not os.path.exists(path):
            cache.pop(path, None)
    _save_sigcache(cache)
    return cache, deferred


def _cert_names(subject):
    """CN and O out of an X.500 subject string.

    Split on commas that are not escaped: organisation names legitimately
    contain them ("Foo, Inc."), and a naive split turns the publisher into
    "Foo" - which would then match a trusted-publisher entry it should not."""
    cn = org = ""
    field, parts, esc = "", [], False
    for ch in subject or "":
        if esc:
            field += ch
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ",":
            parts.append(field)
            field = ""
        else:
            field += ch
    parts.append(field)
    for p in parts:
        k, _, v = p.strip().partition("=")
        k, v = k.strip().upper(), v.strip().strip('"')
        if k == "CN" and not cn:
            cn = v
        elif k == "O" and not org:
            org = v
    return cn, org


# ------------------------------------------------------------------- peers
def _peer_nets(cfg):
    """Addresses that are not strangers: our own fleet, the gate networks, and
    whatever the operator added. Derived from machines.json rather than kept as
    a second list, for the same reason the fleet check does it - a list you
    have to remember to update is a list that is wrong."""
    nets = []

    def add(cidr, label):
        try:
            nets.append((ipaddress.ip_network(str(cidr).strip(), strict=False), label))
        except ValueError:
            pass

    for m in cfg.get("machines", []):
        if m.get("ip"):
            add(m["ip"] + "/32", m["name"])
    for c in cfg.get("expected_login_cidrs", []):
        add(c, "lan")
    for c in cfg.get("allowed_peers", []):
        add(c, "allowed")
    for c in cfg.get("local_watch", {}).get("trusted_peers", []):
        add(c, "trusted")
    for d in cfg.get("gate_domains", []):
        try:
            for info in socket.getaddrinfo(d, None):
                add(info[4][0] + "/32", d.split(".")[0])
        except (socket.gaierror, ValueError):
            continue
    return nets


def _classify_peer(ip, nets):
    """(class, label). Class drives severity; label is what the row shows."""
    if not ip or ip in ("0.0.0.0", "::", "*"):
        return "none", ""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "public", ip
    if a.is_loopback:
        return "loopback", "loopback"
    for n, label in nets:
        if a in n:
            return "known", label
    if a.is_multicast:
        return "multicast", "multicast"
    if a.is_link_local:
        return "lan", "link-local"
    if a.is_private:
        return "lan", "private"
    return "public", ""


def rdns(ip):
    """Cached reverse name, resolved in the background.

    Returns whatever is known NOW - '' on first sighting, the name on a later
    pass. Blocking a poller on a PTR lookup that may never answer is how a
    monitor stops monitoring."""
    with _rdns_lock:
        if ip in _rdns:
            return _rdns[ip]
        if ip in _rdns_inflight:
            return ""
        _rdns_inflight.add(ip)

    def work():
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = ""
        with _rdns_lock:
            _rdns[ip] = name
            _rdns_inflight.discard(ip)

    threading.Thread(target=work, daemon=True, name="rdns").start()
    return ""


# --------------------------------------------------------------- classifying
def _verdict(proc, sig, cfg):
    """(verdict, reasons) for the process behind a socket."""
    lw = cfg.get("local_watch", {})
    trusted_pub = {s.strip().lower() for s in
                   lw.get("trusted_publishers") or DEFAULT_TRUSTED_PUBLISHERS}
    trusted_img = {str(s).strip().lower() for s in lw.get("trusted_images", [])}

    path = proc.get("path") or ""
    lpath = path.lower()
    svc = proc.get("svc") or ""

    if proc.get("kernel"):
        return "system", ["windows kernel / system process"]
    if lpath and lpath in trusted_img:
        return "allowed", ["trusted by you"]
    if not path:
        return "unverified", ["process image not readable - not a registered "
                              "service, and identifying it needs elevation"]

    status = (sig or {}).get("status") or "Pending"
    cn, org = _cert_names((sig or {}).get("signer", ""))
    publisher = org or cn
    sysroot = (os.environ.get("SystemRoot") or "C:\\Windows").lower()
    in_system = lpath.startswith(sysroot)
    staged = any(d in lpath for d in STAGING_DIRS)

    if status == "Pending":
        return "unverified", ["signature check queued - verdict on the next pass"]
    if status != "Valid":
        reasons = []
        if status in ("NotSigned", "UnknownError"):
            reasons.append("unsigned binary")
        else:
            # An INVALID signature is a stronger signal than none at all: it
            # means something was signed and then modified.
            reasons.append(f"signature {status}")
        if svc:
            reasons.append(f"registered as service '{svc}' but not validly signed")
        if staged:
            reasons.append("running from a staging directory")
        return "unknown", reasons

    trusted = cn.lower() in trusted_pub or org.lower() in trusted_pub
    if staged:
        return "unknown", [f"signed by {publisher}",
                           "running from a staging directory"]
    if trusted and (svc or in_system):
        return "system", ([f"service '{svc}'"] if svc else ["Windows component"]) \
            + [f"signed by {publisher}"]
    if trusted:
        return "signed", [f"signed by {publisher}", "not a registered service"]
    if svc:
        return "signed", [f"third-party service '{svc}'", f"signed by {publisher}"]
    return "signed", [f"signed by {publisher} - not a registered system service"]


def _severity(direction, verdict, peer_class, exposure):
    """How loudly a row should shout.

    Exposure is the axis, not novelty: an unrecognised process somebody is
    already talking to outranks the same process merely holding a port open,
    and a port open to the world outranks one open only to loopback."""
    if verdict in ACCOUNTED:
        return "OK"
    if verdict == "signed":
        return "INFO"
    if verdict == "unverified":
        return "HIGH" if direction == "IN" else "WARN"
    if direction == "IN":
        if peer_class == "public":
            return "CRIT"
        # Loopback is another process on this same machine, not somebody who
        # reached the laptop. Still worth listing - it is how a local agent
        # gets driven - but it must not claim the same urgency as a stranger
        # on the internet holding an open session.
        return "WARN" if peer_class == "loopback" else "HIGH"
    if direction == "LISTEN":
        return "WARN" if exposure == "loopback" else "HIGH"
    return "HIGH" if peer_class == "public" else "WARN"


def _collect_linux():
    """The Linux collector, shaped exactly like the PowerShell one.

    "This PC" and the Connections tab ran a PowerShell blob, so on Linux every
    scan died with FileNotFoundError: 'powershell' and the tab showed
    "SCAN FAILED - this list is incomplete" (owner screenshot, 2026-08-17).
    Same fields, from /proc and `ss`, so everything downstream is unchanged.

    Without root, the kernel only reveals socket owners for OUR OWN processes —
    so `admin` reports what we actually had, and the UI's existing
    "run elevated" path still means something.
    """
    import glob
    import subprocess

    admin = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    out = {"ok": True, "admin": admin, "host": socket.gethostname(),
           "procs": {}, "conns": []}

    # --- processes: name, exe, cmdline, and the systemd unit if there is one
    for d in glob.glob("/proc/[0-9]*"):
        pid = os.path.basename(d)
        try:
            with open(os.path.join(d, "comm"), errors="replace") as fh:
                name = fh.read().strip()
        except OSError:
            continue
        try:
            path = os.readlink(os.path.join(d, "exe"))
        except OSError:
            path = ""                      # kernel thread, or not ours to see
        try:
            with open(os.path.join(d, "cmdline"), "rb") as fh:
                cmd = fh.read().replace(b"\0", b" ").decode(errors="replace").strip()
        except OSError:
            cmd = ""
        svc = ""
        try:
            with open(os.path.join(d, "cgroup"), errors="replace") as fh:
                for line in fh:
                    if ".service" in line:
                        svc = line.strip().split("/")[-1]
                        break
        except OSError:
            pass
        out["procs"][pid] = {"name": name, "rawpath": path, "pathsrc": "/proc",
                             "cmd": cmd, "svc": svc}

    # --- sockets: `ss` is the supported interface to the same tables
    try:
        res = subprocess.run(["ss", "-tunapH"], capture_output=True, text=True,
                             timeout=30)
        lines = res.stdout.splitlines()
    except (OSError, subprocess.TimeoutExpired) as ex:
        out["ok"] = False
        out["error"] = "ss: %s" % ex
        return out

    def split_addr(token):
        """'10.0.0.1:22' / '[::1]:631' / '*:*' -> (addr, port)."""
        token = token.strip()
        if token.startswith("["):
            host, _, port = token.rpartition("]:")
            return host.lstrip("["), port
        host, _, port = token.rpartition(":")
        return ("" if host in ("*", "0.0.0.0") and port == "*" else host), port

    for line in lines:
        f = line.split(None, 5)
        if len(f) < 5:
            continue
        netid, state, _rq, _sq, local = f[0], f[1], f[2], f[3], f[4]
        rest = f[5] if len(f) > 5 else ""
        peer = rest.split()[0] if rest else ""
        la, lp = split_addr(local)
        ra, rp = split_addr(peer) if peer else ("", "0")
        proto = "UDP" if netid.startswith("udp") else "TCP"
        # udp has no state column value we can use the same way
        st = {"ESTAB": "Established", "LISTEN": "Listen", "UNCONN": "Listen"}.get(
            state.upper(), state.title())
        pid = -1
        m = re.search(r"pid=(\d+)", rest)
        if m:
            pid = int(m.group(1))
        out["conns"].append({"la": la, "lp": lp, "ra": ra, "rp": rp,
                             "state": st, "pid": pid, "proto": proto,
                             "since": 0})
    return out


def scan(cfg=None):
    """One pass. Never raises: a collector that dies silently would leave the
    tab showing an all-clear it did not earn, so failure comes back as a
    populated `error` and the UI says so in place of the list."""
    cfg = cfg or gmconfig.load()
    t0 = time.time()
    base = {"ok": False, "error": "", "admin": False, "host": "", "elevated": False,
            "rows": [], "counts": {}, "deferred": 0,
            "checked_at": time.time(), "elapsed": 0.0}
    try:
        raw = (_collect_linux() if os.name != "nt"
               else _run_ps(PS_COLLECT, timeout=120))
    except Exception as ex:
        base["error"] = f"{type(ex).__name__}: {ex}"[:300]
        base["elapsed"] = round(time.time() - t0, 1)
        return base

    base["admin"] = base["elevated"] = bool(raw.get("admin"))
    base["host"] = raw.get("host") or ""
    if not raw.get("ok", True):
        base["error"] = raw.get("error") or "collector reported failure"
        base["elapsed"] = round(time.time() - t0, 1)
        return base

    procs = raw.get("procs") or {}
    for p in procs.values():
        p["path"] = _exe_of(p.get("rawpath"))
        try:
            st = os.stat(p["path"]) if p["path"] else None
            p["size"] = int(st.st_size) if st else 0
            p["mtime"] = int(st.st_mtime) if st else 0
        except OSError:
            # The path is known but unreadable from here. Not the same as
            # having no path, and not something to call clean.
            p["size"], p["mtime"] = 0, 0
    # PID 0 and 4 own real sockets (SMB, RPC) and have no image on disk. They
    # are the one case where "no path" is expected rather than suspicious.
    for k in ("0", "4"):
        if k in procs:
            procs[k]["kernel"] = True
    cache, deferred = _signatures(procs, _load_sigcache())

    conns = _aslist(raw.get("conns"))
    # (local port -> pids listening on it). Direction comes from this, because
    # a port number alone does not distinguish a server from a client.
    listeners = {}
    for c in conns:
        if str(c.get("state", "")).lower() == "listen":
            listeners.setdefault(_int(c.get("lp")), set()).add(_int(c.get("pid"), -1))

    nets = _peer_nets(cfg)
    rows = []
    for c in conns:
        state = str(c.get("state") or "")
        # `or -1` would be wrong here: pid 0 and port 0 are both real values,
        # and the falsy-default idiom silently turned every kernel-owned socket
        # into "pid -1", which then matched no process at all.
        pid = _int(c.get("pid"), -1)
        la, lp = str(c.get("la") or ""), _int(c.get("lp"))
        ra, rp = str(c.get("ra") or ""), _int(c.get("rp"))
        proto = c.get("proto") or "TCP"

        if state.lower() == "listen" or (proto == "UDP" and not ra):
            direction = "LISTEN"
        elif pid in listeners.get(lp, ()):
            direction = "IN"
        else:
            direction = "OUT"

        proc = dict(procs.get(str(pid)) or {})
        sig = cache.get(proc.get("path") or "")
        verdict, reasons = _verdict(proc, sig, cfg)

        if direction == "LISTEN":
            # For a door, what matters is how wide it is open, not who is on
            # the other side - there is nobody on the other side yet.
            wildcard = la in ("0.0.0.0", "::")
            lcls, _ = _classify_peer(la, nets)
            exposure = "world" if wildcard else (
                "loopback" if lcls == "loopback" else "this host's LAN address")
            peer_class, peer_label = ("none", exposure)
        else:
            peer_class, peer_label = _classify_peer(ra, nets)
            exposure = peer_class
        sev = _severity(direction, verdict, peer_class, exposure)

        cn, org = _cert_names((sig or {}).get("signer", ""))
        rows.append({
            "sev": sev, "dir": direction, "proto": proto, "state": state,
            "local": f"{la}:{lp}", "laddr": la, "lport": lp,
            "remote": (f"{ra}:{rp}" if ra else ""), "raddr": ra, "rport": rp,
            "peer": peer_label or peer_class, "peer_class": peer_class,
            "rdns": rdns(ra) if peer_class == "public" and ra else "",
            "pid": pid, "proc": proc.get("name") or f"pid {pid}",
            "path": proc.get("path") or "", "pathsrc": proc.get("pathsrc") or "",
            "cmd": proc.get("cmd") or "", "svc": proc.get("svc") or "",
            "signer": org or cn, "sigstatus": (sig or {}).get("status", "Pending"),
            "verdict": verdict, "why": "; ".join(r for r in reasons if r),
            "since": _int(c.get("since")),
        })

    rows.sort(key=lambda r: (SEV_ORDER.get(r["sev"], 9),
                             DIR_ORDER.get(r["dir"], 3),
                             r["proc"].lower(), r["lport"]))

    def n(pred):
        return sum(1 for r in rows if pred(r))

    base.update({
        "ok": True, "rows": rows, "deferred": deferred,
        "elapsed": round(time.time() - t0, 1), "checked_at": time.time(),
        "counts": {
            "total": len(rows),
            "inbound": n(lambda r: r["dir"] == "IN"),
            "listening": n(lambda r: r["dir"] == "LISTEN"),
            "outbound": n(lambda r: r["dir"] == "OUT"),
            "accounted": n(lambda r: r["verdict"] in ACCOUNTED),
            "review": n(lambda r: r["verdict"] == "signed"),
            "unknown": n(lambda r: r["verdict"] == "unknown"),
            "unverified": n(lambda r: r["verdict"] == "unverified"),
            "unknown_in": n(lambda r: r["dir"] == "IN" and r["verdict"] == "unknown"),
            "unknown_out": n(lambda r: r["dir"] == "OUT" and r["verdict"] == "unknown"),
            # The headline, and the number that colours the tray icon.
            #
            # `unknown` only - NOT unverified. Unelevated, unverified is a
            # fixed population of SYSTEM processes that cannot be identified no
            # matter what, so counting them here would leave the tray amber
            # forever, and a warning light that is always on is a warning light
            # nobody reads. They are not being hidden: they carry their own
            # tile, their own line in the banner, and their own mark on the tab.
            #
            # Loopback listeners are excluded too - not reachable from another
            # machine, and forty of them would bury the one that is.
            "exposed": n(lambda r: r["verdict"] == "unknown"
                         and (r["dir"] == "IN"
                              or (r["dir"] == "LISTEN" and r["peer"] != "loopback"))),
        },
    })
    return base


# ------------------------------------------------------------------ findings
def findings(lsnap, cfg=None):
    """The rows worth telling somebody about, as (key, severity, text).

    The key is deliberately coarse - it drops the remote ephemeral port and the
    pid, so a program that reconnects every thirty seconds is ONE finding that
    persists rather than a hundred identical alerts. That is the same reason
    the fleet notifier diffs conditions instead of announcing state."""
    cfg = cfg or gmconfig.load()
    lw = cfg.get("local_watch", {})
    alert_out = lw.get("alert_outbound", True)
    alert_unver = lw.get("alert_unverified", False)
    out = []
    for r in lsnap.get("rows", []):
        v = r["verdict"]
        if v not in UNACCOUNTED:
            continue
        if v == "unverified" and not alert_unver:
            continue
        who = r["proc"] + (f" ({r['path']})" if r["path"] else "")
        if r["dir"] == "IN":
            peer = r["raddr"] + (f" [{r['rdns']}]" if r["rdns"] else "")
            text = (f"unidentified inbound {r['proto']} from {peer} "
                    f"to port {r['lport']} - {who}; {r['why']}")
        elif r["dir"] == "LISTEN":
            if r["peer"] == "loopback":
                continue            # not reachable from another machine
            text = (f"unidentified {r['proto']} listener on {r['local']} "
                    f"({r['peer']}) - {who}; {r['why']}")
        else:
            if not alert_out or r["peer_class"] != "public":
                continue
            peer = r["raddr"] + (f" [{r['rdns']}]" if r["rdns"] else "")
            text = (f"unidentified outbound {r['proto']} to {peer}:{r['rport']} "
                    f"- {who}; {r['why']}")
        key = "|".join([r["dir"], r["proto"],
                        str(r["lport"]) if r["dir"] != "OUT" else "",
                        r["raddr"], (r["path"] or r["proc"]).lower()])
        out.append((key, r["sev"], text))
    return out


# ------------------------------------------------- established, non-system
_PORT_NAMES = {}


def port_label(port, proto="tcp"):
    """'443 https'. Read from the local services file, so it works offline and
    never becomes a guess dressed up as a fact - an unnamed port stays a bare
    number rather than being labelled from a table we invented."""
    key = (port, proto)
    if key not in _PORT_NAMES:
        try:
            _PORT_NAMES[key] = socket.getservbyport(port, proto)
        except (OSError, OverflowError, TypeError):
            _PORT_NAMES[key] = ""
    name = _PORT_NAMES[key]
    return f"{port} {name}" if name else str(port)


def service_port(r):
    """The port that says WHAT is being talked to.

    Outbound that is the remote port; inbound it is ours. The other end is an
    ephemeral number the OS picked, and ranking by it would produce a chart of
    49152-and-friends that means nothing."""
    return r["rport"] if r["dir"] == "OUT" else r["lport"]


def established(lsnap, include_trusted=True):
    """Every established session whose owner is NOT a registered system service.

    Listeners are excluded on purpose: an open port is not a connection, it is
    the possibility of one, and mixing the two makes both counts wrong."""
    out = []
    for r in lsnap.get("rows", []):
        if r["state"] != "Established" or r["verdict"] == "system":
            continue
        if not include_trusted and r["verdict"] == "allowed":
            continue
        out.append(r)
    return out


def _rank(rows, keyfn, labelfn, top=8):
    """Top N by count as (label, count, is_residual) triples.

    Everything past N is FOLDED into one 'other' row rather than truncated: a
    chart that silently drops its tail implies the tail is empty. But the
    residual is flagged, because on a machine with many peers it is routinely
    larger than the top-ranked item, and a bar at the bottom that is longer
    than the one at the top makes a descending chart look broken. The flag
    lets the chart draw it as a leftover instead of a rank."""
    tally, labels = {}, {}
    for r in rows:
        k = keyfn(r)
        if k in (None, ""):
            continue
        tally[k] = tally.get(k, 0) + 1
        labels.setdefault(k, labelfn(r))
    ranked = sorted(tally.items(), key=lambda kv: (-kv[1], str(labels[kv[0]]).lower()))
    head = [(labels[k], v, False) for k, v in ranked[:top]]
    tail = sum(v for _k, v in ranked[top:])
    if tail:
        head.append((f"other ({len(ranked) - top})", tail, True))
    return head


def connection_stats(rows, now=None):
    """Aggregates for the Connections tab: totals, spread, age, and rankings."""
    now = now or time.time()
    ages = [now - r["since"] for r in rows if r["since"]]
    peers = {r["raddr"] for r in rows if r["raddr"]}
    by_class = {}
    for r in rows:
        by_class[r["peer_class"]] = by_class.get(r["peer_class"], 0) + 1
    top_prog = _rank(rows, lambda r: (r["path"] or r["proc"]).lower(),
                     lambda r: r["proc"])
    ranked_progs = [t for t in top_prog if not t[2]]
    return {
        "total": len(rows),
        "programs": len({(r["path"] or r["proc"]).lower() for r in rows}),
        "hosts": len(peers),
        "public": by_class.get("public", 0),
        # Distinct public HOSTS, not connections to them. The two differ by an
        # order of magnitude on a browser-heavy machine, and putting a
        # connection count under a "remote hosts" heading reads as impossible.
        "public_hosts": len({r["raddr"] for r in rows
                             if r["raddr"] and r["peer_class"] == "public"}),
        "lan": by_class.get("lan", 0) + by_class.get("known", 0),
        "loopback": by_class.get("loopback", 0),
        "inbound": sum(1 for r in rows if r["dir"] == "IN"),
        "unknown": sum(1 for r in rows if r["verdict"] == "unknown"),
        "oldest": max(ages) if ages else 0,
        "newest": min(ages) if ages else 0,
        # Anything opened in the last five minutes. On a tab you glance at
        # while something is going wrong, "what just started" is the question.
        "recent": sum(1 for a in ages if a <= 300),
        "busiest": (ranked_progs[0][0], ranked_progs[0][1]) if ranked_progs
                   else ("-", 0),
        "by_program": top_prog,
        "by_host": _rank(rows, lambda r: r["raddr"],
                         lambda r: r["rdns"] or r["raddr"]),
        "by_port": _rank(rows, service_port,
                         lambda r: port_label(service_port(r),
                                              r["proto"].lower())),
    }


def human_age(seconds):
    s = int(max(0, seconds))
    if s < 90:
        return f"{s}s"
    if s < 5400:
        return f"{s // 60}m"
    if s < 172800:
        return f"{s // 3600}h"
    return f"{s // 86400}d"


def trust_image(path, cfg=None):
    """Add an image to the allowlist and persist it."""
    cfg = cfg or gmconfig.load()
    imgs = cfg.setdefault("local_watch", {}).setdefault("trusted_images", [])
    if path and path.lower() not in {str(p).lower() for p in imgs}:
        imgs.append(path)
        gmconfig.save(cfg)
    return cfg


def untrust_image(path, cfg=None):
    cfg = cfg or gmconfig.load()
    lw = cfg.setdefault("local_watch", {})
    imgs = lw.setdefault("trusted_images", [])
    keep = [p for p in imgs if str(p).lower() != str(path).lower()]
    if len(keep) != len(imgs):
        lw["trusted_images"] = keep
        gmconfig.save(cfg)
    return cfg


def scan_elevated(timeout=180):
    """Re-run the scan as administrator, through one UAC prompt.

    Worth its own path because unelevated the SYSTEM-owned non-service
    processes - lsass, wininit, csrss, dasHost - cannot be identified at all,
    and 'cannot identify' is the one verdict an operator cannot act on."""
    out = os.path.join(HERE, "elevated_scan.tmp")
    try:
        os.remove(out)
    except OSError:
        pass
    # Frozen, gmlocal.py does not exist on disk to be handed to an interpreter -
    # the exe re-runs ITSELF with --local-scan and gmtray's entry point routes
    # it here. From source it is the interpreter plus the script, as before.
    cmd = gmpaths.relaunch_argv("--local-scan", "--out", out)
    exe, rest = cmd[0], cmd[1:]
    args = ",".join("'" + str(a).replace("'", "''") + "'" for a in rest)
    ps = (f"Start-Process -FilePath '{exe}' -ArgumentList {args} "
          f"-Verb RunAs -WindowStyle Hidden -Wait")
    enc = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
         "Bypass", "-EncodedCommand", enc],
        capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        with open(out, "r", encoding="utf-8") as f:
            snap = json.load(f)
        os.remove(out)
        return snap
    except (OSError, ValueError):
        err = (r.stderr or b"").decode("utf-8", "replace").strip()
        # A declined UAC prompt is a choice, not a fault, and must not be
        # dressed up as a scanner failure.
        return {"ok": False, "rows": [], "counts": {}, "admin": False,
                "elevated": False, "checked_at": time.time(), "elapsed": 0.0,
                "deferred": 0, "host": "",
                "error": "elevated scan did not run"
                         + (f": {err[:160]}" if err else " (UAC declined?)")}


if __name__ == "__main__":
    s = scan()
    if "--out" in sys.argv:
        dest = sys.argv[sys.argv.index("--out") + 1]
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(s, f)
        sys.exit(0 if s["ok"] else 1)
    if "--json" in sys.argv:
        print(json.dumps(s, indent=2))
        sys.exit(0 if s["ok"] else 1)
    if not s["ok"]:
        print("local scan FAILED:", s["error"])
        sys.exit(1)
    c = s["counts"]
    print(f"{s['host']}  {'ELEVATED' if s['admin'] else 'not elevated'}  {s['elapsed']}s")
    print(f"{c['total']} sockets: {c['inbound']} in, {c['listening']} listening, "
          f"{c['outbound']} out")
    print(f"accounted {c['accounted']}   review {c['review']}   "
          f"unknown {c['unknown']}   unverified {c['unverified']}   "
          f"EXPOSED {c['exposed']}\n")
    show = s["rows"] if "--all" in sys.argv else \
        [r for r in s["rows"] if r["verdict"] not in ACCOUNTED]
    print(f"{'SEV':<5}{'DIR':<7}{'LOCAL':<22}{'REMOTE':<22}{'PROC':<22}WHY")
    print("-" * 128)
    for r in show:
        print(f"{r['sev']:<5}{r['dir']:<7}{r['local'][:21]:<22}"
              f"{(r['remote'] or r['peer'])[:21]:<22}{r['proc'][:21]:<22}"
              f"{r['why'][:48]}")
    print(f"\n{len(show)} row(s) shown"
          + (f", {s['deferred']} image(s) still to verify" if s["deferred"] else ""))
    fs = findings(s)
    if fs:
        print(f"\n{len(fs)} would alert:")
        for _k, sev, t in fs:
            print(f"  {sev:<5} {t[:110]}")
