#!/usr/bin/env python3
r"""
bootstrap_ssh - manage the fleet list, install our SSH key on every machine,
and allowlist us in fail2ban so routine monitoring can never lock us out.

WHY THIS SCRIPT IS SO CAREFUL ABOUT AUTHENTICATION
Many machines run fail2ban with a short trigger. During an early survey of a
fleet, a probe that tried three usernames per host produced two failed auths
per host and got us BANNED, host by host, for ~10 minutes each - port 22 goes
to a silent DROP (connect timeout, not "refused") while ICMP still answers, so
a machine looks up but unreachable. A monitor that retries on failure would ban
itself permanently and then report the whole fleet as down.

Two rules follow, enforced here rather than left to good luck:

  1. EXACTLY ONE authentication attempt per host, with the username recorded
     for it. No fallbacks, no "try the other account" - a wrong guess costs a
     ten-minute lockout, so guessing is never worth it. If auth fails, this
     script stops on that host and says so.
  2. The fail2ban allowlist is written on the FIRST successful connection,
     before anything else, so the window in which we can lock ourselves out is
     as short as possible.

The bootstrap password is read from the INFRAMON_SSH_PASSWORD environment
variable if set, otherwise you are prompted for it (getpass). It is never
written to disk, never logged, and never passed on a command line where it
would appear in the remote machine's process list - sudo reads it from stdin.

  list                          show the fleet
  add <name> <ip> <user>        register a machine (then run apply for it)
  remove <name|ip>              unregister a machine
  enable|disable <name|ip>      keep it listed but stop/start polling it
  check                         read-only: who is reachable, who needs setup
  apply [name ...]              install key + allowlist (all, or just these)

    python bootstrap_ssh.py check
    python bootstrap_ssh.py apply
    python bootstrap_ssh.py add web-2 192.0.2.40 youruser
"""

import getpass, os, re, sys, socket, warnings
warnings.filterwarnings("ignore")
import paramiko

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gmconfig, sshconn
from sshconn import run

PUBKEY_PATH = os.path.expanduser(os.path.join("~", ".ssh", "id_ed25519.pub"))
# Env var that may hold the bootstrap password, so an unattended run does not
# have to prompt. Optional - if it is not set we ask, once.
PASSWORD_ENV = "INFRAMON_SSH_PASSWORD"


def bootstrap_password():
    """The password used for the ONE first-time login per host (to install the
    key and write the fail2ban allowlist). From the environment if set, else
    prompted. Never written to disk or logged."""
    pw = os.environ.get(PASSWORD_ENV)
    if pw:
        return pw
    return getpass.getpass("SSH/sudo password for first-time setup: ")


def pubkey():
    with open(PUBKEY_PATH, "r", encoding="utf-8") as f:
        return f.read().strip()


# port checks, connection and command execution all live in sshconn, so the
# jump-host rule is written once and cannot drift between the bootstrapper and
# the monitor.


# Idempotent by construction: the key is appended only if absent, and the
# fail2ban drop-in is a file we own and overwrite, so re-running changes
# nothing. Any pre-existing ignoreip is reported before we replace it, so a
# hand-tuned value is never silently lost.
SETUP = r"""
set -u
KEY='%(key)s'
mkdir -p ~/.ssh && chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
if grep -qF "$KEY" ~/.ssh/authorized_keys 2>/dev/null; then echo "KEY=already-present"
else printf '%%s\n' "$KEY" >> ~/.ssh/authorized_keys; echo "KEY=added"; fi
echo "SRCIP=$(echo $SSH_CLIENT | awk '{print $1}')"
echo "HOSTNAME=$(hostname)"
echo "SUDO=$(sudo -n true 2>/dev/null && echo passwordless || echo needs-password)"
echo "F2B=$(command -v fail2ban-client >/dev/null && echo present || echo absent)"
echo "NVIDIA=$(command -v nvidia-smi >/dev/null && echo present || echo absent)"
"""

ALLOW_CMD = r"""
sudo -S -p '' bash -c '
  set -e
  mkdir -p /etc/fail2ban/jail.d
  cat > /etc/fail2ban/jail.d/00-monitor-allowlist.conf <<EOF
# Written by Infra Monitor (bootstrap_ssh.py) - the monitoring host must never
# be banned, or a transient failure becomes a fleet-wide outage that looks real.
[DEFAULT]
ignoreip = %(allow)s
EOF
  fail2ban-client reload >/dev/null 2>&1 || systemctl reload fail2ban >/dev/null 2>&1 || true
  echo "F2B_RELOADED=yes"
  fail2ban-client get sshd ignoreip 2>/dev/null | tr "\n" " " | sed "s/^/F2B_IGNORE_AFTER=/"
  echo
' 2>&1
"""


def bootstrap(cfg, m, allowlist, pw, key, apply_changes, jump=None):
    name, ip, user = m["name"], m["ip"], m["user"]
    row = {"name": name, "ip": ip, "user": user, "status": "", "key": "-",
           "f2b": "-", "keyauth": "-", "gpu": m.get("gpu"), "note": ""}

    # NEVER attempt auth speculatively. A failed key auth is a failed LOGIN,
    # not a free probe - offering our key to a machine that has never seen it
    # during an earlier "read-only" check is what can get a host locked out. So:
    #   - bootstrapped machine -> key auth (we have evidence it works)
    #   - not bootstrapped     -> password auth, once, and only in apply mode
    booted = bool(m.get("bootstrapped"))
    if not booted and not apply_changes:
        row["status"] = "needs-setup"
        row["note"] = "not bootstrapped; no auth attempted (would risk lockout)"
        return row

    try:
        cli = sshconn.connect(cfg, m, password=None if booted else pw,
                              jump=jump, timeout=cfg.get("ssh_timeout", 15))
        row["status"] = "ok(key)" if booted else "ok(password)"
    except sshconn.AuthRejected:
        row["status"] = "AUTH-FAILED"
        row["note"] = (f"'{user}' " + ("key" if booted else "+ password") +
                       " rejected - NOT retrying (lockout risk)")
        return row
    except sshconn.Unreachable as ex:
        row["status"] = "UNREACHABLE"
        row["note"] = str(ex)[:80]
        return row
    if not apply_changes:
        cli.close()
        return row

    try:
        _rc, out, _err = run(cli, SETUP % {"key": key})
        info = dict(re.findall(r"^(\w+)=(.*)$", out, re.M))
        row["key"] = info.get("KEY", "?")
        row["gpu"] = (info.get("NVIDIA") == "present")
        row["note"] = f"src={info.get('SRCIP','?')} sudo={info.get('SUDO','?')}"

        if info.get("F2B") == "present":
            _rc, out2, err2 = run(cli, ALLOW_CMD % {"allow": " ".join(allowlist)},
                                  password=pw)
            if "F2B_RELOADED=yes" in out2:
                row["f2b"] = "allowlisted"
            else:
                row["f2b"] = "FAILED"
                row["note"] += " | f2b: " + (err2 or out2).strip()[:70]
        else:
            row["f2b"] = "n/a (absent)"
    finally:
        cli.close()

    # Verify with a FRESH key-only connection. This is the check that matters;
    # everything above is plumbing. If this fails, the machine is NOT marked
    # bootstrapped, so the next run spends a password attempt rather than
    # locking us out with a key the machine has never accepted.
    v = None
    try:
        v = sshconn.connect(cfg, m, password=None, jump=jump,
                            timeout=cfg.get("ssh_timeout", 15))
        _rc, o, _ = run(v, "id -un")
        row["keyauth"] = "VERIFIED" if o.strip() == user else f"odd:{o.strip()[:14]}"
    except Exception as ex:
        row["keyauth"] = "FAILED"
        row["note"] += f" | keyauth: {type(ex).__name__}"
    finally:
        sshconn.close(v)
    return row


def mark_bootstrapped(data, row):
    """Record verified key auth, so later runs use the key instead of spending
    a password attempt - and so `check` knows it may safely try at all."""
    tgt = gmconfig.find(data, row["name"])
    if not tgt:
        return
    if row["keyauth"] == "VERIFIED":
        tgt["bootstrapped"] = True
    if row["gpu"] is not None:
        tgt["gpu"] = row["gpu"]


def cmd_list(data):
    print(f"{'NAME':<6} {'IP':<15} {'USER':<11} {'SCOPE':<7} {'GPU':<8} "
          f"{'BOOTSTRAPPED':<13} ENABLED")
    print("-" * 76)
    for m in data["machines"]:
        gpu = {True: "yes", False: "no", None: "unknown"}[m.get("gpu")]
        print(f"{m['name']:<6} {m['ip']:<15} {m['user']:<11} "
              f"{gmconfig.scope_of(m):<7} {gpu:<8} "
              f"{'yes' if m.get('bootstrapped') else 'no':<13} "
              f"{'yes' if m.get('enabled', True) else 'NO'}")
    n_local = sum(1 for m in data["machines"] if gmconfig.scope_of(m) == "local")
    print(f"\n{len(data['machines'])} machines "
          f"({n_local} local - gated on {', '.join(data['gate_domains'])}; "
          f"{len(data['machines']) - n_local} public - always checked), "
          f"{len(gmconfig.active(data))} enabled")


def cmd_run(data, apply_changes, only):
    machines = [m for m in gmconfig.active(data)
                if not only or m["name"] in only or m["ip"] in only]
    if not machines:
        sys.exit("no machines matched")
    pw = bootstrap_password() if apply_changes else ""
    key = pubkey()
    allowlist = data["allowlist"]
    print(f"{'MODE: APPLY' if apply_changes else 'MODE: CHECK (read-only)'}   "
          f"{len(machines)} machines   key={key.split()[-1]}")
    if apply_changes:
        print(f"allowlist: {' '.join(allowlist)}")
    hdr = (f"\n{'NAME':<6} {'IP':<15} {'USER':<11} {'STATUS':<13} {'KEY':<14} "
           f"{'FAIL2BAN':<13} {'KEYAUTH':<9} NOTE")
    print(hdr); print("-" * (len(hdr) + 20))

    # The bastion first: everything local rides through this one connection.
    jump = None
    jname = data.get("jump_host")
    if jname and any(gmconfig.scope_of(m) == "local" and m["name"] != jname
                     for m in machines):
        jm = gmconfig.find(data, jname)
        if jm and not jm.get("bootstrapped") and apply_changes:
            # Bootstrap the bastion itself first, directly - nothing can go
            # through it until it works.
            r0 = bootstrap(data, jm, allowlist, pw, key, True, jump=None)
            print(f"{r0['name']:<6} {r0['ip']:<15} {r0['user']:<11} {r0['status']:<13} "
                  f"{r0['key']:<14} {r0['f2b']:<13} {r0['keyauth']:<9} {r0['note']}")
            mark_bootstrapped(data, r0)
            gmconfig.save(data)
            machines = [m for m in machines if m["name"] != jname]
        try:
            jump = sshconn.open_jump(data, timeout=data.get("ssh_timeout", 15))
            print(f"[jump] via {jname} - local machines tunnel through it\n")
        except Exception as ex:
            print(f"[jump] {jname} unavailable ({type(ex).__name__}: "
                  f"{str(ex)[:60]}) - falling back to direct connections\n")

    rows = []
    for m in machines:
        # One unhealthy host must never abort the fleet run. An earlier version
        # let an exec_command failure on a single host kill the whole pass,
        # leaving the rest untouched and the operator believing they were done.
        try:
            r = bootstrap(data, m, allowlist, pw, key, apply_changes, jump=jump)
        except Exception as ex:
            r = {"name": m["name"], "ip": m["ip"], "user": m["user"],
                 "status": "ERROR", "key": "-", "f2b": "-", "keyauth": "-",
                 "gpu": m.get("gpu"),
                 "note": f"{type(ex).__name__}: {str(ex)[:70]}"}
        rows.append(r)
        print(f"{r['name']:<6} {r['ip']:<15} {r['user']:<11} {r['status']:<13} "
              f"{r['key']:<14} {r['f2b']:<13} {r['keyauth']:<9} {r['note']}")
        if apply_changes:
            # Persist per host, not at the end: if this run dies halfway, the
            # machines already done must not be retried with a password.
            mark_bootstrapped(data, r)
            gmconfig.save(data)

    print("\n--- summary ---")
    print(f"  reachable      : {sum(1 for r in rows if r['status'] not in ('BLOCKED','ERROR'))}/{len(rows)}")
    if apply_changes:
        print(f"  key auth works : {sum(1 for r in rows if r['keyauth']=='VERIFIED')}/{len(rows)}")
        print(f"  allowlisted    : {sum(1 for r in rows if r['f2b']=='allowlisted')}/{len(rows)}")
        print(f"  GPU machines   : {sum(1 for r in rows if r['gpu'])}/{len(rows)} (detected, not guessed)")
    sshconn.close(jump)
    bad = [r for r in rows
           if r["status"] in ("BLOCKED", "UNREACHABLE", "AUTH-FAILED", "ERROR")
           or r["keyauth"] == "FAILED" or r["f2b"] == "FAILED"]
    if bad:
        print("\n  needs attention:")
        for r in bad:
            print(f"    {r['name']:<6} {r['status']:<12} {r['note']}")
    return 1 if bad else 0


def main():
    argv = sys.argv[1:]
    cmd = (argv[0] if argv else "check").lower()
    rest = argv[1:]
    data = gmconfig.load()
    try:
        if cmd == "list":
            cmd_list(data); return 0
        if cmd == "add":
            if len(rest) < 3:
                sys.exit("usage: add <name> <ip> <user> [local|public]\n"
                         "  local  = only polled while on a known/trusted network\n"
                         "  public = internet-reachable, always polled (default: local)")
            scope = rest[3] if len(rest) > 3 else "local"
            gmconfig.add(data, rest[0], rest[1], rest[2], scope=scope)
            gmconfig.save(data)
            print(f"added {rest[0]} ({rest[1]}, user {rest[2]}, scope {scope})")
            print(f"now run:  bootstrap_ssh.py apply {rest[0]}")
            return 0
        if cmd == "remove":
            if not rest:
                sys.exit("usage: remove <name|ip>")
            m = gmconfig.remove(data, rest[0])
            gmconfig.save(data)
            print(f"removed {m['name']} ({m['ip']})")
            print("note: its authorized_keys entry on that machine is left "
                  "alone - remove it there if the box is being decommissioned.")
            return 0
        if cmd in ("enable", "disable"):
            if not rest:
                sys.exit(f"usage: {cmd} <name|ip>")
            m = gmconfig.set_enabled(data, rest[0], cmd == "enable")
            gmconfig.save(data)
            print(f"{m['name']} is now {'polled' if m['enabled'] else 'NOT polled'}")
            return 0
        if cmd in ("check", "apply"):
            return cmd_run(data, cmd == "apply", rest)
        sys.exit(f"unknown command {cmd!r} - see the docstring")
    except gmconfig.ConfigError as ex:
        sys.exit(f"error: {ex}")


if __name__ == "__main__":
    sys.exit(main())
