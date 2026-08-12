#!/usr/bin/env python3
r"""
gmnotify - Windows toast alerts for fleet state changes.

ALERT ON TRANSITIONS, NOT ON STATE
A monitor that toasts "host disk 97% full" every two minutes trains you to
dismiss it without reading, and then the one that mattered gets dismissed too.
So this fires only when a machine's condition CHANGES: healthy -> problem,
problem -> healthy, or the problem itself changing. Steady-state faults stay
visible in the tray dashboard, silently.

Recovery is announced as well as failure. Knowing a box came back matters as
much as knowing it went away, and without it you cannot tell a fixed problem
from a monitor that stopped running.

No third-party dependency: the toast is built as XML and handed to the WinRT
notifier through PowerShell, which every Windows 10/11 box already has.
"""

import json, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gmpaths

STATE_PATH = os.path.join(gmpaths.APP_DIR, "alert_state.json")
# A separate file from the fleet state, not another key inside it: that one is
# keyed by machine name, and a local finding key colliding with a hostname
# would silently swallow one of them.
LOCAL_STATE_PATH = os.path.join(gmpaths.APP_DIR, "alert_state_local.json")
# How long a finding is remembered after it stops being seen. A connection that
# comes and goes every few minutes must not re-alert each time it returns; one
# that has genuinely been gone for a day is news again if it comes back.
LOCAL_FORGET_SECONDS = 24 * 3600

# Toasts need a registered AppUserModelID. Borrowing PowerShell's own is the
# standard trick - registering a bespoke one needs a Start Menu shortcut, which
# is far more machinery than a monitor warrants.
APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"

PS_TOAST = r"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] > $null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml(@'
%(toastxml)s
'@)
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('%(appid)s').Show($toast)
"""


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;"))


def toast(title, lines, urgent=False):
    """Show one toast. Returns True if Windows accepted it."""
    body = "\n".join(str(l) for l in lines)[:400]
    scenario = "urgent" if urgent else "default"
    sound = "Looping.Alarm2" if urgent else "Default"
    # Precomputed so no backslash appears inside an f-string expression - that
    # is a syntax error before Python 3.12 (PEP 701), and this app is frozen on
    # whatever interpreter the build box has.
    loop_attr = ' loop="false"' if urgent else ''
    xml = (f'<toast scenario="{scenario}">'
           f'<visual><binding template="ToastGeneric">'
           f'<text>{_esc(title)}</text>'
           f'<text>{_esc(body)}</text>'
           f'</binding></visual>'
           f'<audio src="ms-winsoundevent:Notification.{sound}"'
           f'{loop_attr}/>'
           f'</toast>')
    script = PS_TOAST % {"toastxml": xml, "appid": APP_ID}
    try:
        # stdin pinned: a --windowed frozen build has no console, so inherited
        # standard handles are invalid.
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-ExecutionPolicy", "Bypass", "-Command", script],
                           capture_output=True, stdin=subprocess.DEVNULL,
                           timeout=25,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.returncode == 0
    except Exception:
        return False


# ------------------------------------------------------------------ state diff
def load_state(path=STATE_PATH):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state, path=STATE_PATH):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, path)


def condition(r):
    """One comparable string per machine. Machines the gate told us not to
    check return None - 'not looked at' must never be diffed against 'healthy',
    or closing the laptop lid would fire a fleet-wide recovery storm."""
    if not r.get("checked"):
        return None
    if not r.get("up"):
        return "DOWN"
    return "OK" if not r["problems"] else "PROBLEM: " + "; ".join(sorted(r["problems"]))


def diff(snapshot, state):
    """(events, new_state). An event is (machine, kind, text)."""
    events, new = [], dict(state)
    for r in snapshot["machines"]:
        cond = condition(r)
        if cond is None:
            continue                       # skipped - carry the old value over
        prev = state.get(r["name"])
        new[r["name"]] = cond
        if prev is None:
            # First sighting. Announce a fault, stay quiet about health - a
            # fresh install must not toast fifteen times to say "all fine".
            if cond != "OK":
                events.append((r["name"], "new", cond))
            continue
        if prev == cond:
            continue
        if cond == "OK":
            events.append((r["name"], "recovered", "back to normal"))
        elif prev == "OK":
            events.append((r["name"], "failed", cond))
        else:
            events.append((r["name"], "changed", cond))
    return events, new


def notify(snapshot, state_path=STATE_PATH, dry_run=False):
    state = load_state(state_path)
    events, new = diff(snapshot, state)
    if not events:
        return []

    down = [e for e in events if e[1] in ("failed", "new", "changed")]
    up = [e for e in events if e[1] == "recovered"]
    # Anything mentioning a foreign session is a possible intrusion and gets
    # its own urgent toast rather than being buried in a list of disk warnings.
    intrusions = [e for e in down if "FOREIGN SESSION" in e[2]]

    if not dry_run:
        if intrusions:
            toast("SECURITY: unexpected SSH session",
                  [f"{n}: {t}" for n, _k, t in intrusions], urgent=True)
        other = [e for e in down if e not in intrusions]
        if other:
            toast(f"Fleet problem ({len(other)} machine{'s' if len(other) > 1 else ''})",
                  [f"{n}: {t[:90]}" for n, _k, t in other], urgent=False)
        if up:
            toast(f"Recovered ({len(up)})", [f"{n}: {t}" for n, _k, t in up])
        save_state(new, state_path)
    return events


# ------------------------------------------------- this machine's connections
def notify_local(lsnap, cfg=None, state_path=LOCAL_STATE_PATH, dry_run=False):
    """Toast the unidentified connections to THIS machine, once each.

    Same rule as the fleet: alert on the transition, not on the state. The
    finding key deliberately ignores the remote ephemeral port and the pid, so
    a program that reconnects every thirty seconds is one alert that stays
    open, not a hundred identical ones - see gmlocal.findings().

    An established INBOUND session is separated from a merely-open port and
    given the urgent toast. Somebody being in is a different event from a door
    being unlocked, and burying the first under a list of the second is how the
    one that matters gets dismissed."""
    import gmlocal
    if not lsnap or not lsnap.get("ok"):
        return []                          # a failed scan has nothing to say
    state = load_state(state_path)
    now = int(time.time())
    events, new = [], {}
    for key, sev, text in gmlocal.findings(lsnap, cfg):
        new[key] = now
        if key not in state:
            events.append((key, sev, text))
    # Carry forward anything recently seen, so a finding that flickers does not
    # re-announce itself the moment it comes back.
    for key, seen in state.items():
        if key not in new and now - int(seen or 0) < LOCAL_FORGET_SECONDS:
            new[key] = seen
    if not events:
        if not dry_run and new != state:
            save_state(new, state_path)
        return []

    if not dry_run:
        # Urgent is reserved for somebody actually being IN from off this
        # machine. A loopback session scores WARN and rides the normal toast,
        # because an alarm that sounds for a local agent talking to itself is
        # an alarm you learn to silence.
        inbound = [e for e in events
                   if e[0].startswith("IN|") and e[1] in ("CRIT", "HIGH")]
        rest = [e for e in events if e not in inbound]
        if inbound:
            toast("SECURITY: unidentified connection to this PC",
                  [t for _k, _s, t in inbound[:5]]
                  + ([f"...and {len(inbound) - 5} more"] if len(inbound) > 5 else []),
                  urgent=True)
        if rest:
            toast(f"Unidentified on this PC ({len(rest)})",
                  [t[:110] for _k, _s, t in rest[:5]]
                  + ([f"...and {len(rest) - 5} more"] if len(rest) > 5 else []))
        save_state(new, state_path)
    return events


if __name__ == "__main__":
    if "--local" in sys.argv:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import gmlocal
        snap = gmlocal.scan()
        if not snap["ok"]:
            print("local scan FAILED:", snap["error"])
            sys.exit(1)
        evs = notify_local(snap, dry_run="--dry-run" in sys.argv)
        print(f"{len(evs)} new local finding(s)")
        for _k, sev, t in evs:
            print(f"  {sev:<5} {t[:100]}")
        sys.exit(0)
    if "--test" in sys.argv:
        ok = toast("Infra Monitor test", ["If you can see this, toasts work.",
                                   "Alerts fire only on state changes."])
        print("toast shown" if ok else "toast FAILED")
        sys.exit(0 if ok else 1)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import gmcheck
    snap = gmcheck.check_all()
    evs = notify(snap, dry_run="--dry-run" in sys.argv)
    print(f"{len(evs)} change(s)")
    for n, k, t in evs:
        print(f"  {n:<8} {k:<10} {t[:80]}")
