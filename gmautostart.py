#!/usr/bin/env python3
r"""
gmautostart - register Infra Monitor to start itself at logon, and unregister it.

AT LOGON, NOT AT BOOT
A tray monitor lives in the notification area, which belongs to an interactive
user session. There is nothing for it to attach to before somebody signs in, so
"start on boot" for this kind of program means "start when the user signs in".
Everything here says logon rather than boot on purpose: a run-at-boot service
would have no tray icon, no dashboard and no toasts - it would be a different
program.

WHERE
    HKCU\Software\Microsoft\Windows\CurrentVersion\Run    value "InfraMonitor"

Per-user and unprivileged: no UAC prompt, no scheduled task, no installer, and
removing it is deleting one registry value. HKLM and a SYSTEM scheduled task
were both rejected - they need elevation to install and they start the app in
the wrong session or for the wrong account.

THE SETTING WINS, NOT THE CODE
Registration is driven by `autostart` in machines.json, not by "is it
registered right now". If the app simply re-registered itself whenever it found
no entry, then turning autostart OFF would be silently undone at the next
launch, and a switch that flips itself back is worse than no switch. So `sync`
makes the registry match the config in BOTH directions: it registers when the
setting is on, and removes a stale entry when the setting is off.

It also rewrites the entry when the path no longer matches - moving or
rebuilding the exe otherwise leaves a logon entry pointing at a file that is
gone, which fails silently every morning.

Failure here is never fatal. A monitor that refuses to start because it could
not write a convenience setting has its priorities backwards; the caller logs
what happened and carries on.
"""

import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gmpaths

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "InfraMonitor"


def desired_command():
    """The exact command line the logon entry should hold.

    Quoted, because the app very plausibly lives under a path with a space in
    it and an unquoted Run value is split on the first one - which turns
    "C:\\Program Files\\InfraMonitor.exe" into an attempt to run "C:\\Program".

    From source it prefers pythonw.exe: python.exe would pop a console window
    at every logon, which is exactly the thing a tray app must not do."""
    if gmpaths.frozen():
        return f'"{os.path.realpath(sys.executable)}"'
    exe = sys.executable or "python.exe"
    cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.isfile(cand):
        exe = cand
    return f'"{exe}" "{os.path.join(gmpaths.APP_DIR, "gmtray.py")}"'


def _winreg():
    if os.name != "nt":
        return None
    try:
        import winreg
        return winreg
    except ImportError:
        return None


def current_command():
    """What is registered right now, or None."""
    winreg = _winreg()
    if not winreg:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            val, _t = winreg.QueryValueEx(k, VALUE_NAME)
            return val
    except FileNotFoundError:
        return None
    except OSError:
        return None


def register():
    """Point the logon entry at this copy of the app. Returns the command."""
    winreg = _winreg()
    if not winreg:
        raise OSError("no registry on this platform")
    cmd = desired_command()
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, VALUE_NAME, 0, winreg.REG_SZ, cmd)
    return cmd


def unregister():
    """Remove the logon entry. Absent is success, not an error."""
    winreg = _winreg()
    if not winreg:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, VALUE_NAME)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


def status():
    """(enabled_in_registry, registered_command, points_at_this_copy)."""
    cur = current_command()
    return bool(cur), cur, (cur == desired_command() if cur else False)


def sync(cfg):
    """Make the registry agree with the `autostart` setting.

    Returns a short string for the log, or None when nothing needed doing."""
    want = cfg.get("autostart", True)
    cur = current_command()
    if want:
        desired = desired_command()
        if cur == desired:
            return None
        try:
            register()
        except OSError as ex:
            return f"could NOT register autostart: {ex}"
        return ("autostart registered at logon" if not cur
                else f"autostart path updated (was {cur})")
    if cur:
        return ("autostart removed at logon" if unregister()
                else "autostart removal FAILED")
    return None


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--register" in args:
        print("registered:", register())
    elif "--unregister" in args:
        print("removed" if unregister() else "was not registered")
    else:
        on, cmd, mine = status()
        print(f"registered : {on}")
        print(f"command    : {cmd or '-'}")
        print(f"this copy  : {mine}")
        print(f"would use  : {desired_command()}")
