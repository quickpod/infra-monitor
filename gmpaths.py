#!/usr/bin/env python3
r"""
gmpaths - where this app's files actually live.

THE ONE THING A FROZEN BUILD BREAKS
Every module here used to find its data with

    os.path.dirname(os.path.abspath(__file__))

which is correct when running from source and WRONG the moment PyInstaller
freezes it. Under `--onefile` the bundle unpacks itself into a fresh temporary
directory (`sys._MEIPASS`) on every launch, and `__file__` points inside it. So
machines.json would be read from a throwaway copy, inframonitor.log would be
written to a directory that is deleted on exit, and every setting saved from the
Settings window - or every image trusted on the This PC tab - would vanish
silently when the process ended. Silently is the problem: nothing errors, the
save appears to work, and the setting is simply gone next launch.

Frozen, the answer is the directory holding the EXE. That is where the user
put Infra Monitor, where machines.json sits next to it, and where it stays
across upgrades of the exe itself.

APP_DIR is resolved once at import. Both branches go through realpath, so an
app started through a Start Menu or Startup-folder shortcut - a symlink or a
.lnk resolved by the shell - still lands on the real install directory rather
than on wherever the link happened to live.
"""

import os, sys


def app_dir():
    """The directory the app keeps its files in - config, log, caches."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.realpath(sys.executable))
    return os.path.dirname(os.path.realpath(os.path.abspath(__file__)))


def state_dir():
    """A directory the RUNNING USER can write: log, config, scratch files.

    APP_DIR is the install prefix. On Windows that is writable and keeping the
    log beside the exe is deliberate (see the module docstring). On Linux the
    app is installed to /opt/quickopen/infra-monitor, owned by root, so writing
    there raises PermissionError for every non-root user — the app crashed on
    import for exactly that reason (field report, Quick OS 0.1.15: the only hard
    launch failure in a 52-app sweep). User data belongs under XDG_STATE_HOME.
    """
    if os.name == "nt":
        return APP_DIR
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state")
    path = os.path.join(base, "quickopen", "infra-monitor")
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        return os.path.join(os.environ.get("TMPDIR", "/tmp"))
    return path


def frozen():
    return bool(getattr(sys, "frozen", False))


def asset(name):
    """A read-only file that ships INSIDE the bundle, not beside the exe.

    The opposite of APP_DIR: the app ICON is part of the build and must come
    out of PyInstaller's unpack directory, while machines.json is user data and
    must not. Reading an asset from APP_DIR works from source and then quietly
    fails in the frozen build, which is exactly the trap this module exists to
    document.
    """
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(
        os.path.realpath(os.path.abspath(__file__)))
    return os.path.join(base, name)


def relaunch_argv(*args):
    """The command line that re-runs THIS app with `args`.

    Frozen, that is the exe itself; from source it is the interpreter plus
    gmtray.py. The elevated rescan needs it, and getting it wrong there means a
    UAC prompt that launches nothing."""
    if frozen():
        return [sys.executable, *args]
    return [sys.executable, os.path.join(APP_DIR, "gmtray.py"), *args]


APP_DIR = app_dir()
STATE_DIR = state_dir()
