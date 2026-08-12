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


def frozen():
    return bool(getattr(sys, "frozen", False))


def relaunch_argv(*args):
    """The command line that re-runs THIS app with `args`.

    Frozen, that is the exe itself; from source it is the interpreter plus
    gmtray.py. The elevated rescan needs it, and getting it wrong there means a
    UAC prompt that launches nothing."""
    if frozen():
        return [sys.executable, *args]
    return [sys.executable, os.path.join(APP_DIR, "gmtray.py"), *args]


APP_DIR = app_dir()
