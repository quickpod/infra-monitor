#!/usr/bin/env python3
r"""
build_exe - freeze Infra Monitor into one InfraMonitor.exe.

    python build_exe.py

WHY --onefile --windowed
Onefile so there is a single thing to copy next to machines.json, and windowed
because a tray monitor that also opens a console window every launch is a tray
monitor you close. Windowed is also why gmtray logs to inframonitor.log rather
than stderr: with no console there is nowhere else for a crashed thread to say so.

WHY THE HIDDEN IMPORTS
PyInstaller finds imports by reading the source, so anything imported
dynamically is invisible to it. The sibling modules ARE imported normally at
the top of gmtray, but `pystray` picks its backend at RUNTIME from what the
platform offers (`pystray._win32` here) and `paramiko` pulls its ciphers in
through `cryptography`'s backend loader. A build without these flags succeeds,
starts, and then fails the first time you click something - which is the worst
possible time to find out.

WHY THE EXE IS NOT SELF-CONTAINED ON PURPOSE
machines.json is NOT bundled. It is user data: the fleet list, the SSH peer
allowlist, and the images you have trusted on the This PC tab. Bundling it
would mean a rebuild silently reverted every setting, and that a saved change
went into a temp directory that is deleted on exit. The exe reads it from its
own directory - see gmpaths.

The previous exe is kept as InfraMonitor.exe.bak-<date> before it is replaced, so a
build that turns out worse than what it replaced can be undone by renaming one
file, with no rebuild and no network.
"""

import os, shutil, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "InfraMonitor"
ENTRY = os.path.join(HERE, "gmtray.py")
DIST = os.path.join(HERE, "dist")

# gmexport is the one that MUST be here: it is imported inside functions (so
# that a plain tray launch never pays for it), which makes it invisible to
# PyInstaller's source analysis. Without this flag the build succeeds and
# Settings > Export fails at the click. The rest are imported normally and
# listed defensively - a missing module here is a runtime failure, not a build
# error, and pystray picks its backend at RUNTIME from what the platform
# offers, so nothing in the source names `pystray._win32` at all.
HIDDEN = ["gmconfig", "gmcheck", "gmnotify", "gmlocal", "gmpaths",
          "gmautostart", "gmexport", "gmstealth", "sshconn",
          "gmtheme", "aura", "customtkinter", "darkdetect",
          "pystray._win32", "PIL.Image", "PIL.ImageDraw",
          "paramiko", "cryptography"]

# Nothing here needs a GUI toolkit beyond tkinter, and these pull in tens of MB.
EXCLUDE = ["matplotlib", "numpy", "scipy", "pandas", "PyQt5", "PyQt6", "PySide2",
           "PySide6", "IPython", "pytest", "setuptools", "wheel"]


def main():
    if os.name != "nt":
        print("This build targets Windows.")
        return 2
    try:
        import PyInstaller                      # noqa: F401
    except ImportError:
        print("PyInstaller is not installed for this interpreter.\n"
              f"  {sys.executable} -m pip install pyinstaller")
        return 2

    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
           "--onefile", "--windowed", "--name", NAME,
           "--distpath", DIST, "--workpath", os.path.join(HERE, "build"),
           "--specpath", os.path.join(HERE, "build")]
    for h in HIDDEN:
        cmd += ["--hidden-import", h]
    for e in EXCLUDE:
        cmd += ["--exclude-module", e]
    # CustomTkinter ships .json colour-theme assets that PyInstaller's source
    # analysis never sees. Aura loads one at startup, so without this the
    # frozen exe dies before it draws anything.
    cmd += ["--collect-all", "customtkinter"]
    icon = os.path.join(HERE, "infra-monitor.ico")
    if os.path.isfile(icon):
        cmd += ["--icon", icon]
    # The PNG is a BUNDLED asset (the dashboard header brand mark), unlike
    # machines.json which stays beside the exe as user data - see gmpaths.
    png = os.path.join(HERE, "infra-monitor.png")
    if os.path.isfile(png):
        cmd += ["--add-data", png + os.pathsep + "."]
    cmd.append(ENTRY)

    print("building:", " ".join(cmd[:8]), "...")
    t0 = time.time()
    r = subprocess.run(cmd, cwd=HERE)
    if r.returncode != 0:
        print(f"\nBUILD FAILED (exit {r.returncode}) - nothing was replaced.")
        return r.returncode

    built = os.path.join(DIST, NAME + ".exe")
    if not os.path.isfile(built):
        print(f"\nBUILD REPORTED SUCCESS but {built} is missing.")
        return 1

    target = os.path.join(HERE, NAME + ".exe")
    if os.path.isfile(target):
        # Keep the outgoing exe. Undoing a bad build is then a rename, needing
        # no rebuild, no toolchain and no network.
        bak = os.path.join(HERE, f"{NAME}.exe.bak-{time.strftime('%Y%m%d')}")
        try:
            shutil.copy2(target, bak)
            print("previous exe kept as", os.path.basename(bak))
        except OSError as ex:
            print("could NOT back up the current exe:", ex)
            print("refusing to overwrite it - move it aside by hand first.")
            return 1
    try:
        shutil.copy2(built, target)
    except OSError as ex:
        # Overwhelmingly this is "the tray app is running and holding the file".
        print(f"could not replace {target}: {ex}")
        print("If Infra Monitor is running, quit it from the tray and re-run.")
        return 1

    # DELETE the dist copy. Leaving one there means two identical exes on the
    # machine, only one of which has machines.json beside it - and the obvious
    # one to double-click is the one PyInstaller just announced. Run that copy
    # and the app finds no config, reports an empty fleet as "all healthy", and
    # registers ITSELF for logon - from a directory the next --clean build
    # deletes. That happened. One exe, in one place.
    try:
        os.remove(built)
        shutil.rmtree(DIST, ignore_errors=True)
    except OSError:
        print(f"NOTE: could not remove {built} - delete it by hand so there is "
              f"only one InfraMonitor.exe on this machine.")

    size = os.path.getsize(target) / (1024 * 1024)
    print(f"\nOK  {target}  ({size:.1f} MB, {time.time() - t0:.0f}s)")
    print("machines.json is NOT bundled - it stays beside the exe as user data.")
    print("Run THIS exe, not a copy: it reads its config from its own folder,")
    print("and it registers that path to start at logon.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
