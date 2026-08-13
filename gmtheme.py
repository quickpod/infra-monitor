#!/usr/bin/env python3
r"""Aura theming for Infra Monitor.

Infra Monitor is a tray app whose dashboard is raw tk + ttk (canvas dials,
Treeviews, copyable Entries), so it cannot use the ``aura.AuraApp`` scaffold
the single-window QuickOpen apps use. It takes the other documented route:
``aura.apply(root, accent, theme)`` restyles every ttk class and the tk option
database, and this module hands the same palette to the tk widgets that draw
themselves.

Everything a widget paints comes from ``TH`` — a live view of the resolved Aura
palette. ``TH`` is re-resolved by :func:`apply`, and because tk fixes a colour
at widget-construction time the app REBUILDS its windows after a flip rather
than trying to repaint 150 widgets in place (see ``App._retheme``).

Theme preference is stored in machines.json as ``theme``:

    "system"  follow the OS appearance, live (the default, and what the
              QuickOpen OS shell expects of every Aura app)
    "dark"    /  "light"    an explicit user override

The status palette (good/warn/serious/critical) is DERIVED from the Aura
tokens rather than being a second hardcoded set, so severity colours move with
the design system and stay legible on whichever surface is underneath them.
"""

import os
import sys
import threading
import tkinter as tk

import aura

# Infra Monitor's per-app Aura accent (branding/gen_icons.py is the source of
# truth for the whole fleet's accents; this is the same violet as its icon).
ACCENT = "#7c3aed"

# machines.json key + the order the header control cycles through.
PREF_KEY = "theme"
CYCLE = ("system", "dark", "light")
PREF_LABEL = {"system": "Theme: System", "dark": "Theme: Dark",
              "light": "Theme: Light"}

_pref = "system"


class _Theme:
    """Attribute view over the resolved palette (``TH.surface``, ``TH.text``).

    A live object rather than module constants: constants would be bound at
    import time and every widget would keep the theme the app started in.
    """

    _d = {}

    def __getattr__(self, key):
        try:
            return _Theme._d[key]
        except KeyError:
            raise AttributeError(key)

    def get(self, key, default=None):
        return _Theme._d.get(key, default)


TH = _Theme()


def family():
    """The Aura UI family for the platform (mirrors the kit's own choice)."""
    if os.name == "nt":
        return "Segoe UI"
    if sys.platform == "darwin":
        return "Helvetica Neue"
    return "DejaVu Sans"


def mono_family():
    """Monospace for the detail panes / problem log."""
    if os.name == "nt":
        return "Consolas"
    if sys.platform == "darwin":
        return "Menlo"
    return "DejaVu Sans Mono"


UI = family()
MONO = mono_family()


def _derive(p, mode):
    """Palette + the app-specific roles built on top of the Aura tokens."""
    t = dict(p)
    t["mode"] = mode
    # Status. ok/warn/danger are Aura tokens; "serious" (the step between a
    # warning and a fault) is blended from the two either side of it so it
    # cannot drift away from them when the tokens change.
    t["good"] = p["ok"]
    t["warn"] = p["warn"]
    t["serious"] = aura.mix(p["warn"], p["danger"], 0.5)
    t["crit"] = p["danger"]
    t["grey"] = p["faint"]
    # ONE series colour for the ranked bar charts. The app accent, never a
    # status hue: none of those numbers is a fault, and a red or amber bar
    # would make a busy browser look like an incident.
    t["series"] = p["accent"]
    t["series_residual"] = aura.mix(p["accent"], p["surface"], 0.55)
    # Unfilled arc of a dial, and the tooltip surface.
    t["track"] = p["surface3"]
    t["tip_bg"] = p["surface2"]
    return t


def apply(root=None, pref=None):
    """Resolve + activate the theme. Returns ``TH``.

    Must run before the widgets that read ``TH`` are built. With *root* given
    it also restyles ttk (Notebook, Treeview, Scrollbar, Combobox, Entry) and,
    on Windows, the title bar.
    """
    global _pref
    if pref:
        _pref = pref
    p = aura.apply(root, accent=ACCENT, theme=_pref)
    mode = "dark" if p["bg"] == aura.TOKENS["dark"]["bg"] else "light"
    _Theme._d = _derive(p, mode)
    return TH


def pref():
    return _pref


def next_pref():
    """The next preference in the header control's cycle."""
    return CYCLE[(CYCLE.index(_pref) + 1) % len(CYCLE)]


def label():
    return PREF_LABEL.get(_pref, "Theme")


def load_pref(cfg):
    v = (cfg or {}).get(PREF_KEY)
    return v if v in CYCLE else "system"


def watch_system(callback):
    """Call ``callback('dark'|'light')`` when the OS appearance flips.

    Best-effort: a desktop with no live signal simply follows on next launch.
    The callback fires on darkdetect's thread — marshal to Tk before touching
    a widget.
    """
    try:
        import darkdetect
    except Exception:
        return None
    if not hasattr(darkdetect, "listener"):
        return None

    def _cb(value):
        try:
            callback("dark" if str(value).lower().startswith("d") else "light")
        except Exception:
            pass

    try:
        th = threading.Thread(target=darkdetect.listener, args=(_cb,),
                              daemon=True, name="theme")
        th.start()
        return th
    except Exception:
        return None


# ---------------------------------------------------------------- components

def beam(parent, height=2):
    """The Aura signature: a 2px accent beam fading out to the right.

    Sits under the window header exactly as it does in the scaffolded apps, so
    the tray dashboard reads as the same family at a glance.
    """
    cv = tk.Canvas(parent, height=height, highlightthickness=0, bd=0, bg=TH.bg)
    state = {"w": 0}

    def draw(_e=None):
        w = cv.winfo_width()
        if w <= 1 or w == state["w"]:
            return
        state["w"] = w
        cv.delete("all")
        fade = max(1, int(w * 0.85))
        for x in range(0, w, 3):
            cv.create_rectangle(
                x, 0, x + 3, height, width=0,
                fill=aura.mix(TH.accent, TH.bg, min(1.0, x / fade)))

    cv.bind("<Configure>", draw)
    return cv


def tile(parent, label, value, note, accent, word=None):
    """One KPI tile: hairline surface card with a 4px accent edge.

    Four panels built these by hand from the same eleven lines; they are one
    component, and one component means they cannot drift apart between tabs.

    *word* is the severity spelled out beside the number - the non-colour
    channel, so a tile never carries its meaning in hue alone.
    """
    t = tk.Frame(parent, bg=TH.surface, highlightthickness=1,
                 highlightbackground=TH.border)
    tk.Frame(t, bg=accent, width=4).pack(side="left", fill="y")
    inner = tk.Frame(t, bg=TH.surface)
    inner.pack(side="left", padx=10, pady=5)
    tk.Label(inner, text=label, bg=TH.surface, fg=TH.muted,
             font=(UI, 7)).pack(anchor="w")
    line = tk.Frame(inner, bg=TH.surface)
    line.pack(anchor="w")
    tk.Label(line, text=str(value), bg=TH.surface, fg=TH.text,
             font=(UI, 14, "bold")).pack(side="left")
    if word:
        tk.Label(line, text="  " + word, bg=TH.surface, fg=TH.text,
                 font=(UI, 8, "bold")).pack(side="left", pady=(6, 0))
    tk.Label(inner, text=note, bg=TH.surface, fg=TH.muted,
             font=(UI, 7)).pack(anchor="w")
    return t
