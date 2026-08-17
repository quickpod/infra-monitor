#!/usr/bin/env python3
r"""
gmtray - background tray monitor for a fleet of SSH machines.

Sits in the notification area, polls the fleet on a timer, toasts on state
CHANGES, and opens a dashboard of dials when you click it.

THREADING
Tk owns the main thread (it insists), pystray runs its own message loop in a
daemon thread, and polling runs in a third. Only the poller touches the
network; it hands results back through root.after() so every widget update
happens on the Tk thread. Updating Tk from a worker thread appears to work and
then crashes days later, which is exactly the failure a background monitor must
not have.

The tray icon colour is the worst state in the fleet, so a glance at the corner
of the screen answers "is anything wrong?" without opening anything:
  grey  - not checked (off-network, gate closed)
  green - everything healthy
  amber - at least one warning
  red   - at least one machine down, or a foreign SSH session
"""

import json, logging, os, queue, sys, threading, time, traceback
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gmconfig, gmcheck, gmnotify, gmlocal, gmpaths, gmautostart, gmstealth
try:
    import gmtheme
    from gmtheme import TH, UI, MONO
except ImportError as _ex:          # pragma: no cover - dependency guard
    # gmtheme pulls in the Aura design system (customtkinter + darkdetect). The
    # frozen exe bundles them; a source checkout may not have them yet, and a
    # bare "ModuleNotFoundError: customtkinter" from a --windowed build goes to
    # a stderr nobody can see. Say it where it will be read instead.
    import tkinter.messagebox as _mb
    _msg = ("Infra Monitor needs its display dependencies:\n\n"
            "    pip install -r requirements.txt\n\n%s" % _ex)
    try:
        _r = tk.Tk(); _r.withdraw(); _mb.showerror("Infra Monitor", _msg)
    except Exception:
        print(_msg, file=sys.stderr)
    sys.exit(2)

# Single-instance marker: the installer's AppMutex checks this to warn the
# user to close the app before install/uninstall. Harmless off Windows.
if os.name == "nt":
    try:
        import ctypes
        ctypes.windll.kernel32.CreateMutexW(None, False, "QuickOpen.InfraMonitor")
    except Exception:
        pass


# pythonw.exe has no console: anything written to stderr is discarded, so a
# crashed poller thread leaves the dashboard frozen on its last snapshot with
# no clue why. That happened. Everything goes to a file instead. A windowed
# PyInstaller build has exactly the same problem, which is why the log lives
# beside the exe rather than inside the temporary unpack directory.
LOG_PATH = os.path.join(gmpaths.STATE_DIR, "inframonitor.log")
logging.basicConfig(
    filename=LOG_PATH, level=logging.INFO, filemode="a",
    format="%(asctime)s %(levelname)-7s %(threadName)-12s %(message)s")
log = logging.getLogger("inframonitor")

import pystray
from PIL import Image, ImageDraw

# TRAY ICON palette. Deliberately NOT themed: the icon is painted into the OS
# notification area over whatever the shell puts behind it, so it keeps one
# vivid fixed set rather than following the app's own light/dark. Everything
# INSIDE the window takes its status colours from the Aura tokens (gmtheme.TH),
# which move with the surface they are drawn on.
GREY, GREEN, AMBER, RED = "#9aa0a6", "#0ca30c", "#fab219", "#d03b3b"


def sev_colours():
    """Severity -> colour for the Treeview row tags, in the current theme."""
    return {"CRIT": TH.crit, "HIGH": TH.serious, "WARN": TH.warn,
            "INFO": TH.muted, "OK": TH.good}


def state_colours():
    """Stealth port state -> colour, in the current theme."""
    return {"open": TH.crit, "closed": TH.warn, "stealth": TH.good,
            "unreachable": TH.muted, "blocked": TH.muted, "error": TH.muted}

# `warn` and `serious` sit below 3:1 on the light surface BY DESIGN. The
# mitigation is that every status is paired with a word, so severity is never
# carried by hue alone - which also makes the dashboard readable for the ~8% of
# men with a colour vision deficiency, and in a screenshot printed in mono.
def severity(pct):
    if pct >= 95:
        return TH.crit, "CRIT"
    if pct >= 85:
        return TH.serious, "HIGH"
    if pct >= 70:
        return TH.warn, "WARN"
    return TH.good, "OK"


def worst_colour(snap):
    if not snap:
        return GREY
    seen = [r for r in snap["machines"] if r.get("checked")]
    if not seen:
        return GREY
    if any(not r["up"] or any("FOREIGN SESSION" in p for p in r["problems"])
           for r in seen):
        return RED
    if any(r["problems"] for r in seen):
        return AMBER
    return GREEN


def make_icon_image(colour, badge=0):
    """The tray icon: the app's own mark, with STATE shown as a corner badge.

    It used to be a flat coloured circle — a green dot that told you the state
    and nothing else, so the tray gave no clue which app it belonged to (owner,
    2026-08-17: "put a good status icon not just a green dot"). Now the icon is
    recognisably Infra Monitor at a glance and the colour rides in a badge, which
    is how every other tray citizen does it.

    Falls back to a drawn rack glyph if the packaged artwork is missing, so a
    stripped build still gets something better than a dot.
    """
    size = 64
    img = None
    try:
        art = Image.open(gmpaths.asset("infra-monitor.png")).convert("RGBA")
        img = art.resize((size, size), Image.LANCZOS)
    except Exception:
        img = None

    if img is None:
        # a small server rack: three stacked units with drive lights
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.rounded_rectangle((10, 8, 54, 56), radius=7, fill="#2b313b",
                            outline="#9aa4b2", width=2)
        for i, top in enumerate((14, 28, 42)):
            d.rounded_rectangle((16, top, 48, top + 10), radius=3,
                                fill="#1a1e26", outline="#3a424f")
            d.ellipse((19, top + 3, 24, top + 8), fill=colour)

    # state badge, bottom-right, with a ring so it reads on any wallpaper
    d = ImageDraw.Draw(img)
    r = 22
    box = (size - r - 2, size - r - 2, size - 2, size - 2)
    d.ellipse(box, fill="#0b0d12")
    d.ellipse((box[0] + 2, box[1] + 2, box[2] - 2, box[3] - 2), fill=colour)
    if badge:
        # a count belongs ON the badge, not floating over the artwork
        text = str(min(badge, 99))
        try:
            tw = d.textlength(text)
        except AttributeError:
            tw = 6 * len(text)
        cx = (box[0] + box[2]) / 2 - tw / 2
        cy = (box[1] + box[3]) / 2 - 6
        d.text((cx, cy), text, fill="#0b0d12")
    return img


# ----------------------------------------------------------------------- dials
def draw_dial(cv, x, y, r, pct, label, sub=""):
    """A 270-degree arc gauge with the severity spelled out beneath it.

    The number and the word carry the meaning; the colour only speeds up
    finding it. Text stays in ink tokens rather than taking the status hue -
    a coloured mark beside a label reads better than coloured text, and keeps
    the value legible when the status is a low-contrast warning yellow."""
    pct = max(0, min(100, pct if isinstance(pct, (int, float)) else 0))
    col, word = severity(pct)
    cv.create_arc(x - r, y - r, x + r, y + r, start=225, extent=-270,
                  style="arc", width=5, outline=TH.track)
    if pct > 0:
        cv.create_arc(x - r, y - r, x + r, y + r, start=225,
                      extent=-270 * pct / 100.0, style="arc", width=5,
                      outline=col)
    cv.create_text(x, y - 3, text=f"{int(pct)}", fill=TH.text,
                   font=(UI, 10, "bold"))
    cv.create_text(x, y + 9, text=label, fill=TH.muted, font=(UI, 6))
    # Severity word stays even at this size: it is the non-colour channel, so
    # dropping it to save pixels would leave hue carrying the meaning alone.
    cv.create_text(x, y + r + 6, text=word, fill=TH.text,
                   font=(UI, 6, "bold"))
    if sub:
        cv.create_text(x, y + r + 15, text=sub, fill=TH.muted,
                       font=(UI, 6))


# ------------------------------------------------------------- ranked bars
# ONE hue, not a categorical palette. Every bar in these charts measures the
# same thing - how many connections - so colour carries no identity here and
# giving each bar its own would imply a difference that does not exist. The hue
# is the app's Aura ACCENT (TH.series), deliberately not a status colour: the
# status palette means good/warning/serious/critical and must never be borrowed
# to mean "series". The accent is dE-distant from all four in both themes, so a
# bar can never be misread as a fault.
# The folded-up tail (TH.series_residual) is the same accent blended toward the
# surface, so it reads as a leftover rather than a ninth competitor - it is
# routinely longer than the top-ranked bar, and in full series colour that
# makes a descending chart look broken. Its value is directly labelled.
BAR_H, BAR_PITCH, BAR_R = 12, 18, 4      # <=24px thick, 6px air, 4px data-end


def _rbar(cv, x0, y0, x1, y1, r, fill):
    """A bar with a rounded data-end and a square baseline.

    Built from a rectangle plus two pie slices because Tk has no rounded
    rectangle. Every piece is outline="" - a stroke around a mark is ink that
    is not data, and at this size it reads as a border rather than a bar."""
    if x1 - x0 <= r:
        cv.create_rectangle(x0, y0, max(x1, x0 + 1), y1, fill=fill, outline="")
        return
    cv.create_rectangle(x0, y0, x1 - r, y1, fill=fill, outline="")
    cv.create_rectangle(x1 - r, y0 + r, x1, y1 - r, fill=fill, outline="")
    cv.create_arc(x1 - 2 * r, y0, x1, y0 + 2 * r, start=0, extent=90,
                  style="pieslice", fill=fill, outline="")
    cv.create_arc(x1 - 2 * r, y1 - 2 * r, x1, y1, start=270, extent=90,
                  style="pieslice", fill=fill, outline="")


def draw_ranked_bars(cv, title, items, x=0, y=0, width=420, gutter=150):
    """A ranked horizontal bar chart of one measure.

    No legend and no gridlines: there is a single series, so the title already
    says what is plotted, and every bar is directly labelled with its value -
    direct labels come before gridlines. Labels stay in ink tokens; the colour
    lives in the mark, never in the text."""
    cv.create_text(x, y, text=title, anchor="nw", fill=TH.text,
                   font=(UI, 8, "bold"))
    top = y + 18
    if not items:
        cv.create_text(x, top + 4, text="nothing to show", anchor="nw",
                       fill=TH.muted, font=(UI, 8))
        return
    valw = 34
    x0 = x + gutter
    span = max(24, width - gutter - valw)
    hi = max(v for _l, v, _o in items) or 1
    for i, (label, val, residual) in enumerate(items):
        cy = top + i * BAR_PITCH
        # Truncated to the gutter so a long path can never run under the bars.
        txt = label if len(label) <= 24 else label[:23] + "…"
        cv.create_text(x, cy + BAR_H / 2, text=txt, anchor="w", fill=TH.muted,
                       font=(UI, 8))
        w = max(2, int(span * val / hi))
        _rbar(cv, x0, cy, x0 + w, cy + BAR_H, BAR_R,
              TH.series_residual if residual else TH.series)
        # Value at the tip, always OUTSIDE the bar, so it can never be clipped
        # by its own mark however short the bar is.
        cv.create_text(x0 + w + 6, cy + BAR_H / 2, text=str(val), anchor="w",
                       fill=TH.text, font=(UI, 8))


def local_detail_lines(r):
    """The full record behind one socket row.

    Shared by both local tabs so the same socket reads identically whichever
    one you found it in - and it is the thing that gets pasted into a ticket,
    which is why it lives in a selectable Text rather than the table."""
    since = (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["since"]))
             if r["since"] else "unknown")
    src = " (from the service registration)" if r.get("pathsrc") == "service" else ""
    return [
        f"verdict    {r['verdict'].upper()} [{r['sev']}] - {r['why']}",
        f"socket     {r['proto']} {r['local']}"
        + (f"  <->  {r['remote']}" if r["remote"] else "")
        + f"   {r['state']}   ({r['dir']})",
        f"peer       {r['peer']}" + (f"   {r['rdns']}" if r["rdns"] else ""),
        f"since      {since}",
        f"process    {r['proc']}   pid {r['pid']}",
        f"image      {r['path'] or '(not readable)'}{src}",
        f"service    {r['svc'] or '(not a registered service)'}",
        f"signature  {r['sigstatus']}" + (f" - {r['signer']}" if r["signer"] else ""),
        f"command    {r['cmd'] or '(not readable)'}",
    ]


STEALTH_HELP = """\
A stealth check asks what a stranger's packets get back from an address, so it
is run from somewhere else - one of the fleet relays, over the SSH connection
this app already uses. Probing from this PC would never leave the machine and
would report every listener open while the internet saw nothing.

  OPEN     the handshake completed. Something is listening AND reachable.
  CLOSED   the host sent RST. Nothing is listening there - but the host
           answered, which confirms to any scanner that this address is live.
  STEALTH  nothing came back. The packet was dropped; from outside, the
           address is indistinguishable from unused space. This is the goal.

Swept: every privileged port 1-1023, a curated set of common service ports,
and every TCP port this PC is currently listening on - including the Windows
service listeners above 49152 that a well-known-ports list misses entirely."""


def stealth_detail_lines(r, snap=None):
    """The full record behind one probed port.

    The vantage is repeated on every row on purpose: the state means nothing
    without it. "3389 stealth" read off a scan launched from this same machine
    is not a finding, it is a mistake, and the row itself has to carry enough
    to stop that reading."""
    snap = snap or {}
    where = f"{snap.get('vantage', '?')} ({snap.get('vantage_kind', '?')})"
    if r["bind"]:
        here = (f"this PC listens on this port, bound to {r['bind']}"
                + (f", owned by service '{r['svc']}'" if r["svc"] else ""))
    elif r["local"]:
        here = "this PC listens on this port"
    else:
        here = "this PC is not listening on this port"
    return [
        f"port       TCP {r['port']}"
        + (f"   {r['name']}" if r["name"] else ""),
        f"state      {r['state'].upper()} [{r['sev']}] - {r['why']}",
        f"means      {r['note'] or 'no response of any kind came back'}",
        f"probed by  {where}"
        + (f"   {r['ms']}ms to answer" if r["ms"] else ""),
        f"on this PC {here}",
        f"why probed {r['source']}",
        f"target     {snap.get('ip', '?')}   verdict {snap.get('verdict', '?')}"
        + (f"   host proved up by ARP {snap['arp']}" if snap.get("arp")
           else "   host up: ICMP reply" if snap.get("ping") == "reply"
           else "   host liveness NOT proved"),
    ] + ([f"caveat     {snap['caveat']}"] if snap.get("caveat") else [])


class Tooltip:
    """Hover text for anything truncated on screen.

    Problem strings routinely run past what a row can show, and the truncated
    tail is usually the useful part - "nvidia-smi FAILING: NVIDIA-SMI has
    failed because it couldn'" tells you nothing the full message doesn't say
    better. Rather than widen every row for the worst case, the row stays
    compact and the whole text appears on hover."""

    def __init__(self, widget, text):
        self.widget, self.text, self.tip = widget, text, None
        widget.bind("<Enter>", self.show, add="+")
        widget.bind("<Leave>", self.hide, add="+")

    def show(self, _e=None):
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)      # no title bar
        self.tip.wm_geometry(f"+{x}+{y}")
        # A Text, not a Label: the tooltip content is the thing you most want
        # to paste into a ticket, so it has to be selectable too.
        t = tk.Text(self.tip, wrap="word", width=88, height=min(
            10, max(1, len(self.text) // 80 + self.text.count("\n") + 1)),
            bg=TH.tip_bg, fg=TH.text, insertbackground=TH.text,
            selectbackground=TH.accent_soft, selectforeground=TH.text,
            highlightthickness=1, highlightbackground=TH.border,
            relief="flat", borderwidth=0,
            font=(UI, 8), padx=6, pady=4)
        t.insert("1.0", self.text)
        t.configure(state="normal")             # keep it selectable/copyable
        t.pack()

    def hide(self, _e=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


def copyable(parent, text, width=None, **kw):
    """A read-only Entry that looks like a Label but can be selected and
    copied. Plain Labels cannot - and a monitoring panel whose hostnames,
    IPs and error strings have to be retyped by hand to be searched or pasted
    into a ticket is quietly hostile."""
    v = tk.StringVar(value=text)
    e = tk.Entry(parent, textvariable=v, state="readonly", relief="flat",
                 readonlybackground=kw.pop("bg", TH.surface),
                 fg=kw.pop("fg", TH.text), bd=0, highlightthickness=0,
                 selectbackground=TH.accent_soft, selectforeground=TH.text,
                 font=kw.pop("font", (UI, 8)),
                 width=width or max(8, min(len(text) + 1, 120)))
    return e


class Dashboard(tk.Toplevel):
    def __init__(self, master, app):
        super().__init__(master)
        # A transient window belongs to its parent: Plasma keeps it with the
        # app instead of giving it a taskbar entry of its own.
        try:
            self.transient(master.winfo_toplevel())
        except Exception:
            pass
        self.app = app
        self.title("Infra Monitor")
        self.geometry("1400x740")
        self.configure(bg=TH.bg)
        self.protocol("WM_DELETE_WINDOW", self.hide)

        # ---- Aura header: brand, live status, actions, then the accent beam.
        # The same header/beam the scaffolded QuickOpen apps carry, rebuilt on
        # a Toplevel because this window is a Notebook of dense tables rather
        # than the sidebar scaffold AuraApp provides.
        head = tk.Frame(self, bg=TH.bg)
        head.pack(fill="x", padx=12, pady=(12, 9))
        self._brand_icon = None
        try:
            img = tk.PhotoImage(file=gmpaths.asset("infra-monitor.png"))
            k = max(1, round(img.width() / 22))
            self._brand_icon = img.subsample(k, k)   # kept: tk drops unref'd
            tk.Label(head, image=self._brand_icon, bd=0, bg=TH.bg)\
                .pack(side="left", padx=(0, 9))
        except Exception:
            pass
        tk.Label(head, text="Infra Monitor", bg=TH.bg, fg=TH.text,
                 font=(UI, 13, "bold")).pack(side="left")
        self.status = tk.Label(head, text="", bg=TH.bg, fg=TH.muted,
                               anchor="w", font=(UI, 9))
        self.status.pack(side="left", padx=(16, 0))
        self._theme_btn = ttk.Button(head, text=gmtheme.label(),
                                     command=self.app.cycle_theme)
        self._theme_btn.pack(side="right")
        ttk.Button(head, text="Refresh now", command=self.app.poll_now,
                   style="Accent.TButton").pack(side="right", padx=(0, 8))
        gmtheme.beam(self).pack(fill="x")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=6, pady=(2, 6))
        # Two groups, two tabs. They are not comparable at a glance anyway -
        # local machines can be legitimately unchecked when off-network,
        # public ones never can - so stacking them in one scroll only made
        # the list long enough that the second half went unread.
        self.panes = {}
        for key, label in (("local", "Local Fleet"), ("dc", "Public Fleet")):
            self.panes[key] = self._make_tab(label)
        self._make_problems_tab()
        self._make_thispc_tab()
        self._make_conns_tab()
        self._make_stealth_tab()

    def _make_problems_tab(self):
        """Newest-first problem log. The per-machine cards answer 'what is
        wrong now'; this answers 'what changed, and when' - which is the
        question you actually have when a toast fired while you were away."""
        outer = tk.Frame(self.nb, bg=TH.bg)
        self.nb.add(outer, text="Problems")
        self.problems = tk.Text(outer, wrap="none", bg=TH.field, fg=TH.text,
                                font=(MONO, 8), relief="flat",
                                insertbackground=TH.text,
                                selectbackground=TH.accent_soft,
                                selectforeground=TH.text,
                                highlightthickness=1,
                                highlightbackground=TH.border,
                                padx=6, pady=4)
        ys = ttk.Scrollbar(outer, orient="vertical", command=self.problems.yview)
        xs = ttk.Scrollbar(outer, orient="horizontal", command=self.problems.xview)
        self.problems.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y"); xs.pack(side="bottom", fill="x")
        self.problems.pack(side="left", fill="both", expand=True)
        for tag, col in (("crit", TH.crit), ("warn", TH.warn),
                         ("ok", TH.good), ("dim", TH.muted)):
            self.problems.tag_configure(tag, foreground=col)

    # ------------------------------------------------------------- this PC
    LCOLS = (("sev", "SEV", 60), ("dir", "DIR", 76), ("proto", "P", 48),
             ("local", "LOCAL", 170), ("remote", "REMOTE", 180),
             ("peer", "PEER", 130), ("proc", "PROCESS", 170),
             ("pid", "PID", 64), ("acct", "SERVICE / PUBLISHER", 220),
             ("why", "WHY IT IS LISTED", 420))

    def _make_thispc_tab(self):
        """Connections to the machine the monitor itself runs on.

        A Treeview rather than the stacked cards the fleet tabs use: this is a
        table of a hundred near-identical rows that wants sorting and
        selection, not thirteen objects each with its own dials. The detail
        pane underneath carries the copyable text, which is what a Treeview
        cannot give you and what ends up pasted into a ticket."""
        outer = tk.Frame(self.nb, bg=TH.bg)
        self.nb.add(outer, text="This PC")
        self.local_tab = outer
        self.lrows, self.lsnap = {}, None

        self.lbanner = tk.Label(outer, bg=TH.bg, fg=TH.muted, anchor="w",
                                font=(UI, 8), justify="left")
        self.lbanner.pack(fill="x", padx=10, pady=(6, 0))
        self.ltiles = tk.Frame(outer, bg=TH.bg)
        self.ltiles.pack(fill="x", padx=8, pady=(4, 2))

        ctl = tk.Frame(outer, bg=TH.bg); ctl.pack(fill="x", padx=10, pady=(0, 4))
        self.lfilter = {}
        for key, label in (("IN", "inbound"), ("LISTEN", "listening"),
                           ("OUT", "outbound")):
            v = tk.BooleanVar(value=True)
            self.lfilter[key] = v
            ttk.Checkbutton(ctl, text=label, variable=v,
                            command=self._rerender_local).pack(side="left")
        self.lshowok = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctl, text="show accounted-for", variable=self.lshowok,
                        command=self._rerender_local)\
            .pack(side="left", padx=(12, 0))
        ttk.Button(ctl, text="Rescan", command=self.app.scan_local_now)\
            .pack(side="right")
        ttk.Button(ctl, text="Scan as administrator",
                  command=self.app.scan_local_elevated).pack(side="right", padx=6)
        ttk.Button(ctl, text="Trust this program",
                  command=self._trust_selected).pack(side="right")
        ttk.Button(ctl, text="Copy all", command=self._copy_local)\
            .pack(side="right", padx=6)

        wrap = tk.Frame(outer, bg=TH.bg)
        wrap.pack(fill="both", expand=True, padx=10)
        self.ltree = ttk.Treeview(wrap, columns=[c[0] for c in self.LCOLS],
                                  show="headings", selectmode="browse")
        for key, head, width in self.LCOLS:
            self.ltree.heading(key, text=head,
                               command=lambda k=key: self._sort_local(k))
            self.ltree.column(key, width=width, stretch=(key == "why"),
                              anchor="w")
        ys = ttk.Scrollbar(wrap, orient="vertical", command=self.ltree.yview)
        xs = ttk.Scrollbar(wrap, orient="horizontal", command=self.ltree.xview)
        self.ltree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y"); xs.pack(side="bottom", fill="x")
        self.ltree.pack(side="left", fill="both", expand=True)
        for tag, col in sev_colours().items():
            self.ltree.tag_configure(tag, foreground=col)
        self.ltree.bind("<<TreeviewSelect>>", self._show_local_detail)
        self.lsort = ("sev", False)

        self.ldetail = tk.Text(outer, height=8, wrap="word", bg=TH.field,
                               fg=TH.text, font=(MONO, 8), relief="flat",
                               insertbackground=TH.text,
                               selectbackground=TH.accent_soft,
                               selectforeground=TH.text,
                               highlightthickness=1,
                               highlightbackground=TH.border,
                               padx=8, pady=5)
        self.ldetail.pack(fill="x", padx=10, pady=(4, 8))
        self.ldetail.insert("1.0", "Select a row to see the full process, "
                                   "signature and socket detail here.")

    def _local_visible(self):
        rows = (self.lsnap or {}).get("rows", [])
        return [r for r in rows
                if (r["dir"] not in self.lfilter or self.lfilter[r["dir"]].get())
                and (self.lshowok.get()
                     or r["verdict"] not in gmlocal.ACCOUNTED)]

    def _local_values(self, r):
        """One row as the columns show it. Shared by the table and the
        clipboard, so what you paste is what you were looking at."""
        return (r["sev"], r["dir"], r["proto"], r["local"], r["remote"] or "-",
                (r["rdns"] or r["peer"] or "-")[:40], r["proc"], r["pid"],
                (r["svc"] or r["signer"] or "")[:60], r["why"])

    def _sort_local(self, key):
        rev = not self.lsort[1] if self.lsort[0] == key else False
        self.lsort = (key, rev)
        self._rerender_local()

    def _rerender_local(self):
        if self.lsnap:
            self.render_local(self.lsnap)

    def render_local(self, lsnap):
        self.lsnap = lsnap
        c = lsnap.get("counts", {})
        if not lsnap.get("ok"):
            # A failed scan must never look like a clean one. The tiles are
            # cleared and the banner says so, because "no unknown connections"
            # and "we could not look" are opposite answers that would
            # otherwise render identically.
            self.lbanner.config(
                fg=TH.crit,
                text="SCAN FAILED - this list is NOT an all-clear.\n"
                     + str(lsnap.get("error", ""))[:300])
        else:
            bits = [f"{lsnap.get('host', 'this PC')}",
                    f"{c.get('total', 0)} sockets",
                    f"scanned {time.strftime('%H:%M:%S', time.localtime(lsnap['checked_at']))}"
                    f" in {lsnap.get('elapsed', 0)}s"]
            if lsnap.get("admin"):
                bits.append("elevated - every process identified")
            else:
                bits.append(f"NOT elevated - {c.get('unverified', 0)} process(es) "
                            f"cannot be identified; use 'Scan as administrator'")
            if lsnap.get("deferred"):
                bits.append(f"{lsnap['deferred']} signature(s) still to check")
            self.lbanner.config(
                fg=(TH.muted if lsnap.get("admin") else TH.warn),
                text="   ".join(bits))

        for w in self.ltiles.winfo_children():
            w.destroy()
        # (label, value, note, colour when NON-zero). The last field matters:
        # zero unknowns is good news and zero accounted-for is not, so the tile
        # colour cannot be derived from the count alone.
        tiles = [
            ("EXPOSED", c.get("exposed", 0),
             "unidentified, reachable from off this PC", TH.crit),
            ("INBOUND", c.get("unknown_in", 0), "unidentified sessions IN", TH.crit),
            ("OUTBOUND", c.get("unknown_out", 0), "unidentified calls OUT", TH.warn),
            ("UNVERIFIED", c.get("unverified", 0), "process not identifiable", TH.warn),
            ("FOR REVIEW", c.get("review", 0), "signed, but not a service", TH.muted),
            ("ACCOUNTED", c.get("accounted", 0), "system services + trusted", TH.good),
        ]
        for label, val, note, hot in tiles:
            col = hot if (val or label in ("FOR REVIEW", "ACCOUNTED")) else TH.good
            gmtheme.tile(self.ltiles, label, val, note, col)\
                .pack(side="left", padx=(0, 8))

        keep = self.ltree.selection()
        keep = keep[0] if keep else None
        self.ltree.delete(*self.ltree.get_children())
        self.lrows.clear()
        key, rev = self.lsort
        rows = self._local_visible()
        if key == "sev":
            rows.sort(key=lambda r: (gmlocal.SEV_ORDER.get(r["sev"], 9),
                                     gmlocal.DIR_ORDER.get(r["dir"], 3),
                                     r["proc"].lower()), reverse=rev)
        else:
            rows.sort(key=lambda r: str(r.get(key, "")).lower(), reverse=rev)
        for r in rows:
            iid = f"{r['proto']}|{r['laddr']}|{r['lport']}|{r['raddr']}|{r['rport']}|{r['pid']}"
            if iid in self.lrows:
                continue                    # same socket listed twice
            self.lrows[iid] = r
            self.ltree.insert("", "end", iid=iid, tags=(r["sev"],),
                              values=self._local_values(r))
        # A rebuild every minute that dropped the selection would make the
        # detail pane unreadable on anything that persists.
        if keep and keep in self.lrows:
            self.ltree.selection_set(keep)
        # Two marks, because they are two different states. "3⚠" is something
        # unaccounted for that you can act on; "8?" is something we could not
        # identify at all. Collapsing them into one number would either hide
        # the actionable one or leave the tab permanently flagged.
        n, u = c.get("exposed", 0), c.get("unverified", 0)
        if not lsnap.get("ok"):
            label = "This PC  (scan failed)"
        elif n or u:
            label = "This PC  (" + "  ".join(
                ([f"{n}⚠"] if n else []) + ([f"{u}?"] if u else [])) + ")"
        else:
            label = "This PC  (ok)"
        self.nb.tab(self.local_tab, text=label)

    def _selected_local(self):
        sel = self.ltree.selection()
        return self.lrows.get(sel[0]) if sel else None

    def _show_local_detail(self, _e=None):
        r = self._selected_local()
        if not r:
            return
        self.ldetail.delete("1.0", "end")
        self.ldetail.insert("1.0", "\n".join(local_detail_lines(r)))

    def _trust_selected(self):
        r = self._selected_local()
        if not r:
            gmtheme.notice("Infra Monitor", "Select a row first.", parent=self)
            return
        if not r["path"]:
            gmtheme.warn(
                "Infra Monitor", "This process has no readable image path, so there "
                "is nothing to trust that could not be impersonated.\n\n"
                "Run 'Scan as administrator' to identify it first.", parent=self)
            return
        if not gmtheme.confirm(
                "Infra Monitor",
                f"Stop reporting connections owned by:\n\n{r['path']}\n\n"
                f"Every socket from this exact image is accounted for from now "
                f"on. If the file is ever replaced, the new one inherits the "
                f"trust - so only do this for programs you recognise.",
                parent=self):
            return
        gmlocal.trust_image(r["path"])
        log.info("local: trusted image %s", r["path"])
        self.app.scan_local_now()

    def _copy_local(self):
        rows = self._local_visible()
        head = "\t".join(h for _k, h, _w in self.LCOLS)
        body = "\n".join("\t".join(str(v) for v in self._local_values(r))
                         for r in rows)
        self.clipboard_clear()
        self.clipboard_append(head + "\n" + body)
        log.info("local: copied %d row(s) to clipboard", len(rows))

    # --------------------------------------------------------- connections
    CCOLS = (("dir", "DIR", 70), ("proto", "P", 48), ("proc", "PROGRAM", 160),
             ("pid", "PID", 64), ("remote", "REMOTE", 175),
             ("host", "RESOLVED", 200), ("port", "SERVICE", 125),
             ("peer", "PEER", 110), ("age", "AGE", 64),
             ("verdict", "ACCOUNTED BY", 260))

    def _make_conns_tab(self):
        """Every established session whose owner is not a system service.

        The This PC tab answers "what is unaccounted for". This one answers
        "what is my machine actually talking to right now" - a different
        question, and one whose answer is mostly benign and therefore belongs
        somewhere that is not an alarm panel."""
        outer = tk.Frame(self.nb, bg=TH.bg)
        self.nb.add(outer, text="Connections")
        self.conns_tab = outer
        self.crows = {}

        self.cbanner = tk.Label(outer, bg=TH.bg, fg=TH.muted, anchor="w",
                                font=(UI, 8))
        self.cbanner.pack(fill="x", padx=10, pady=(6, 0))
        self.ctiles = tk.Frame(outer, bg=TH.bg)
        self.ctiles.pack(fill="x", padx=8, pady=(4, 2))
        self.ccharts = tk.Canvas(outer, bg=TH.bg, highlightthickness=0,
                                 height=190)
        self.ccharts.pack(fill="x", padx=10)
        self.ccharts.bind("<Configure>", lambda _e: self._draw_charts())

        ctl = tk.Frame(outer, bg=TH.bg); ctl.pack(fill="x", padx=10, pady=(2, 4))
        tk.Label(ctl, text="peers:", bg=TH.bg, fg=TH.muted,
                 font=(UI, 8)).pack(side="left")
        self.cfilter = {}
        for key, label in (("public", "public"), ("lan", "LAN"),
                           ("loopback", "loopback")):
            v = tk.BooleanVar(value=True)
            self.cfilter[key] = v
            ttk.Checkbutton(ctl, text=label, variable=v,
                            command=self._rerender_conns).pack(side="left")
        self.chide_trusted = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctl, text="hide trusted", variable=self.chide_trusted,
                        command=self._rerender_conns)\
            .pack(side="left", padx=(12, 0))
        ttk.Button(ctl, text="Rescan", command=self.app.scan_local_now)\
            .pack(side="right")
        ttk.Button(ctl, text="Copy all", command=self._copy_conns)\
            .pack(side="right", padx=6)

        wrap = tk.Frame(outer, bg=TH.bg)
        wrap.pack(fill="both", expand=True, padx=10)
        self.ctree = ttk.Treeview(wrap, columns=[c[0] for c in self.CCOLS],
                                  show="headings", selectmode="browse")
        for key, head, width in self.CCOLS:
            self.ctree.heading(key, text=head,
                               command=lambda k=key: self._sort_conns(k))
            self.ctree.column(key, width=width, stretch=(key == "verdict"),
                              anchor="w")
        ys = ttk.Scrollbar(wrap, orient="vertical", command=self.ctree.yview)
        xs = ttk.Scrollbar(wrap, orient="horizontal", command=self.ctree.xview)
        self.ctree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y"); xs.pack(side="bottom", fill="x")
        self.ctree.pack(side="left", fill="both", expand=True)
        for tag, col in sev_colours().items():
            self.ctree.tag_configure(tag, foreground=col)
        self.ctree.bind("<<TreeviewSelect>>", self._show_conn_detail)
        self.csort = ("age", False)

        self.cdetail = tk.Text(outer, height=6, wrap="word", bg=TH.field,
                               fg=TH.text, font=(MONO, 8), relief="flat",
                               insertbackground=TH.text,
                               selectbackground=TH.accent_soft,
                               selectforeground=TH.text,
                               highlightthickness=1,
                               highlightbackground=TH.border,
                               padx=8, pady=5)
        self.cdetail.pack(fill="x", padx=10, pady=(4, 8))

    def _conns_visible(self):
        if not self.lsnap:
            return []
        rows = gmlocal.established(
            self.lsnap, include_trusted=not self.chide_trusted.get())
        out = []
        for r in rows:
            cls = r["peer_class"]
            bucket = ("loopback" if cls == "loopback"
                      else "public" if cls == "public" else "lan")
            if self.cfilter[bucket].get():
                out.append(r)
        return out

    def _conn_values(self, r, now):
        age = gmlocal.human_age(now - r["since"]) if r["since"] else "-"
        return (r["dir"], r["proto"], r["proc"], r["pid"], r["remote"] or "-",
                (r["rdns"] or "-")[:44],
                gmlocal.port_label(gmlocal.service_port(r), r["proto"].lower()),
                r["peer"] or r["peer_class"], age,
                (r["svc"] or r["signer"] or r["why"])[:70])

    def _sort_conns(self, key):
        rev = not self.csort[1] if self.csort[0] == key else False
        self.csort = (key, rev)
        self._rerender_conns()

    def _rerender_conns(self):
        if self.lsnap:
            self.render_conns(self.lsnap)

    def _draw_charts(self):
        """Three rankings side by side, redrawn on resize so the bars use the
        real width rather than a guess made before the window was mapped."""
        cv = self.ccharts
        cv.delete("all")
        st = getattr(self, "cstats", None)
        if not st:
            return
        w = max(cv.winfo_width(), 900)
        col = (w - 20) // 3
        for i, (title, items) in enumerate((
                ("Connections by program", st["by_program"]),
                ("Connections by remote host", st["by_host"]),
                ("Connections by service port", st["by_port"]))):
            draw_ranked_bars(cv, title, items, x=8 + i * col, y=6,
                             width=col - 12,
                             gutter=min(160, max(90, (col - 12) // 3)))

    def render_conns(self, lsnap):
        self.lsnap = lsnap
        now = time.time()
        rows = self._conns_visible()
        st = gmlocal.connection_stats(rows, now)
        self.cstats = st
        if not lsnap.get("ok"):
            self.cbanner.config(fg=TH.crit,
                                text="SCAN FAILED - this list is incomplete. "
                                     + str(lsnap.get("error", ""))[:240])
        else:
            self.cbanner.config(
                fg=TH.muted,
                text="Established sessions whose owner is NOT a registered "
                     "system service - listeners excluded.   "
                     f"scanned {time.strftime('%H:%M:%S', time.localtime(lsnap['checked_at']))}"
                     f" in {lsnap.get('elapsed', 0)}s")

        for w in self.ctiles.winfo_children():
            w.destroy()
        busiest, bn = st["busiest"]
        tiles = [
            ("ESTABLISHED", str(st["total"]), f"{st['programs']} program(s)"),
            ("REMOTE HOSTS", str(st["hosts"]), f"{st['public_hosts']} public"),
            ("BUSIEST", str(bn), busiest[:20]),
            ("INBOUND", str(st["inbound"]), "sessions reaching us"),
            ("NEWEST", gmlocal.human_age(st["newest"]) if st["total"] else "-",
             f"{st['recent']} opened in 5m"),
            ("OLDEST", gmlocal.human_age(st["oldest"]) if st["total"] else "-",
             "longest-lived session"),
        ]
        for label, val, note in tiles:
            # The accent edge is the same single series colour as the charts,
            # not a status colour: none of these numbers is a fault, and a red
            # or amber edge would make a busy browser look like an incident.
            gmtheme.tile(self.ctiles, label, val, note, TH.series)\
                .pack(side="left", padx=(0, 8))
        self._draw_charts()

        keep = self.ctree.selection()
        keep = keep[0] if keep else None
        self.ctree.delete(*self.ctree.get_children())
        self.crows.clear()
        key, rev = self.csort
        if key == "age":
            # Newest first by default: on a tab you open because something is
            # happening, what just started is the interesting end.
            rows.sort(key=lambda r: -(r["since"] or 0), reverse=rev)
        elif key in ("pid", "port"):
            rows.sort(key=lambda r: (r["pid"] if key == "pid"
                                     else gmlocal.service_port(r)), reverse=rev)
        else:
            idx = [c[0] for c in self.CCOLS].index(key)
            rows.sort(key=lambda r: str(self._conn_values(r, now)[idx]).lower(),
                      reverse=rev)
        for r in rows:
            iid = f"{r['proto']}|{r['laddr']}|{r['lport']}|{r['raddr']}|{r['rport']}|{r['pid']}"
            if iid in self.crows:
                continue
            self.crows[iid] = r
            self.ctree.insert("", "end", iid=iid, tags=(r["sev"],),
                              values=self._conn_values(r, now))
        if keep and keep in self.crows:
            self.ctree.selection_set(keep)
        self.nb.tab(self.conns_tab, text=f"Connections  ({st['total']})")

    def _show_conn_detail(self, _e=None):
        sel = self.ctree.selection()
        r = self.crows.get(sel[0]) if sel else None
        if r:
            self.cdetail.delete("1.0", "end")
            self.cdetail.insert("1.0", "\n".join(local_detail_lines(r)))

    def _copy_conns(self):
        now = time.time()
        head = "\t".join(h for _k, h, _w in self.CCOLS)
        body = "\n".join("\t".join(str(v) for v in self._conn_values(r, now))
                         for r in self._conns_visible())
        self.clipboard_clear()
        self.clipboard_append(head + "\n" + body)

    # ------------------------------------------------------------- stealth
    SCOLS = (("sev", "SEV", 60), ("port", "PORT", 70), ("state", "STATE", 100),
             ("name", "SERVICE", 140), ("bind", "BOUND HERE", 130),
             ("svc", "WINDOWS SERVICE", 160), ("source", "WHY PROBED", 175),
             ("ms", "MS", 64), ("note", "WHAT IT MEANS", 420))

    def _make_stealth_tab(self):
        """Is a given address invisible from outside, or does it answer?

        Manual only, and deliberately so. The other three tabs read state that
        already exists; this one SENDS ~1100 connection attempts at an address,
        which is indistinguishable from a port scan to whatever sits in front
        of it - and this fleet already has a gateway that drops port 22 for ten
        minutes when it sees a burst. A check with that cost does not get to
        fire on a timer without somebody asking for it."""
        outer = tk.Frame(self.nb, bg=TH.bg)
        self.nb.add(outer, text="Stealth")
        self.stealth_tab = outer
        self.srows, self.ssnap = {}, None
        self.sbusy = False

        self.sbanner = tk.Label(outer, bg=TH.bg, fg=TH.muted, anchor="w",
                                font=(UI, 9), justify="left")
        self.sbanner.pack(fill="x", padx=10, pady=(6, 0))
        self.scaveat = tk.Label(outer, bg=TH.bg, fg=TH.muted, anchor="w",
                                font=(UI, 8), justify="left",
                                wraplength=1340)
        self.scaveat.pack(fill="x", padx=10, pady=(2, 0))
        self.stiles = tk.Frame(outer, bg=TH.bg)
        self.stiles.pack(fill="x", padx=8, pady=(4, 2))

        ctl = tk.Frame(outer, bg=TH.bg); ctl.pack(fill="x", padx=10, pady=(2, 4))
        tk.Label(ctl, text="target:", bg=TH.bg, fg=TH.muted,
                 font=(UI, 8)).pack(side="left")
        self.starget = tk.StringVar()
        e = ttk.Entry(ctl, textvariable=self.starget, width=24,
                      font=(UI, 9))
        e.pack(side="left", padx=(4, 4))
        e.bind("<Return>", lambda _ev: self._run_stealth())
        ttk.Button(ctl, text="my public IP",
                  command=self._fill_public_ip).pack(side="left")

        tk.Label(ctl, text="  from:", bg=TH.bg, fg=TH.muted,
                 font=(UI, 8)).pack(side="left")
        # "auto" is the default and the honest one: the right vantage depends
        # on the target, and a fixed relay silently produces a wrong answer for
        # half the addresses you might type.
        self.svantage = tk.StringVar(value="auto")
        names = ["auto"] + [v["name"] for v in gmstealth.vantages(self.app.cfg)]
        self.svbox = ttk.Combobox(ctl, textvariable=self.svantage, width=12,
                                  state="readonly", values=names)
        self.svbox.pack(side="left", padx=(4, 0))

        # Speed is a control, not a setting buried elsewhere: the fast sweep is
        # the one that can get this laptop dropped by the gateway, so the
        # choice sits next to the button that fires it, with the cost of each
        # spelled out beside it rather than in documentation nobody opens.
        tk.Label(ctl, text="  sweep:", bg=TH.bg, fg=TH.muted,
                 font=(UI, 8)).pack(side="left")
        self.smode = tk.StringVar(value=gmstealth.DEFAULT_MODE)
        for key in ("fast", "gentle"):
            ttk.Radiobutton(ctl, text=key, variable=self.smode, value=key,
                            command=self._mode_hint).pack(side="left")

        self.sshowall = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctl, text="show stealthed ports too",
                        variable=self.sshowall,
                        command=self._rerender_stealth)\
            .pack(side="left", padx=(12, 0))

        self.srunbtn = ttk.Button(ctl, text="Run stealth check",
                                  style="Accent.TButton",
                                  command=self._run_stealth)
        self.srunbtn.pack(side="right")
        ttk.Button(ctl, text="Copy all", command=self._copy_stealth)\
            .pack(side="right", padx=6)

        wrap = tk.Frame(outer, bg=TH.bg)
        wrap.pack(fill="both", expand=True, padx=10)
        self.stree = ttk.Treeview(wrap, columns=[c[0] for c in self.SCOLS],
                                  show="headings", selectmode="browse")
        for key, head, width in self.SCOLS:
            self.stree.heading(key, text=head,
                               command=lambda k=key: self._sort_stealth(k))
            self.stree.column(key, width=width, stretch=(key == "note"),
                              anchor="w")
        ys = ttk.Scrollbar(wrap, orient="vertical", command=self.stree.yview)
        xs = ttk.Scrollbar(wrap, orient="horizontal", command=self.stree.xview)
        self.stree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y"); xs.pack(side="bottom", fill="x")
        self.stree.pack(side="left", fill="both", expand=True)
        for tag, col in sev_colours().items():
            self.stree.tag_configure(tag, foreground=col)
        self.stree.bind("<<TreeviewSelect>>", self._show_stealth_detail)
        self.ssort = ("sev", False)

        self.sdetail = tk.Text(outer, height=7, wrap="word", bg=TH.field,
                               fg=TH.text, font=(MONO, 8), relief="flat",
                               insertbackground=TH.text,
                               selectbackground=TH.accent_soft,
                               selectforeground=TH.text,
                               highlightthickness=1,
                               highlightbackground=TH.border,
                               padx=8, pady=5)
        self.sdetail.pack(fill="x", padx=10, pady=(4, 8))
        self.sdetail.insert("1.0", STEALTH_HELP)
        self.sbanner.config(text="No stealth check run yet - nothing here is a "
                                 "result. Enter an address and press Run.")
        self._mode_hint()

    def _mode_hint(self):
        """What the selected speed costs, before it is paid.

        'gentle' taking three minutes is something to find out while choosing
        it, not while waiting - and the fast sweep's real cost is not time, it
        is that this fleet's gateway reacts to bursts."""
        mode = self.smode.get()
        n = len(gmstealth.port_plan(self.app.lsnap))
        secs = gmstealth.estimate_seconds(n, mode)
        self.scaveat.config(
            fg=TH.muted,
            text=f"{n} ports to sweep - {gmstealth.SWEEP_MODES[mode]['label']}."
                 f"  Up to about {secs}s against a fully stealthed target.")

    def _fill_public_ip(self):
        """Resolving our own address is a network call, so it cannot happen on
        the Tk thread - a two-second stall in the UI of a monitor looks exactly
        like the freeze it exists to notice."""
        def work():
            ip = gmcheck.public_ip()
            self.after(0, lambda: self.starget.set(ip or ""))
            if not ip:
                self.after(0, lambda: self.sbanner.config(
                    fg=TH.warn, text="Could not determine this machine's public "
                                     "IP - offline, or every lookup service is "
                                     "unreachable."))
        threading.Thread(target=work, daemon=True, name="pubip").start()

    def _run_stealth(self):
        target = self.starget.get().strip()
        if not target:
            gmtheme.notice("Infra Monitor", "Enter an IP address or hostname to "
                                          "check.", parent=self)
            return
        if self.sbusy:
            return
        van = self.svantage.get()
        van = None if van == "auto" else van
        mode = self.smode.get()
        n = len(gmstealth.port_plan(self.app.lsnap))
        self.sbusy = True
        self.srunbtn.config(state="disabled", text="Scanning...")
        self.sbanner.config(
            fg=TH.muted,
            text=f"Sweeping {target} ({mode}) - {n} ports: the privileged "
                 f"range, common services, and every port this PC listens on."
                 f"  Up to about {gmstealth.estimate_seconds(n, mode)}s.")
        self.app.run_stealth(target, van, mode)

    def _stealth_visible(self):
        rows = (self.ssnap or {}).get("rows", [])
        if self.sshowall.get():
            return list(rows)
        return [r for r in rows if r["state"] != "stealth"]

    def _stealth_values(self, r):
        return (r["sev"], r["port"], r["state"], r["name"] or "-",
                r["bind"] or "-", r["svc"] or "-", r["source"],
                r["ms"] or "", r["note"] or r["why"])

    def _sort_stealth(self, key):
        rev = not self.ssort[1] if self.ssort[0] == key else False
        self.ssort = (key, rev)
        self._rerender_stealth()

    def _rerender_stealth(self):
        if self.ssnap:
            self.render_stealth(self.ssnap)

    def render_stealth(self, ssnap):
        self.ssnap = ssnap
        self.sbusy = False
        self.srunbtn.config(state="normal", text="Run stealth check")
        c = ssnap.get("counts", {})

        if not ssnap.get("ok"):
            # A sweep that did not run must never render like a clean one. No
            # tiles, no rows, and the reason in place of the verdict.
            self.sbanner.config(
                fg=TH.crit,
                text="STEALTH CHECK DID NOT RUN - this is NOT an all-clear.\n"
                     + str(ssnap.get("error", ""))[:300])
            self.scaveat.config(text="")
            for w in self.stiles.winfo_children():
                w.destroy()
            self.stree.delete(*self.stree.get_children())
            self.srows.clear()
            self.nb.tab(self.stealth_tab, text="Stealth  (failed)")
            return

        col = {"EXPOSED": TH.crit, "NOT STEALTH": TH.warn,
               "UNCONFIRMED": TH.serious, "STEALTH": TH.good,
               # Not a status colour: a self-probe is neither a pass nor a
               # fault, and giving it one would make a no-op look like a
               # result.
               "SELF-PROBE": TH.muted}.get(ssnap["verdict"], TH.muted)
        self.sbanner.config(
            fg=col,
            text=f"{ssnap['verdict']} - {ssnap['verdict_note']}\n"
                 f"{ssnap['ip']}"
                 + (f" ({ssnap['note']})" if ssnap.get("note") else "")
                 + f"   probed from {ssnap['vantage']} "
                   f"({ssnap['vantage_kind']})   {c.get('total', 0)} ports "
                   f"{ssnap.get('mode', '')} in "
                   f"{ssnap.get('elapsed', 0)}s   ICMP: "
                   f"{ssnap.get('ping') or 'not attempted'}"
                 + (f"   ARP: {ssnap['arp']}" if ssnap.get("arp") else ""))
        # The caveat is never folded into the verdict line. It is the sentence
        # that stops the verdict being over-read, and a reader who skims one
        # line must not skim past it. With nothing to qualify, the slot goes
        # back to telling you what the next sweep will cost.
        if ssnap.get("caveat"):
            self.scaveat.config(fg=TH.serious, text=ssnap["caveat"])
        else:
            self._mode_hint()

        for w in self.stiles.winfo_children():
            w.destroy()
        alive = bool(ssnap.get("arp")) or ssnap.get("ping") == "reply"
        # Note the inverted colour on STEALTH: here a big number is the good
        # news, which is the opposite of every other tile in this app, so it
        # cannot inherit the "non-zero means trouble" rule the others use.
        tiles = [
            ("OPEN", str(c.get("open", 0)), "answered a handshake",
             TH.crit if c.get("open") else TH.good),
            ("REACHABLE HERE", str(c.get("listeners_open", 0)),
             "our own listeners, from outside",
             TH.crit if c.get("listeners_open") else TH.good),
            ("CLOSED", str(c.get("closed", 0)), "RST - host reveals itself",
             TH.warn if c.get("closed") else TH.good),
            ("STEALTH", str(c.get("stealth", 0)),
             f"{c.get('stealth_pct', 0)}% dropped silently", TH.good),
            # Whether the target proved it exists at all. Without this, a
            # sweep of a switched-off machine renders identically to a
            # perfectly stealthed one - 100% stealth, nothing open - and the
            # tile is the only thing on screen that tells them apart.
            ("HOST IS UP", "yes" if alive else "unproven",
             "ARP/ICMP - is the silence real?", TH.good if alive else TH.serious),
            ("UNTESTED", str(c.get("untested", 0)), "no conclusive answer",
             TH.warn if c.get("untested") else TH.good),
            ("OUR PORTS", str(c.get("listeners", 0)),
             f"{c.get('privileged', 0)} privileged also swept", TH.muted),
        ]
        for label, val, note, accent in tiles:
            gmtheme.tile(self.stiles, label, val, note, accent)\
                .pack(side="left", padx=(0, 8))

        keep = self.stree.selection()
        keep = keep[0] if keep else None
        self.stree.delete(*self.stree.get_children())
        self.srows.clear()
        key, rev = self.ssort
        rows = self._stealth_visible()
        if key == "sev":
            rows.sort(key=lambda r: (gmstealth.SEV_ORDER.get(r["sev"], 9),
                                     gmstealth.STATE_ORDER.get(r["state"], 9),
                                     r["port"]), reverse=rev)
        elif key in ("port", "ms"):
            rows.sort(key=lambda r: r[key], reverse=rev)
        elif key == "state":
            rows.sort(key=lambda r: (gmstealth.STATE_ORDER.get(r["state"], 9),
                                     r["port"]), reverse=rev)
        else:
            rows.sort(key=lambda r: str(r.get(key, "")).lower(), reverse=rev)
        for r in rows:
            iid = f"{r['proto']}|{r['port']}"
            if iid in self.srows:
                continue
            self.srows[iid] = r
            self.stree.insert("", "end", iid=iid, tags=(r["sev"],),
                              values=self._stealth_values(r))
        if keep and keep in self.srows:
            self.stree.selection_set(keep)

        # Two marks again, and for the same reason as the This PC tab: an open
        # port is something to act on, an untested one is something we failed
        # to establish. Collapsing them would let a sweep that half ran read as
        # a sweep that found nothing.
        o, u = c.get("open", 0), c.get("untested", 0)
        marks = ([f"{o} open"] if o else []) + ([f"{u}?"] if u else [])
        if ssnap.get("self_probe"):
            marks = []          # "14 open" on a self-probe is a scary non-fact
        self.nb.tab(self.stealth_tab,
                    text="Stealth  (" + ("  ".join(marks) if marks
                                         else ssnap["verdict"].lower()) + ")")

    def _show_stealth_detail(self, _e=None):
        sel = self.stree.selection()
        r = self.srows.get(sel[0]) if sel else None
        if not r:
            return
        self.sdetail.delete("1.0", "end")
        self.sdetail.insert("1.0", "\n".join(stealth_detail_lines(r, self.ssnap)))

    def _copy_stealth(self):
        head = "\t".join(h for _k, h, _w in self.SCOLS)
        body = "\n".join("\t".join(str(v) for v in self._stealth_values(r))
                         for r in self._stealth_visible())
        s = self.ssnap or {}
        # The verdict travels with the rows. Pasted into a ticket, a bare port
        # table does not say where it was probed from - and from the wrong
        # vantage the same table means the opposite thing.
        hdr = (f"# stealth check {s.get('ip', '')} from {s.get('vantage', '')} "
               f"({s.get('vantage_kind', '')}) - {s.get('verdict', '')}\n"
               f"# {s.get('verdict_note', '')}\n"
               + (f"# CAVEAT: {s.get('caveat')}\n" if s.get("caveat") else ""))
        self.clipboard_clear()
        self.clipboard_append(hdr + head + "\n" + body)

    def _make_tab(self, label):
        """A tab holding its own independently scrolling canvas, so scrolling
        one fleet does not move the other."""
        outer = tk.Frame(self.nb, bg=TH.bg)
        self.nb.add(outer, text=label)
        cv = tk.Canvas(outer, bg=TH.bg, highlightthickness=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=cv.yview)
        inner = tk.Frame(cv, bg=TH.bg)
        inner.bind("<Configure>",
                   lambda e, c=cv: c.configure(scrollregion=c.bbox("all")))
        win = cv.create_window((0, 0), window=inner, anchor="nw")
        # Pin the scrolled frame to the canvas WIDTH. Without this it keeps its
        # natural width, so the card grid sizes its columns from the widest
        # problem string rather than from the window - and the machines in
        # columns 2 and 3 end up drawn past the right edge, invisible. A
        # monitor that hides a machine is the one failure it cannot have.
        cv.bind("<Configure>",
                lambda e, c=cv, w=win: c.itemconfigure(w, width=e.width),
                add="+")
        cv.configure(yscrollcommand=sb.set)
        cv.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        # Bound to the canvas, not bind_all: a global wheel binding would
        # scroll whichever pane was created last, whatever the mouse is over.
        for w in (cv, inner):
            w.bind("<MouseWheel>",
                   lambda e, c=cv: c.yview_scroll(int(-e.delta / 120), "units"))
        return {"outer": outer, "canvas": cv, "inner": inner}

    def hide(self):
        self.withdraw()

    def render(self, snap):
        for p in self.panes.values():
            for w in p["inner"].winfo_children():
                w.destroy()
        if not snap:
            tk.Label(self.panes["local"]["inner"], bg=TH.bg, fg=TH.muted,
                     font=(UI, 9),
                     text="No data yet - first poll in progress.").pack(pady=30)
            return
        gate = ("ON-NETWORK" if snap["gate_ok"] else "OFF-NETWORK")
        self.status.config(
            text=f"{gate} ({snap['gate_note']}, via {snap['gate_id']})   "
                 f"checked {time.strftime('%H:%M:%S', time.localtime(snap['checked_at']))}"
                 f" in {snap['elapsed']}s",
            fg=TH.muted)
        if not snap["machines"]:
            # An empty fleet polls in 0.0s and reports nothing wrong, which
            # looks exactly like a healthy one. Say what is actually going on,
            # and say where the file it wants should be - the usual cause is
            # running a copy of the exe from a folder that has no config.
            missing = not gmconfig.exists()
            self.status.config(
                fg=TH.crit,
                text=("NO CONFIGURATION - machines.json was not found. "
                      if missing else "No machines configured yet. ")
                     + f"Infra Monitor is reading from {gmpaths.APP_DIR}")
            for key in ("local", "dc"):
                tk.Label(
                    self.panes[key]["inner"], bg=TH.bg, fg=TH.text, justify="left",
                    font=(UI, 10), padx=20, pady=24,
                    text=("machines.json was not found.\n\n"
                          if missing else
                          "No machines configured yet.\n\n")
                         + f"Infra Monitor reads its config from the folder it "
                           f"runs from:\n    {gmpaths.APP_DIR}\n\n"
                           "This is NOT an all-clear - nothing is being "
                           "monitored.\n\n"
                           "Add one with Settings > Add machine... (or Import..."
                           "),\nor edit machines.json directly - see "
                           "machines.example.json for a template.").pack(anchor="w")
            self.render_problems(getattr(self.app, "problem_log", []))
            return

        groups = {
            "local": ([r for r in snap["machines"] if r["scope"] == "local"],
                      "Local Fleet", "private network - polled only on a known network (gate)"),
            "dc":    ([r for r in snap["machines"] if r["scope"] != "local"],
                      "Public Fleet", "internet-reachable - always checked, gate ignored"),
        }
        for i, (key, (group, label, note)) in enumerate(groups.items()):
            pane = self.panes[key]
            n_bad = sum(1 for r in group
                        if r.get("checked") and (not r["up"] or r["problems"]))
            # The count rides on the tab itself, so a problem in the tab you
            # are NOT looking at is still visible - otherwise tabs hide faults,
            # which is the one thing a monitor must never do.
            self.nb.tab(i, text=f"{label}  ({n_bad}⚠)" if n_bad
                        else f"{label}  (ok)")
            if not group:
                tk.Label(pane["inner"], text="No machines in this fleet.",
                         bg=TH.bg, fg=TH.muted).pack(pady=30)
                continue
            tk.Label(pane["inner"], text=note, bg=TH.bg, fg=TH.muted,
                     font=(UI, 8)).grid(row=0, column=0, columnspan=self._ncols(), sticky="w", padx=10, pady=(6, 0))
            self._fleet_tiles(pane["inner"], group)
            self._cards(pane["inner"], group, 2)
        self.render_problems(getattr(self.app, "problem_log", []))

    def render_problems(self, entries):
        """Newest first. A Text widget, so the whole log is selectable and
        copyable - this is the pane whose contents end up pasted into a ticket
        or a message, and a grid of Labels cannot be copied at all."""
        self.problems.configure(state="normal")
        self.problems.delete("1.0", "end")
        n_open = sum(1 for e in entries if e["kind"] != "recovered")
        self.nb.tab(2, text=f"Problems  ({len(entries)})" if entries
                    else "Problems")
        if not entries:
            self.problems.insert("end", "No problems recorded since start.\n",
                                 "dim")
        for e in entries:
            tag = ("ok" if e["kind"] == "recovered"
                   else "crit" if e["kind"] in ("failed", "new") else "warn")
            self.problems.insert(
                "end", f"{e['when']}  {e['machine']:<9} {e['kind']:<10} ", tag)
            self.problems.insert("end", e["text"] + "\n")
        # Left editable so selection and Ctrl+C work; the poller rewrites it
        # each cycle anyway, so a stray keystroke cannot corrupt anything.
        self.problems.see("1.0")

    def _fleet_tiles(self, parent, group):
        """Per-fleet KPI row: the worst machine per resource, not the average.

        An average hides the thing you need to see - one host at 97% disk
        vanishes into a fleet mean of 30%. The headline number is the peak, with the
        machine that owns it named underneath, so the tile is actionable
        instead of merely tidy."""
        live = [r for r in group if r.get("checked") and r["up"]]
        bar = tk.Frame(parent, bg=TH.bg)
        bar.grid(row=1, column=0, columnspan=self._ncols(), sticky="ew", padx=8, pady=(6, 2))
        if not live:
            tk.Label(bar, text="No machines reachable.", bg=TH.bg,
                     fg=TH.muted, font=(UI, 9)).pack(anchor="w")
            return

        def peak(key):
            best = max(live, key=lambda r: r["metrics"].get(key, 0) or 0)
            return best["metrics"].get(key, 0) or 0, best["name"]

        def gpu_peak():
            top, who = 0, "-"
            for r in live:
                for g in r["metrics"].get("gpus", []):
                    if g["util"] >= top:
                        top, who = g["util"], f"{r['name']}:{g['index']}"
            return top, who

        tiles = [("CPU", *peak("cpu")), ("MEMORY", *peak("mem")),
                 ("DISK", *peak("disk")), ("GPU", *gpu_peak())]
        for label, val, who in tiles:
            col, word = severity(val)
            gmtheme.tile(bar, f"PEAK {label}", f"{int(val)}%", who, col,
                         word=word).pack(side="left", padx=(0, 8))

    CARD_MIN_PX = 430          # widest real card: name + addr + 7 dials

    def _ncols(self):
        """How many machine cards fit across the window right now.

        Chaining them horizontally is what actually uses the width - one card
        per row left most of the dashboard empty and pushed 13 machines into a
        scroll. Derived from the live window width rather than fixed, so
        widening the window packs more per row instead of just stretching
        them."""
        w = self.winfo_width()
        if w <= 1:                         # before first map, geometry is 1x1
            w = 1400
        return max(1, min(4, w // self.CARD_MIN_PX))

    def _cards(self, parent, group, base_row):
        for i, r in enumerate(group):
            m = r["metrics"]
            if not r.get("checked"):
                bar = TH.grey
            elif not r["up"]:
                bar = TH.crit
            elif r["problems"]:
                bar = (TH.crit if any("FOREIGN" in p for p in r["problems"])
                       else TH.warn)
            else:
                bar = TH.good

            # ONE machine per full-width row. Two narrow columns forced every
            # problem string to be truncated at ~150 chars; a single wide row
            # gives the text the horizontal space it needs, and makes the fleet
            # scan as a list rather than a grid.
            card = tk.Frame(parent, bg=TH.surface, highlightthickness=1,
                            highlightbackground=TH.border)
            nc = self._ncols()
            card.grid(row=base_row + i // nc, column=i % nc,
                      padx=3, pady=1, sticky="ew")
            for c in range(nc):
                parent.grid_columnconfigure(c, weight=1, uniform="cards")
            tk.Frame(card, bg=bar, width=4).pack(side="left", fill="y")

            body = tk.Frame(card, bg=TH.surface)
            body.pack(side="left", fill="both", expand=True, padx=4, pady=1)

            # Name, address, dials and status all on ONE line. Vertical space
            # is the scarce axis when 13 machines should fit without scrolling;
            # horizontal space is free.
            row0 = tk.Frame(body, bg=TH.surface); row0.pack(fill="x")
            tk.Label(row0, text=r["name"], bg=TH.surface, fg=TH.text, width=7,
                     anchor="w", font=(UI, 9, "bold")).pack(side="left")
            copyable(row0, r["ip"] or r.get("alias", ""), width=16,
                     fg=TH.muted, font=(MONO, 8)).pack(side="left")

            gpus = m.get("gpus", [])
            if r.get("checked") and r["up"]:
                n = 3 + min(len(gpus), 4)
                cv = tk.Canvas(body, bg=TH.surface, height=56, width=n * 58,
                               highlightthickness=0)
                cv.pack(side="left", anchor="w")
                draw_dial(cv, 26, 22, 16, m.get("cpu", 0), "CPU")
                draw_dial(cv, 84, 22, 16, m.get("mem", 0), "MEM",
                          "%d/%dG" % (m.get("mem_used_mb", 0) // 1024,
                                      m.get("mem_total_mb", 0) // 1024))
                draw_dial(cv, 142, 22, 16, m.get("disk", 0), "DISK",
                          "%d/%dG" % (m.get("disk_used_gb", 0),
                                      m.get("disk_total_gb", 0)))
                for j, g in enumerate(gpus[:4]):
                    draw_dial(cv, 200 + j * 58, 22, 16, g["util"],
                              "GPU%d" % g["index"], "%dC" % g["temp"])
                extra = ("  +%d more" % (len(gpus) - 4)) if len(gpus) > 4 else ""
                gtxt = ("%dx %s%s" % (len(gpus), gpus[0]["name"], extra)
                        if gpus else m.get("nvidia", "no GPU"))
                lb = tk.Label(row0, text="  " + gtxt[:32], bg=TH.surface,
                              fg=TH.muted, font=(UI, 8))
                lb.pack(side="left")
                Tooltip(lb, gtxt)
                qp = m.get("quickpod", "-")
                q = tk.Label(row0, text="  qp:" + qp.split(":")[-1][:8],
                             bg=TH.surface, fg=TH.muted, font=(UI, 8))
                q.pack(side="left")
                Tooltip(q, "quickpod: " + qp)
            else:
                note = r.get("note") or "; ".join(r["problems"]) or "unreachable"
                e = copyable(row0, note[:100], fg=TH.muted,
                             font=(UI, 8), width=40)
                e.pack(side="left", fill="x", expand=True)
                Tooltip(e, note)

            if r["problems"]:
                full = "  |  ".join(r["problems"])
                pe = copyable(body, "! " + full, fg=bar,
                              font=(UI, 8), width=40)
                pe.pack(fill="x")
                # Full text on hover: the tail of a problem string is usually
                # the actionable half, and it is exactly what gets cut off.
                Tooltip(pe, "\n".join(r["problems"]))




class Settings(tk.Toplevel):
    """Edit which machines are watched and which checks apply to each.

    Writes machines.json, which the poller re-reads every cycle - so a change
    takes effect on the next poll with nothing to restart."""

    COLS = ("machine", "scope", "watch", "quickpod", "nvidia", "relay")

    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.title("Infra Monitor - Settings")
        # Wider than the original 720: the Aura type scale is a step up from
        # the 8pt this window was laid out for, and at 720 the button row ran
        # off the edge with Cancel past the frame.
        self.geometry("1000x580")
        self.minsize(900, 480)
        self.configure(bg=TH.bg)
        self.rows = {}

        tk.Label(self, bg=TH.bg, fg=TH.muted, justify="left", anchor="w",
                 font=(UI, 9), padx=10, pady=5, wraplength=860,
                 text="Turn a check off for machines it does not apply to - a "
                      "permanent warning you cannot act on is what teaches you "
                      "to ignore the panel. Private machines are only polled "
                      "while you are on a known network; public ones are always "
                      "polled.").pack(fill="x")

        head = tk.Frame(self, bg=TH.surface2); head.pack(fill="x", padx=10)
        for t, w in (("Machine", 22), ("Network", 12), ("Watch", 8),
                     ("quickpod", 10), ("nvidia-smi", 11), ("Reached via", 14)):
            tk.Label(head, text=t, width=w, anchor="w", bg=TH.surface2,
                     fg=TH.text,
                     font=(UI, 8, "bold")).pack(side="left", pady=4)

        wrap = tk.Frame(self, bg=TH.bg); wrap.pack(fill="both", expand=True, padx=10)
        cv = tk.Canvas(wrap, bg=TH.bg, highlightthickness=0)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=cv.yview)
        self.body = tk.Frame(cv, bg=TH.bg)
        self.body.bind("<Configure>",
                       lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.create_window((0, 0), window=self.body, anchor="nw")
        cv.configure(yscrollcommand=sb.set)
        cv.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
        cv.bind("<MouseWheel>",
                lambda e: cv.yview_scroll(int(-e.delta / 120), "units"))

        al = tk.Frame(self, bg=TH.bg); al.pack(fill="x", padx=10, pady=(6, 0))
        tk.Label(al, bg=TH.bg, fg=TH.text, font=(UI, 8, "bold"),
                 text="Allowed SSH peers (comma separated IPs or CIDRs)")\
            .pack(anchor="w")
        tk.Label(al, bg=TH.bg, fg=TH.muted, font=(UI, 7), justify="left",
                 anchor="w", wraplength=860,
                 text="Sessions from anywhere else are alerted as intrusions. "
                      "Every monitored machine and both gate networks are "
                      "already allowed automatically - list only extras here.")\
            .pack(anchor="w")
        self.peers = ttk.Entry(al, font=(MONO, 8))
        self.peers.pack(fill="x", pady=(2, 0))

        jl = tk.Frame(self, bg=TH.bg); jl.pack(fill="x", padx=10, pady=(8, 0))
        tk.Label(jl, bg=TH.bg, fg=TH.text, font=(UI, 8, "bold"),
                 text="Default relay for private machines (optional)")\
            .pack(anchor="w")
        tk.Label(jl, bg=TH.bg, fg=TH.muted, font=(UI, 7), justify="left",
                 anchor="w", wraplength=860,
                 text="Machines on a private network are reached through this "
                      "host unless their own relay above says otherwise. Leave "
                      "empty to connect to every machine directly.")\
            .pack(anchor="w")
        # values are filled in build(), which is the only place cfg is loaded —
        # constructing them here would freeze an empty list into the widget
        self.jump = ttk.Combobox(jl, font=(MONO, 8), state="readonly", values=[""])
        self.jump.pack(fill="x", pady=(2, 0))

        bar = tk.Frame(self, bg=TH.bg); bar.pack(fill="x", padx=10, pady=8)
        ttk.Button(bar, text="Add machine...", command=self.add).pack(side="left")
        ttk.Button(bar, text="Relay hosts...", command=self.relays)\
            .pack(side="left", padx=6)
        ttk.Button(bar, text="Remove selected", command=self.remove)\
            .pack(side="left", padx=6)
        ttk.Button(bar, text="Export...", command=self.export_cfg)\
            .pack(side="left", padx=(18, 0))
        ttk.Button(bar, text="Import...", command=self.import_cfg)\
            .pack(side="left", padx=6)
        ttk.Button(bar, text="Save & re-check", command=self.save)\
            .pack(side="right")
        ttk.Button(bar, text="Cancel", command=self.destroy)\
            .pack(side="right", padx=6)
        self.build()

    def build(self):
        for w in self.body.winfo_children():
            w.destroy()
        self.rows.clear()
        self.cfg = gmconfig.load()
        self.sel = tk.StringVar(value="")
        if hasattr(self, "peers"):
            self.peers.delete(0, "end")
            self.peers.insert(0, ", ".join(self.cfg.get("allowed_peers", [])))
        if hasattr(self, "jump"):
            # refresh the choices too: a relay added in the Relay hosts dialog
            # must appear here without reopening Settings
            self.jump["values"] = [""] + gmconfig.relay_names(self.cfg)
            self.jump.set(self.cfg.get("jump_host", "") or "")
        for m in self.cfg["machines"]:
            row = tk.Frame(self.body, bg=TH.bg); row.pack(fill="x")
            v = {"watch": tk.BooleanVar(value=m.get("enabled", True)),
                 "quickpod": tk.BooleanVar(value=m.get("check_quickpod", False)),
                 "nvidia": tk.BooleanVar(value=m.get("check_nvidia", True)),
                 "scope": tk.StringVar(
                     value="public" if gmconfig.scope_of(m) == "public" else "private")}
            self.rows[m["name"]] = v
            ttk.Radiobutton(row, text="", variable=self.sel,
                            value=m["name"]).pack(side="left")
            tk.Label(row, text=f"{m['name']}  ({m.get('ip') or m.get('alias','')})",
                     width=20, anchor="w", bg=TH.bg, fg=TH.text,
                     font=(UI, 9)).pack(side="left")
            ttk.Combobox(row, textvariable=v["scope"], width=9, state="readonly",
                         values=("private", "public")).pack(side="left", padx=(0, 12))
            for key, pad in (("watch", 30), ("quickpod", 44), ("nvidia", 46)):
                ttk.Checkbutton(row, variable=v[key]).pack(side="left")
                tk.Frame(row, bg=TH.bg, width=pad).pack(side="left")
            # "Reached via" used to be a read-only label, so a relay could only
            # be set when the machine was first added and never changed, and the
            # global default had no UI at all (owner, 2026-08-17: "we need a way
            # to add relay hosts"). It is a picker now: any other machine can act
            # as the relay, or "(direct)" for a straight SSH connection.
            v["via"] = tk.StringVar(value=(m.get("via") or ""))
            others = [""] + [n for n in gmconfig.relay_names(self.cfg)
                             if n != m["name"]]
            box = ttk.Combobox(row, textvariable=v["via"], width=12,
                               values=others)
            box.pack(side="left")
            # what it RESOLVES to, which is not the same thing: a private machine
            # with no explicit via still inherits the default relay below
            eff = gmconfig.relay_of(self.cfg, m) or "direct"
            tk.Label(row, text="→ %s" % eff, anchor="w", bg=TH.bg, fg=TH.muted,
                     font=(UI, 7)).pack(side="left", padx=(4, 0))

    def add(self):
        d = tk.Toplevel(self); d.title("Add machine"); d.configure(bg=TH.bg)
        d.transient(self.winfo_toplevel())
        fields = {}
        # key and label are separate on purpose: the key is what ok() reads, so
        # renaming a label (e.g. "ip" -> "IP or hostname") must not silently
        # change the dict key and turn Add into a KeyError.
        hops = [""] + gmconfig.relay_names(gmconfig.load())
        for i, (key, lbl, default) in enumerate(
                (("name", "name", ""),
                 ("ip", "IP or hostname", ""),
                 ("user", "user", "root"),
                 ("alias", "alias (optional)", ""),
                 ("via", "via relay (optional)", ""))):
            tk.Label(d, text=lbl, bg=TH.bg, fg=TH.text, font=(UI, 8),
                     anchor="w", width=18)\
                .grid(row=i, column=0, padx=8, pady=4, sticky="w")
            if key == "via":
                # a relay is CHOSEN, not typed: free text here just invited a
                # name that does not exist (owner: "relays should be available
                # as dropdowns")
                e = ttk.Combobox(d, width=26, values=hops, state="readonly")
                e.set(default)
            else:
                e = ttk.Entry(d, width=28); e.insert(0, default)
            e.grid(row=i, column=1, padx=8, pady=4)
            fields[key] = e
        sc = tk.StringVar(value="private")
        ttk.Combobox(d, textvariable=sc, width=10, state="readonly",
                     values=("private", "public")).grid(row=5, column=1, sticky="w",
                                                        padx=8)
        tk.Label(d, text="network", bg=TH.bg, fg=TH.text, font=(UI, 8),
                 anchor="w", width=18)\
            .grid(row=5, column=0, padx=8, sticky="w")

        def ok():
            try:
                cfg = gmconfig.load()
                gmconfig.add(cfg, fields["name"].get().strip(),
                             fields["ip"].get().strip(),
                             fields["user"].get().strip() or "root",
                             scope=("public" if sc.get() == "public" else "local"),
                             via=fields["via"].get().strip() or None,
                             alias=fields["alias"].get().strip() or None)
                gmconfig.save(cfg)
                d.destroy(); self.build()
            except gmconfig.ConfigError as ex:
                gmtheme.error("Infra Monitor", str(ex), parent=d)
        ttk.Button(d, text="Add", command=ok).grid(row=6, column=1, sticky="e",
                                                  padx=8, pady=8)

    def relays(self):
        """Add or remove RELAY hosts — bastions you connect *through*.

        A relay used to have to be one of the monitored machines, because
        sshconn.open_jump looked the name up in machines.json. That made a plain
        bastion impossible to configure (owner, 2026-08-17: "still does not have
        a way to add relay hosts"). Relays are their own list now: name, address,
        user, port — nothing about monitoring.
        """
        d = tk.Toplevel(self); d.title("Relay hosts"); d.configure(bg=TH.bg)
        d.transient(self.winfo_toplevel())
        tk.Label(d, bg=TH.bg, fg=TH.muted, font=(UI, 8), justify="left",
                 wraplength=520, anchor="w",
                 text="A relay is a host you connect THROUGH to reach machines "
                      "that are not directly reachable. It does not have to be "
                      "monitored. Pick a relay per machine, or set one as the "
                      "default, in the main Settings window.")\
            .pack(fill="x", padx=12, pady=(12, 8))

        listbox = tk.Listbox(d, height=6, bg=TH.surface, fg=TH.text,
                             selectbackground=TH.get("accent", "#5b86f7"),
                             highlightthickness=0, relief="flat", font=(MONO, 9))
        listbox.pack(fill="both", expand=True, padx=12)

        def refill():
            listbox.delete(0, "end")
            for r in gmconfig.load().get("relays", []):
                listbox.insert("end", "%s    %s@%s:%s"
                               % (r.get("name"), r.get("user", "root"),
                                  r.get("ip", "?"), r.get("port", 22)))
            if not listbox.size():
                listbox.insert("end", "(no relay hosts yet)")
        refill()

        form = tk.Frame(d, bg=TH.bg); form.pack(fill="x", padx=12, pady=10)
        ent = {}
        for i, (key, lbl, default) in enumerate(
                (("name", "name", ""), ("host", "IP or hostname", ""),
                 ("user", "user", "root"), ("port", "port", "22"))):
            tk.Label(form, text=lbl, bg=TH.bg, fg=TH.text, anchor="w",
                     width=14, font=(UI, 8)).grid(row=i, column=0, sticky="w",
                                                  pady=2)
            e = ttk.Entry(form, width=26); e.insert(0, default)
            e.grid(row=i, column=1, sticky="w", pady=2)
            ent[key] = e

        def add_it():
            cfg = gmconfig.load()
            try:
                gmconfig.add_relay(cfg, ent["name"].get().strip(),
                                   ent["host"].get().strip(),
                                   ent["user"].get().strip() or "root",
                                   ent["port"].get().strip() or 22)
            except gmconfig.ConfigError as ex:
                gmtheme.error("Infra Monitor", str(ex), parent=d)
                return
            gmconfig.save(cfg)
            for e in ent.values():
                e.delete(0, "end")
            ent["user"].insert(0, "root"); ent["port"].insert(0, "22")
            refill()
            self.build()          # the pickers must offer the new relay at once

        def remove_it():
            sel = listbox.curselection()
            if not sel:
                gmtheme.notice("Infra Monitor", "Select a relay first.", parent=d)
                return
            name = listbox.get(sel[0]).split()[0]
            if name == "(no":
                return
            if not gmtheme.confirm(
                    "Remove relay",
                    "Remove relay %r?\n\nAny machine using it goes back to a "
                    "direct connection." % name, parent=d):
                return
            cfg = gmconfig.remove_relay(gmconfig.load(), name)
            gmconfig.save(cfg)
            refill()
            self.build()

        row = tk.Frame(d, bg=TH.bg); row.pack(fill="x", padx=12, pady=(0, 12))
        ttk.Button(row, text="Add relay", command=add_it).pack(side="left")
        ttk.Button(row, text="Remove selected", command=remove_it)\
            .pack(side="left", padx=6)
        ttk.Button(row, text="Close", command=d.destroy).pack(side="right")

    def export_cfg(self):
        """Write a portable copy of this configuration.

        Offers to keep the local trusted-image list only when there is one -
        a checkbox for an empty list is a question with no wrong answer, which
        is a question not worth asking."""
        import gmexport
        cfg = gmconfig.load()
        has_local = bool(cfg.get("local_watch", {}).get("trusted_images"))
        path = filedialog.asksaveasfilename(
            parent=self, title="Export Infra Monitor configuration",
            defaultextension=".json", initialfile="infra-monitor-config.json",
            filetypes=[("Infra Monitor config", "*.json"), ("All files", "*.*")])
        if not path:
            return
        with_local = has_local and gmtheme.confirm(
            "Infra Monitor", "Include this machine's trusted-image list?\n\n"
            "Those are absolute paths to binaries on THIS PC. On another "
            "machine they are meaningless at best, and at worst a path that "
            "now resolves to a different program.\n\nNo is the safe answer.",
            parent=self, default="no")
        try:
            b = gmexport.export_config(path, with_local=with_local)
        except Exception as ex:
            gmtheme.error("Infra Monitor", f"Export failed:\n\n{ex}", parent=self)
            return
        log.info("config exported to %s (with_local=%s)", path, with_local)
        gmtheme.notice(
            "Infra Monitor", f"Exported {len(b['config'].get('machines', []))} "
            f"machine(s) to\n\n{path}\n\nNothing in this file is secret - no "
            f"keys, no passwords. The 'bootstrapped' flags were reset, so the "
            f"new machine will not offer a key to a host that has never seen "
            f"it.", parent=self)

    def import_cfg(self):
        import gmexport
        path = filedialog.askopenfilename(
            parent=self, title="Import Infra Monitor configuration",
            filetypes=[("Infra Monitor config", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            data, incoming = gmexport.read_bundle(path)
            problems = gmexport.validate(incoming)
        except Exception as ex:
            gmtheme.error("Infra Monitor", f"Cannot read that file:\n\n{ex}",
                                 parent=self)
            return
        if problems:
            # Refuse rather than import the good half: a config that is
            # partly the old fleet and partly the new one is worse than either.
            gmtheme.error(
                "Infra Monitor", "This config was NOT imported - nothing has "
                "changed:\n\n" + "\n".join(problems[:12]), parent=self)
            return
        n = len(incoming.get("machines", []))
        merge = gmtheme.confirm(
            "Infra Monitor",
            f"{os.path.basename(path)}\nwritten {data.get('exported_at')} on "
            f"{data.get('exported_from')}\n\n{n} machine(s).\n\n"
            f"YES  - merge into the current fleet, keeping this machine's own "
            f"settings.\nNO   - replace the whole configuration.\n\n"
            f"Either way the current machines.json is backed up first.",
            parent=self)
        try:
            summary, backup = gmexport.import_config(path, merge=merge)
        except Exception as ex:
            gmtheme.error("Infra Monitor", f"Import failed:\n\n{ex}", parent=self)
            return
        log.info("config imported from %s (merge=%s): %s", path, merge, summary)
        gmtheme.notice(
            "Infra Monitor", f"{summary['machines']} machine(s) now configured "
            f"({summary['added']} added, {summary['updated']} updated).\n\n"
            + (f"Previous config kept as\n{os.path.basename(backup)}\n\n"
               if backup else "")
            + "Key auth is not verified on this machine yet - run "
              "bootstrap_ssh before trusting the first poll.", parent=self)
        self.build()
        self.app.poll_now()

    def remove(self):
        name = self.sel.get()
        if not name:
            gmtheme.notice("Infra Monitor", "Select a machine first.", parent=self)
            return
        if not gmtheme.confirm("Infra Monitor", f"Stop monitoring {name}?\n\n"
                                   "Its SSH key on the machine is left alone.",
                                   parent=self):
            return
        cfg = gmconfig.load()
        gmconfig.remove(cfg, name)
        gmconfig.save(cfg)
        self.build()

    def save(self):
        cfg = gmconfig.load()
        for name, v in self.rows.items():
            m = gmconfig.find(cfg, name)
            if not m:
                continue
            m["enabled"] = v["watch"].get()
            m["check_quickpod"] = v["quickpod"].get()
            m["check_nvidia"] = v["nvidia"].get()
            m["scope"] = "public" if v["scope"].get() == "public" else "local"
            via = (v["via"].get() or "").strip()
            if via and not gmconfig.resolve_hop(cfg, via):
                gmtheme.error(
                    "Infra Monitor",
                    "%s: relay %r is not a monitored machine or a relay host.\n\n"
                    "Nothing was saved." % (name, via), parent=self)
                return
            if via == name:
                gmtheme.error(
                    "Infra Monitor",
                    "%s cannot relay through itself — that would prove nothing "
                    "about it.\n\nNothing was saved." % name, parent=self)
                return
            if via:
                m["via"] = via
            else:
                m.pop("via", None)
        peers, bad = [], []
        for p in self.peers.get().replace(";", ",").split(","):
            p = p.strip()
            if not p:
                continue
            try:                      # validate here, not at check time - a
                import ipaddress      # typo must not silently disable the rule
                ipaddress.ip_network(p, strict=False)
                peers.append(p)
            except ValueError:
                bad.append(p)
        if bad:
            gmtheme.error("Infra Monitor", "Not valid IPs/CIDRs:\n  " +
                                 "\n  ".join(bad) + "\n\nNothing was saved.",
                                 parent=self)
            return
        cfg["allowed_peers"] = peers
        jump = (self.jump.get() or "").strip() if hasattr(self, "jump") else ""
        if jump and not gmconfig.resolve_hop(cfg, jump):
            gmtheme.error(
                "Infra Monitor",
                "Default relay %r is not a monitored machine or a relay "
                "host.\n\nAdd it under \"Relay hosts...\", or leave the field "
                "empty for direct connections.\n\nNothing was saved." % jump,
                parent=self)
            return
        cfg["jump_host"] = jump
        gmconfig.save(cfg)
        log.info("settings saved by user")
        self.destroy()
        self.app.poll_now()


class App:
    def __init__(self):
        self.cfg = gmconfig.load()
        # Every piece of state the Dashboard reads is established BEFORE it is
        # constructed. Its tabs render themselves on the way up - the Stealth
        # tab sizes its sweep from the last local snapshot - so a field
        # assigned after this line is a field that does not exist yet when a
        # widget asks for it, and the app dies at launch rather than at use.
        self.snap = None
        self.lsnap = None
        self.problem_log = []   # newest-first, for the Problems tab
        self.stop = threading.Event()
        self.root = tk.Tk()
        self.root.withdraw()
        # iconphoto(True, ...) makes this the DEFAULT for every window created
        # afterwards, so dialogs stop inventing their own (owner, 2026-08-17:
        # "a separate icon appears in task bar for each dialog it should be all
        # unified"). WM_CLASS is already handled once in aura.py, which patches
        # tk.Tk.__init__ — the two together are what lets Plasma group the
        # windows under the pinned launcher.
        try:
            self._win_icon = tk.PhotoImage(
                file=gmpaths.asset("infra-monitor.png"))
            self.root.iconphoto(True, self._win_icon)
        except Exception:
            self._win_icon = None      # never fatal: an icon is cosmetic
        # Aura goes on BEFORE the first widget exists. tk fixes a widget's
        # colours when it is created, so a theme applied afterwards would only
        # reach whatever is built next - which is how half-dark windows happen.
        gmtheme.apply(self.root, gmtheme.load_pref(self.cfg))
        self.dash = Dashboard(self.root, self)
        self.dash.withdraw()
        self.icon = pystray.Icon(
            "InfraMonitor", make_icon_image(GREY), "Infra Monitor - starting",
            menu=pystray.Menu(
                pystray.MenuItem("Dashboard", self.show_dash, default=True),
                pystray.MenuItem("Refresh now", lambda *_: self.poll_now()),
                pystray.MenuItem("Settings...", self.show_settings),
                pystray.MenuItem("Trust this network", self.trust_network),
                pystray.MenuItem("Forget networks", self.forget_networks),
                # Appearance follows the OS by default and cycles
                # System -> Dark -> Light, the same control the dashboard
                # header carries.
                pystray.MenuItem(lambda _i: gmtheme.label(), self.cycle_theme),
                # A checked menu item, not a hidden setting: the app registers
                # itself at logon on first run, and anything that arranges to
                # start itself must show an obvious way to stop it.
                pystray.MenuItem("Start automatically at login", self.toggle_autostart,
                                 checked=lambda _i: self.cfg.get("autostart", True)),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Quit", self.quit)))
        self._wake = threading.Event()
        # The local scan gets its own wake event and its own thread. It costs
        # no network, it must keep running when the gate is closed and the
        # fleet is not being polled at all, and a connection can open and shut
        # well inside one two-minute fleet cycle. Sharing the fleet poller
        # would tie a local rescan to an SSH round trip to thirteen machines.
        self._wake_local = threading.Event()
        self.q = queue.Queue()

    # ---- tray callbacks arrive on pystray's thread; marshal to Tk
    def show_dash(self, *_):
        self.root.after(0, self._show_dash)

    def _show_dash(self):
        self.dash.deiconify()
        self.dash.lift()
        self.dash.focus_force()

    def trust_network(self, *_a):
        """Add the current network to the trusted list, from the UI.

        The fleet is only probed on networks the user has trusted (see
        gmcheck.gate_ok): private addresses belong to whoever owns the LAN we are
        attached to, so probing them anywhere else is wrong. First run adopts the
        install network automatically; this is how the second, third and VPN
        networks get added — without a terminal (field ask 2026-08-17).
        """
        try:
            _cfg, mac, label, added = gmcheck.learn_gate()
        except RuntimeError as e:
            gmnotify.toast("Cannot trust this network", [str(e)])
            return
        gmnotify.toast("Network trusted" if added else "Already trusted",
                       ["%s (gateway %s)" % (label, mac),
                        "The fleet will be checked here."])
        self.poll_now()

    def forget_networks(self, *_a):
        """Drop every trusted network, so nothing local is probed until one is
        trusted again. The counterpart to Trust this network — the user can undo
        what they granted."""
        cfg = gmconfig.load()
        n = len(cfg.get("gate_fingerprints") or [])
        cfg["gate_fingerprints"] = []
        # do not silently re-adopt on the next check, or Forget would do nothing
        cfg["gate_adopt_disabled"] = True
        gmconfig.save(cfg)
        gmnotify.toast("Networks forgotten",
                       ["Removed %d trusted network(s)." % n,
                        "Local machines will not be checked until you use "
                        "Trust this network."])
        self.poll_now()

    def show_settings(self, *_):
        self.root.after(0, lambda: Settings(self.root, self))

    # ---- appearance
    def cycle_theme(self, *_):
        """System -> Dark -> Light. Saved, so the choice survives a restart."""
        self.root.after(0, lambda: self._cycle_theme())

    def _cycle_theme(self):
        pref = gmtheme.next_pref()
        cfg = gmconfig.load()
        cfg[gmtheme.PREF_KEY] = pref
        try:
            gmconfig.save(cfg)
        except OSError as ex:
            # Not fatal: the flip still applies to this session. A monitor that
            # refused to change appearance because a settings file was
            # read-only would be the wrong priority.
            log.error("could not save theme setting: %s", ex)
        self.cfg = cfg
        log.info("theme preference set to %s", pref)
        self._retheme(pref)
        try:
            self.icon.update_menu()
        except Exception:
            pass

    def _system_theme(self, mode):
        """The OS flipped Aura Dark/Light - follow it, unless overridden."""
        if gmtheme.pref() != "system" or mode == TH.mode:
            return
        log.info("OS appearance changed to %s - re-theming", mode)
        self._retheme()

    def _retheme(self, pref=None):
        """Rebuild the windows in the resolved theme.

        tk binds a colour at widget-construction time, so a flip means building
        the dashboard again rather than repainting a hundred and fifty widgets
        in place and missing some. Every panel already renders itself from a
        stored snapshot, so nothing is lost but the scroll position - and the
        alternative, a relogin-style "restart to apply", is exactly the
        behaviour the design system forbids."""
        gmtheme.apply(self.root, pref)
        old = self.dash
        geom, visible, ssnap = None, False, None
        try:
            geom = old.geometry()
            visible = old.state() == "normal"
            ssnap = old.ssnap
        except Exception:
            pass
        try:
            old.destroy()
        except Exception:
            pass
        self.dash = Dashboard(self.root, self)
        if geom:
            self.dash.geometry(geom)
        if not visible:
            self.dash.withdraw()
        self.dash.render(self.snap)
        if self.lsnap:
            self.dash.render_local(self.lsnap)
            self.dash.render_conns(self.lsnap)
        if ssnap:
            self.dash.render_stealth(ssnap)
        self.dash.render_problems(self.problem_log)

    def poll_now(self, *_):
        self._wake.set()

    def scan_local_now(self, *_):
        self._wake_local.set()

    def toggle_autostart(self, *_):
        """Flip the setting, then make the registry follow it.

        The setting is written FIRST and is what `sync` reads, so switching
        this off survives the next launch instead of being re-registered by
        the startup path."""
        cfg = gmconfig.load()
        cfg["autostart"] = not cfg.get("autostart", True)
        try:
            gmconfig.save(cfg)
        except OSError as ex:
            log.error("could not save autostart setting: %s", ex)
            return
        self.cfg = cfg
        note = gmautostart.sync(cfg)
        log.info("autostart set to %s%s", cfg["autostart"],
                 f" ({note})" if note else "")
        try:
            self.icon.update_menu()
        except Exception:
            pass

    def scan_local_elevated(self, *_):
        """One elevated scan, off the Tk thread.

        The UAC prompt blocks until the user answers it, and answering it can
        take as long as they like - on the Tk thread that is a frozen
        dashboard, which looks exactly like the crash this app is supposed to
        notice."""
        def work():
            log.info("local: elevated scan requested")
            try:
                snap = gmlocal.scan_elevated()
            except Exception as ex:
                log.exception("elevated scan failed")
                snap = {"ok": False, "rows": [], "counts": {}, "admin": False,
                        "checked_at": time.time(), "elapsed": 0.0,
                        "deferred": 0, "host": "",
                        "error": f"{type(ex).__name__}: {ex}"}
            self.q.put(("local", snap))
        threading.Thread(target=work, daemon=True, name="elevated").start()

    def run_stealth(self, target, vantage=None, mode=None):
        """One stealth sweep, off the Tk thread.

        Its own thread rather than the fleet poller's: it can take the better
        part of a minute against a fully stealthed host, it is triggered by a
        person rather than a timer, and hanging it off the poll cycle would
        mean a button that does nothing for two minutes.

        The last local snapshot is handed in rather than re-scanned, so the
        ports probed are exactly the ones the This PC tab is showing as
        listening. Two scans could disagree, and then a port that vanished
        between them would be reported stealth when it was simply never
        opened."""
        def work():
            log.info("stealth: %s sweep of %s from %s",
                     mode or gmstealth.DEFAULT_MODE, target, vantage or "auto")
            try:
                snap = gmstealth.scan(target, cfg=self.cfg, vantage=vantage,
                                      lsnap=self.lsnap,
                                      mode=mode or gmstealth.DEFAULT_MODE)
                if snap.get("ok"):
                    c = snap["counts"]
                    log.info("stealth: %s from %s (%s) -> %s (%d open, "
                             "%d closed, %d stealth, %d untested) in %.1fs",
                             snap["ip"], snap["vantage"], snap["mode"],
                             snap["verdict"], c["open"], c["closed"],
                             c["stealth"], c["untested"], snap["elapsed"])
                    for _k, sev, text in gmstealth.findings(snap):
                        log.info("STEALTH %s %s", sev, text[:160])
                        self.problem_log.insert(0, {
                            "when": time.strftime("%m-%d %H:%M:%S"),
                            "machine": snap["ip"],
                            "kind": "exposed" if sev in ("CRIT", "HIGH")
                                    else "notice",
                            "text": text})
                    del self.problem_log[500:]
                else:
                    log.warning("stealth: %s failed: %s", target,
                                snap.get("error"))
            except Exception as ex:
                log.exception("stealth sweep crashed")
                # The tab is waiting on a result and has its button disabled.
                # A crash that produced nothing would leave it disabled
                # forever, so a failure is still a result.
                snap = {"ok": False, "rows": [], "counts": {}, "target": target,
                        "ip": "", "vantage": vantage or "auto",
                        "mode": mode or gmstealth.DEFAULT_MODE,
                        "vantage_kind": "", "verdict": "", "verdict_note": "",
                        "caveat": "", "ping": "", "arp": "", "note": "",
                        "checked_at": time.time(), "elapsed": 0.0,
                        "error": f"{type(ex).__name__}: {ex}"[:300]}
            self.q.put(("stealth", snap))
        threading.Thread(target=work, daemon=True, name="stealth").start()

    def quit(self, *_):
        self.stop.set()
        self._wake.set()
        self._wake_local.set()
        try:
            self.icon.stop()
        except Exception:
            pass
        self.root.after(0, self.root.quit)

    # ---- the only thread that touches the network
    def poller(self):
        while not self.stop.is_set():
            try:
                self.cfg = gmconfig.load()      # picks up add/remove live
                snap = gmcheck.check_all(self.cfg)
                self.snap = snap
                bad = [r["name"] for r in snap["machines"]
                       if r.get("checked") and (not r["up"] or r["problems"])]
                log.info("poll ok in %.1fs, gate=%s, %d need attention: %s",
                         snap["elapsed"], snap["gate_ok"], len(bad), ",".join(bad))
                try:
                    for n, k, t in gmnotify.notify(snap):
                        log.info("ALERT %s %s: %s", n, k, t[:120])
                        # Newest first, capped: this is a session log for the
                        # Problems tab, not an audit trail - inframonitor.log keeps
                        # the permanent record.
                        self.problem_log.insert(0, {
                            "when": time.strftime("%m-%d %H:%M:%S"),
                            "machine": n, "kind": k, "text": t})
                    del self.problem_log[500:]
                except Exception:
                    log.exception("notify failed")
                # Hand the result to Tk through a queue. Calling root.after()
                # from a worker thread reaches into Tcl from the wrong thread;
                # it appears to work and then wedges the UI days later.
                self.q.put(("fleet", snap))
            except Exception:
                log.exception("poll failed")
            # Interruptible sleep so "Refresh now" and Quit are instant.
            self._wake.wait(max(30, int(self.cfg.get("poll_seconds", 120))))
            self._wake.clear()

    # ---- the local scan: no network, so it runs whatever the gate says
    def local_poller(self):
        while not self.stop.is_set():
            lw = (self.cfg or {}).get("local_watch", {})
            if lw.get("enabled", True):
                try:
                    lsnap = gmlocal.scan(self.cfg)
                    self.lsnap = lsnap
                    if lsnap.get("ok"):
                        c = lsnap["counts"]
                        log.info("local scan ok in %.1fs: %d sockets, %d exposed, "
                                 "%d unknown, %d unverified", lsnap["elapsed"],
                                 c["total"], c["exposed"], c["unknown"],
                                 c["unverified"])
                        try:
                            for _k, sev, text in gmnotify.notify_local(
                                    lsnap, self.cfg):
                                log.info("LOCAL ALERT %s %s", sev, text[:150])
                                self.problem_log.insert(0, {
                                    "when": time.strftime("%m-%d %H:%M:%S"),
                                    "machine": "this-pc",
                                    "kind": "unknown" if sev in ("CRIT", "HIGH")
                                            else "notice",
                                    "text": text})
                            del self.problem_log[500:]
                        except Exception:
                            log.exception("local notify failed")
                    else:
                        log.warning("local scan failed: %s", lsnap.get("error"))
                    self.q.put(("local", lsnap))
                except Exception:
                    log.exception("local scan crashed")
            self._wake_local.wait(max(20, int(lw.get("poll_seconds", 60) or 60)))
            self._wake_local.clear()

    def drain(self):
        """Runs on the Tk thread; the only place widgets are touched."""
        try:
            while True:
                kind, snap = self.q.get_nowait()
                if kind == "fleet":
                    self._apply(snap)
                elif kind == "stealth":
                    self.dash.render_stealth(snap)
                    self.dash.render_problems(self.problem_log)
                elif kind == "theme":
                    self._system_theme(snap)
                else:
                    self._apply_local(snap)
        except queue.Empty:
            pass
        except Exception:
            log.exception("render failed")
        if not self.stop.is_set():
            self.root.after(500, self.drain)

    def _local_alarm(self):
        """(colour, badge count) contributed by this machine.

        An unidentified process someone is already talking to is at least as
        serious as a fleet machine being down, so it gets the same red - the
        tray colour is documented as the worst state anywhere, and quietly
        exempting the local box would make that untrue."""
        c = (self.lsnap or {}).get("counts") or {}
        if not self.lsnap or not self.lsnap.get("ok"):
            return None, 0
        n = c.get("exposed", 0)
        if any(r["sev"] in ("CRIT", "HIGH") and r["verdict"] == "unknown"
               for r in self.lsnap.get("rows", [])):
            return RED, n
        return (AMBER if n else None), n

    def _repaint_icon(self):
        bad = sum(1 for r in (self.snap or {}).get("machines", [])
                  if r.get("checked") and (not r["up"] or r["problems"]))
        col = worst_colour(self.snap)
        lcol, lbad = self._local_alarm()
        if lcol == RED or col == RED:
            col = RED
        elif lcol == AMBER and col in (GREEN, GREY):
            col = AMBER
        total = bad + lbad
        # "all healthy" with nothing configured is the one message this must
        # never show - it is the difference between a monitor that is watching
        # and one that is not.
        if self.snap is not None and not self.snap.get("machines"):
            fleet = "Infra Monitor - NO MACHINES CONFIGURED"
            col = RED if col in (GREEN, GREY) else col
        elif bad:
            fleet = f"Infra Monitor - {bad} need attention"
        else:
            fleet = "Infra Monitor - all healthy"
        try:
            self.icon.icon = make_icon_image(col, total)
            self.icon.title = fleet + (f"; {lbad} unidentified on this PC"
                                       if lbad else "")
        except Exception:
            pass

    def _apply(self, snap):
        self.snap = snap
        self._repaint_icon()
        self.dash.render(snap)              # kept current even while hidden

    def _apply_local(self, lsnap):
        self.lsnap = lsnap
        self._repaint_icon()
        # Both local tabs read the same snapshot, so they can never disagree
        # about what is connected - two scans would.
        self.dash.render_local(lsnap)
        self.dash.render_conns(lsnap)
        self.dash.render_problems(self.problem_log)

    def run(self):
        log.info("=== Infra Monitor starting (pid %d, %s) ===", os.getpid(),
                 "frozen" if gmpaths.frozen() else "source")
        log.info("app dir %s, config %s", gmpaths.APP_DIR, gmconfig.CONFIG_PATH)
        if not gmconfig.exists():
            log.error("machines.json NOT FOUND at %s - nothing will be "
                      "monitored until it is imported or created",
                      gmconfig.CONFIG_PATH)
        # Register at logon on the way up. sync() is driven by the `autostart`
        # setting, so this both installs it on a first run and REMOVES a stale
        # entry if the setting was turned off - and rewrites the path when the
        # exe has moved, which otherwise fails silently every morning.
        try:
            note = gmautostart.sync(self.cfg)
            if note:
                log.info("autostart: %s", note)
        except Exception:
            # Never fatal. Failing to start because a convenience setting could
            # not be written would be the wrong priority for a monitor.
            log.exception("autostart sync failed")
        # The OS appearance signal arrives on darkdetect's own thread, so it
        # goes through the same queue every other worker uses rather than
        # reaching into Tcl from the wrong thread.
        gmtheme.watch_system(lambda mode: self.q.put(("theme", mode)))
        threading.Thread(target=self.icon.run, daemon=True,
                         name="tray").start()
        threading.Thread(target=self.poller, daemon=True, name="poller").start()
        threading.Thread(target=self.local_poller, daemon=True,
                         name="local").start()
        self.root.after(500, self.drain)
        self.root.mainloop()
        log.info("=== Infra Monitor stopped ===")


QUIET = False


def _report(title, text, ok=True):
    """Say something to whoever started us.

    A --windowed build has no console, so a print() into the void would make a
    failed import look exactly like a successful one. When there is nowhere to
    print, put it in a dialog instead.

    But a dialog BLOCKS until somebody clicks it, and these verbs are meant to
    be scriptable - an installer calling --import-config would hang forever on
    a message box nobody is watching. `--quiet` suppresses the dialog, and the
    outcome goes to inframonitor.log either way, so an unattended run still leaves
    evidence of what happened."""
    (log.info if ok else log.error)("%s: %s", title, text.replace("\n", " "))
    if QUIET:
        return
    if sys.stdout is not None and sys.stdout.isatty():
        print(text)
        return
    try:
        r = tk.Tk(); r.withdraw()
        # even the no-session path gets the themed dialog: this is the one the
        # user sees after a CLI-ish action, so a stock X11 box here would be the
        # only unstyled surface left in the app
        try:
            gmtheme.apply(r)
        except Exception:
            pass
        (gmtheme.notice if ok else gmtheme.error)(title, text, r)
        r.destroy()
    except Exception:
        pass


def _arg_after(argv, flag):
    i = argv.index(flag)
    return argv[i + 1] if len(argv) > i + 1 else None


def main(argv=None):
    global QUIET
    argv = sys.argv[1:] if argv is None else argv
    QUIET = "--quiet" in argv

    # Config moves between machines through the EXE, not through a Python
    # script: the machine being deployed to is precisely the one with no
    # Python on it.
    if "--export-config" in argv:
        import gmexport
        dest = _arg_after(argv, "--export-config")
        if not dest:
            _report("Infra Monitor", "--export-config needs a file path", False)
            return 2
        try:
            b = gmexport.export_config(dest, "--with-local" in argv,
                                       "--keep-bootstrapped" in argv)
        except Exception as ex:
            _report("Infra Monitor - export failed", str(ex), False)
            return 1
        _report("Infra Monitor", f"Exported {len(b['config'].get('machines', []))} "
                          f"machine(s) to\n{dest}\n\n{b['notes']}")
        return 0

    # Deliberately available without starting the app, so the uninstall path
    # works from a script and does not depend on the tray being reachable.
    if "--register-autostart" in argv or "--unregister-autostart" in argv:
        on = "--register-autostart" in argv
        cfg = gmconfig.load()
        cfg["autostart"] = on
        try:
            gmconfig.save(cfg)
        except OSError:
            pass
        note = gmautostart.sync(cfg) or ("already registered" if on
                                         else "was not registered")
        _report("Infra Monitor", f"Start automatically at login: {'ON' if on else 'OFF'}\n{note}")
        return 0

    # Teach the gate this network. Run it once in each house; from then on
    # "am I home?" is answered from the default gateway's MAC with no network
    # call at all. Available without starting the tray on purpose - the honest
    # time to run it is right after plugging in somewhere new.
    if "--learn-gate" in argv:
        name = _arg_after(argv, "--learn-gate")
        if name and name.startswith("-"):
            name = None
        try:
            _cfg, mac, label, added = gmcheck.learn_gate(name=name)
        except Exception as ex:
            _report("Infra Monitor - could not learn this network", str(ex), False)
            return 1
        _report("Infra Monitor",
                (f"Learned {label}\ngateway {mac}\n\n"
                 "Local machines will be polled whenever this gateway is the "
                 "one in front of you." ) if added else
                (f"Already known as {label}\ngateway {mac}\n\nNothing changed."))
        return 0

    if "--import-config" in argv:
        import gmexport
        src = _arg_after(argv, "--import-config")
        if not src:
            _report("Infra Monitor", "--import-config needs a file path", False)
            return 2
        try:
            summary, backup = gmexport.import_config(src, "--merge" in argv)
        except Exception as ex:
            _report("Infra Monitor - import failed", str(ex), False)
            return 1
        _report("Infra Monitor",
                f"Imported: {summary['machines']} machine(s) configured "
                f"({summary['added']} added, {summary['updated']} updated).\n\n"
                + (f"Previous config kept as\n{os.path.basename(backup)}\n\n"
                   if backup else "")
                + "Key auth is not verified on this machine yet - run "
                  "bootstrap_ssh before trusting the first poll.")
        return 0
    # The frozen build is ONE exe wearing two hats. `--local-scan` is how the
    # elevated rescan re-enters: PowerShell relaunches this same exe through
    # UAC, it scans, writes JSON where it was told, and exits without ever
    # building a window. Without this the elevated button would raise a UAC
    # prompt and then start a second tray icon.
    if "--local-scan" in argv:
        out = (argv[argv.index("--out") + 1]
               if "--out" in argv and len(argv) > argv.index("--out") + 1
               else os.path.join(gmpaths.STATE_DIR, "elevated_scan.tmp"))
        snap = gmlocal.scan()
        with open(out, "w", encoding="utf-8") as f:
            json.dump(snap, f)
        return 0 if snap.get("ok") else 1
    App().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())







