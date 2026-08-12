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

# pythonw.exe has no console: anything written to stderr is discarded, so a
# crashed poller thread leaves the dashboard frozen on its last snapshot with
# no clue why. That happened. Everything goes to a file instead. A windowed
# PyInstaller build has exactly the same problem, which is why the log lives
# beside the exe rather than inside the temporary unpack directory.
LOG_PATH = os.path.join(gmpaths.APP_DIR, "inframonitor.log")
logging.basicConfig(
    filename=LOG_PATH, level=logging.INFO, filemode="a",
    format="%(asctime)s %(levelname)-7s %(threadName)-12s %(message)s")
log = logging.getLogger("inframonitor")

import pystray
from PIL import Image, ImageDraw

# Reserved STATUS palette (never themed, never reused as series colors).
GOOD, WARNING, SERIOUS, CRITICAL = "#0ca30c", "#fab219", "#ec835a", "#d03b3b"
GREY = "#9aa0a6"
INK, INK_MUTED = "#1a1a19", "#767676"
GREEN, AMBER, RED = GOOD, WARNING, CRITICAL     # names used by the tray icon

# On a light surface `warning` and `serious` are below 3:1 BY DESIGN. The
# mitigation is that every status is paired with a word, so severity is never
# carried by hue alone - which also makes the dashboard readable for the ~8% of
# men with a colour vision deficiency, and in a screenshot printed in mono.
def severity(pct):
    if pct >= 95:
        return CRITICAL, "CRIT"
    if pct >= 85:
        return SERIOUS, "HIGH"
    if pct >= 70:
        return WARNING, "WARN"
    return GOOD, "OK"


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
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((6, 6, 58, 58), fill=colour)
    if badge:
        d.ellipse((34, 2, 62, 30), fill="#ffffff")
        d.text((41 if badge < 10 else 37, 8), str(min(badge, 99)), fill=colour)
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
                  style="arc", width=5, outline="#e9e9e9")
    if pct > 0:
        cv.create_arc(x - r, y - r, x + r, y + r, start=225,
                      extent=-270 * pct / 100.0, style="arc", width=5,
                      outline=col)
    cv.create_text(x, y - 3, text=f"{int(pct)}", fill=INK,
                   font=("Segoe UI", 10, "bold"))
    cv.create_text(x, y + 9, text=label, fill=INK_MUTED, font=("Segoe UI", 6))
    # Severity word stays even at this size: it is the non-colour channel, so
    # dropping it to save pixels would leave hue carrying the meaning alone.
    cv.create_text(x, y + r + 6, text=word, fill=INK,
                   font=("Segoe UI", 6, "bold"))
    if sub:
        cv.create_text(x, y + r + 15, text=sub, fill=INK_MUTED,
                       font=("Segoe UI", 6))


# ------------------------------------------------------------- ranked bars
# ONE hue, not a categorical palette. Every bar in these charts measures the
# same thing - how many connections - so colour carries no identity here and
# giving each bar its own would imply a difference that does not exist. It is
# also deliberately NOT a status colour: the reserved palette above means
# good/warning/serious/critical and must never be borrowed to mean "series".
# Checked against this app's white surface: 4.42:1 contrast, and dE >= 15 from
# all four status hues and from the muted ink, so it cannot impersonate one.
SERIES = "#2a78d6"
# The folded-up tail. A lighter step of the SAME ramp, so it reads as a
# leftover rather than a ninth competitor - it is routinely longer than the
# top-ranked bar, and in full series colour that makes a descending chart look
# broken. Step 250 is the lightest the ramp allows against a light surface
# while a bar still reads as a bar (2.06:1); its value is directly labelled.
SERIES_RESIDUAL = "#86b6ef"
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
    cv.create_text(x, y, text=title, anchor="nw", fill=INK,
                   font=("Segoe UI", 8, "bold"))
    top = y + 18
    if not items:
        cv.create_text(x, top + 4, text="nothing to show", anchor="nw",
                       fill=INK_MUTED, font=("Segoe UI", 8))
        return
    valw = 34
    x0 = x + gutter
    span = max(24, width - gutter - valw)
    hi = max(v for _l, v, _o in items) or 1
    for i, (label, val, residual) in enumerate(items):
        cy = top + i * BAR_PITCH
        # Truncated to the gutter so a long path can never run under the bars.
        txt = label if len(label) <= 24 else label[:23] + "…"
        cv.create_text(x, cy + BAR_H / 2, text=txt, anchor="w", fill=INK_MUTED,
                       font=("Segoe UI", 8))
        w = max(2, int(span * val / hi))
        _rbar(cv, x0, cy, x0 + w, cy + BAR_H, BAR_R,
              SERIES_RESIDUAL if residual else SERIES)
        # Value at the tip, always OUTSIDE the bar, so it can never be clipped
        # by its own mark however short the bar is.
        cv.create_text(x0 + w + 6, cy + BAR_H / 2, text=str(val), anchor="w",
                       fill=INK, font=("Segoe UI", 8))


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
            bg="#ffffe0", relief="solid", borderwidth=1,
            font=("Segoe UI", 8), padx=6, pady=4)
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
                 readonlybackground=kw.pop("bg", "white"),
                 fg=kw.pop("fg", INK), bd=0, highlightthickness=0,
                 font=kw.pop("font", ("Segoe UI", 8)),
                 width=width or max(8, min(len(text) + 1, 120)))
    return e


class Dashboard(tk.Toplevel):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.title("Infra Monitor")
        self.geometry("1400x740")
        self.configure(bg="white")
        self.protocol("WM_DELETE_WINDOW", self.hide)

        top = tk.Frame(self, bg="white"); top.pack(fill="x", padx=8, pady=(5, 2))
        self.status = tk.Label(top, text="", bg="white", anchor="w",
                               font=("Segoe UI", 9))
        self.status.pack(side="left")
        tk.Button(top, text="Refresh now", command=self.app.poll_now)\
            .pack(side="right")

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
        outer = tk.Frame(self.nb, bg="white")
        self.nb.add(outer, text="Problems")
        self.problems = tk.Text(outer, wrap="none", bg="white", fg=INK,
                                font=("Consolas", 8), relief="flat",
                                padx=6, pady=4)
        ys = ttk.Scrollbar(outer, orient="vertical", command=self.problems.yview)
        xs = ttk.Scrollbar(outer, orient="horizontal", command=self.problems.xview)
        self.problems.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y"); xs.pack(side="bottom", fill="x")
        self.problems.pack(side="left", fill="both", expand=True)
        for tag, col in (("crit", CRITICAL), ("warn", WARNING),
                         ("ok", GOOD), ("dim", INK_MUTED)):
            self.problems.tag_configure(tag, foreground=col)

    # ------------------------------------------------------------- this PC
    SEV_TAG = {"CRIT": CRITICAL, "HIGH": SERIOUS, "WARN": WARNING,
               "INFO": INK_MUTED, "OK": GOOD}
    LCOLS = (("sev", "SEV", 46), ("dir", "DIR", 58), ("proto", "P", 36),
             ("local", "LOCAL", 150), ("remote", "REMOTE", 160),
             ("peer", "PEER", 110), ("proc", "PROCESS", 150),
             ("pid", "PID", 52), ("acct", "SERVICE / PUBLISHER", 210),
             ("why", "WHY IT IS LISTED", 420))

    def _make_thispc_tab(self):
        """Connections to the machine the monitor itself runs on.

        A Treeview rather than the stacked cards the fleet tabs use: this is a
        table of a hundred near-identical rows that wants sorting and
        selection, not thirteen objects each with its own dials. The detail
        pane underneath carries the copyable text, which is what a Treeview
        cannot give you and what ends up pasted into a ticket."""
        outer = tk.Frame(self.nb, bg="white")
        self.nb.add(outer, text="This PC")
        self.local_tab = outer
        self.lrows, self.lsnap = {}, None

        self.lbanner = tk.Label(outer, bg="white", fg=INK_MUTED, anchor="w",
                                font=("Segoe UI", 8), justify="left")
        self.lbanner.pack(fill="x", padx=10, pady=(6, 0))
        self.ltiles = tk.Frame(outer, bg="white")
        self.ltiles.pack(fill="x", padx=8, pady=(4, 2))

        ctl = tk.Frame(outer, bg="white"); ctl.pack(fill="x", padx=10, pady=(0, 4))
        self.lfilter = {}
        for key, label in (("IN", "inbound"), ("LISTEN", "listening"),
                           ("OUT", "outbound")):
            v = tk.BooleanVar(value=True)
            self.lfilter[key] = v
            tk.Checkbutton(ctl, text=label, variable=v, bg="white", fg=INK,
                           font=("Segoe UI", 8), command=self._rerender_local)\
                .pack(side="left")
        self.lshowok = tk.BooleanVar(value=False)
        tk.Checkbutton(ctl, text="show accounted-for", variable=self.lshowok,
                       bg="white", fg=INK, font=("Segoe UI", 8),
                       command=self._rerender_local).pack(side="left", padx=(12, 0))
        tk.Button(ctl, text="Rescan", command=self.app.scan_local_now)\
            .pack(side="right")
        tk.Button(ctl, text="Scan as administrator",
                  command=self.app.scan_local_elevated).pack(side="right", padx=6)
        tk.Button(ctl, text="Trust this program",
                  command=self._trust_selected).pack(side="right")
        tk.Button(ctl, text="Copy all", command=self._copy_local)\
            .pack(side="right", padx=6)

        wrap = tk.Frame(outer, bg="white")
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
        for tag, col in self.SEV_TAG.items():
            self.ltree.tag_configure(tag, foreground=col)
        self.ltree.bind("<<TreeviewSelect>>", self._show_local_detail)
        self.lsort = ("sev", False)

        self.ldetail = tk.Text(outer, height=8, wrap="word", bg="#fbfbfb",
                               fg=INK, font=("Consolas", 8), relief="flat",
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
                fg=CRITICAL,
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
                fg=(INK_MUTED if lsnap.get("admin") else WARNING),
                text="   ".join(bits))

        for w in self.ltiles.winfo_children():
            w.destroy()
        # (label, value, note, colour when NON-zero). The last field matters:
        # zero unknowns is good news and zero accounted-for is not, so the tile
        # colour cannot be derived from the count alone.
        tiles = [
            ("EXPOSED", c.get("exposed", 0),
             "unidentified, reachable from off this PC", CRITICAL),
            ("INBOUND", c.get("unknown_in", 0), "unidentified sessions IN", CRITICAL),
            ("OUTBOUND", c.get("unknown_out", 0), "unidentified calls OUT", WARNING),
            ("UNVERIFIED", c.get("unverified", 0), "process not identifiable", WARNING),
            ("FOR REVIEW", c.get("review", 0), "signed, but not a service", INK_MUTED),
            ("ACCOUNTED", c.get("accounted", 0), "system services + trusted", GOOD),
        ]
        for label, val, note, hot in tiles:
            col = hot if (val or label in ("FOR REVIEW", "ACCOUNTED")) else GOOD
            t = tk.Frame(self.ltiles, bg="white", highlightthickness=1,
                         highlightbackground="#e3e3e3")
            t.pack(side="left", padx=(0, 8))
            tk.Frame(t, bg=col, width=5).pack(side="left", fill="y")
            inner = tk.Frame(t, bg="white")
            inner.pack(side="left", padx=10, pady=5)
            tk.Label(inner, text=label, bg="white", fg=INK_MUTED,
                     font=("Segoe UI", 7)).pack(anchor="w")
            tk.Label(inner, text=str(val), bg="white", fg=INK,
                     font=("Segoe UI", 14, "bold")).pack(anchor="w")
            tk.Label(inner, text=note, bg="white", fg=INK_MUTED,
                     font=("Segoe UI", 7)).pack(anchor="w")

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
            messagebox.showinfo("Infra Monitor", "Select a row first.", parent=self)
            return
        if not r["path"]:
            messagebox.showwarning(
                "Infra Monitor", "This process has no readable image path, so there "
                "is nothing to trust that could not be impersonated.\n\n"
                "Run 'Scan as administrator' to identify it first.", parent=self)
            return
        if not messagebox.askyesno(
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
    CCOLS = (("dir", "DIR", 52), ("proto", "P", 34), ("proc", "PROGRAM", 140),
             ("pid", "PID", 52), ("remote", "REMOTE", 155),
             ("host", "RESOLVED", 190), ("port", "SERVICE", 105),
             ("peer", "PEER", 90), ("age", "AGE", 52),
             ("verdict", "ACCOUNTED BY", 260))

    def _make_conns_tab(self):
        """Every established session whose owner is not a system service.

        The This PC tab answers "what is unaccounted for". This one answers
        "what is my machine actually talking to right now" - a different
        question, and one whose answer is mostly benign and therefore belongs
        somewhere that is not an alarm panel."""
        outer = tk.Frame(self.nb, bg="white")
        self.nb.add(outer, text="Connections")
        self.conns_tab = outer
        self.crows = {}

        self.cbanner = tk.Label(outer, bg="white", fg=INK_MUTED, anchor="w",
                                font=("Segoe UI", 8))
        self.cbanner.pack(fill="x", padx=10, pady=(6, 0))
        self.ctiles = tk.Frame(outer, bg="white")
        self.ctiles.pack(fill="x", padx=8, pady=(4, 2))
        self.ccharts = tk.Canvas(outer, bg="white", highlightthickness=0,
                                 height=190)
        self.ccharts.pack(fill="x", padx=10)
        self.ccharts.bind("<Configure>", lambda _e: self._draw_charts())

        ctl = tk.Frame(outer, bg="white"); ctl.pack(fill="x", padx=10, pady=(2, 4))
        tk.Label(ctl, text="peers:", bg="white", fg=INK_MUTED,
                 font=("Segoe UI", 8)).pack(side="left")
        self.cfilter = {}
        for key, label in (("public", "public"), ("lan", "LAN"),
                           ("loopback", "loopback")):
            v = tk.BooleanVar(value=True)
            self.cfilter[key] = v
            tk.Checkbutton(ctl, text=label, variable=v, bg="white", fg=INK,
                           font=("Segoe UI", 8), command=self._rerender_conns)\
                .pack(side="left")
        self.chide_trusted = tk.BooleanVar(value=False)
        tk.Checkbutton(ctl, text="hide trusted", variable=self.chide_trusted,
                       bg="white", fg=INK, font=("Segoe UI", 8),
                       command=self._rerender_conns).pack(side="left", padx=(12, 0))
        tk.Button(ctl, text="Rescan", command=self.app.scan_local_now)\
            .pack(side="right")
        tk.Button(ctl, text="Copy all", command=self._copy_conns)\
            .pack(side="right", padx=6)

        wrap = tk.Frame(outer, bg="white")
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
        for tag, col in self.SEV_TAG.items():
            self.ctree.tag_configure(tag, foreground=col)
        self.ctree.bind("<<TreeviewSelect>>", self._show_conn_detail)
        self.csort = ("age", False)

        self.cdetail = tk.Text(outer, height=6, wrap="word", bg="#fbfbfb",
                               fg=INK, font=("Consolas", 8), relief="flat",
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
            self.cbanner.config(fg=CRITICAL,
                                text="SCAN FAILED - this list is incomplete. "
                                     + str(lsnap.get("error", ""))[:240])
        else:
            self.cbanner.config(
                fg=INK_MUTED,
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
            t = tk.Frame(self.ctiles, bg="white", highlightthickness=1,
                         highlightbackground="#e3e3e3")
            t.pack(side="left", padx=(0, 8))
            # The accent bar is the same single series colour as the charts,
            # not a status colour: none of these numbers is a fault, and a red
            # or amber edge would make a busy browser look like an incident.
            tk.Frame(t, bg=SERIES, width=5).pack(side="left", fill="y")
            inner = tk.Frame(t, bg="white"); inner.pack(side="left", padx=10, pady=5)
            tk.Label(inner, text=label, bg="white", fg=INK_MUTED,
                     font=("Segoe UI", 7)).pack(anchor="w")
            tk.Label(inner, text=val, bg="white", fg=INK,
                     font=("Segoe UI", 14, "bold")).pack(anchor="w")
            tk.Label(inner, text=note, bg="white", fg=INK_MUTED,
                     font=("Segoe UI", 7)).pack(anchor="w")
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
    SCOLS = (("sev", "SEV", 46), ("port", "PORT", 58), ("state", "STATE", 88),
             ("name", "SERVICE", 130), ("bind", "BOUND HERE", 120),
             ("svc", "WINDOWS SERVICE", 150), ("source", "WHY PROBED", 165),
             ("ms", "MS", 52), ("note", "WHAT IT MEANS", 420))

    STATE_TAG = {"open": CRITICAL, "closed": WARNING, "stealth": GOOD,
                 "unreachable": INK_MUTED, "blocked": INK_MUTED,
                 "error": INK_MUTED}

    def _make_stealth_tab(self):
        """Is a given address invisible from outside, or does it answer?

        Manual only, and deliberately so. The other three tabs read state that
        already exists; this one SENDS ~1100 connection attempts at an address,
        which is indistinguishable from a port scan to whatever sits in front
        of it - and this fleet already has a gateway that drops port 22 for ten
        minutes when it sees a burst. A check with that cost does not get to
        fire on a timer without somebody asking for it."""
        outer = tk.Frame(self.nb, bg="white")
        self.nb.add(outer, text="Stealth")
        self.stealth_tab = outer
        self.srows, self.ssnap = {}, None
        self.sbusy = False

        self.sbanner = tk.Label(outer, bg="white", fg=INK_MUTED, anchor="w",
                                font=("Segoe UI", 9), justify="left")
        self.sbanner.pack(fill="x", padx=10, pady=(6, 0))
        self.scaveat = tk.Label(outer, bg="white", fg=INK_MUTED, anchor="w",
                                font=("Segoe UI", 8), justify="left",
                                wraplength=1340)
        self.scaveat.pack(fill="x", padx=10, pady=(2, 0))
        self.stiles = tk.Frame(outer, bg="white")
        self.stiles.pack(fill="x", padx=8, pady=(4, 2))

        ctl = tk.Frame(outer, bg="white"); ctl.pack(fill="x", padx=10, pady=(2, 4))
        tk.Label(ctl, text="target:", bg="white", fg=INK_MUTED,
                 font=("Segoe UI", 8)).pack(side="left")
        self.starget = tk.StringVar()
        e = tk.Entry(ctl, textvariable=self.starget, width=24,
                     font=("Segoe UI", 9))
        e.pack(side="left", padx=(4, 4))
        e.bind("<Return>", lambda _ev: self._run_stealth())
        tk.Button(ctl, text="my public IP",
                  command=self._fill_public_ip).pack(side="left")

        tk.Label(ctl, text="  from:", bg="white", fg=INK_MUTED,
                 font=("Segoe UI", 8)).pack(side="left")
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
        tk.Label(ctl, text="  sweep:", bg="white", fg=INK_MUTED,
                 font=("Segoe UI", 8)).pack(side="left")
        self.smode = tk.StringVar(value=gmstealth.DEFAULT_MODE)
        for key in ("fast", "gentle"):
            tk.Radiobutton(ctl, text=key, variable=self.smode, value=key,
                           bg="white", fg=INK, font=("Segoe UI", 8),
                           command=self._mode_hint).pack(side="left")

        self.sshowall = tk.BooleanVar(value=False)
        tk.Checkbutton(ctl, text="show stealthed ports too",
                       variable=self.sshowall, bg="white", fg=INK,
                       font=("Segoe UI", 8),
                       command=self._rerender_stealth).pack(side="left", padx=(12, 0))

        self.srunbtn = tk.Button(ctl, text="Run stealth check",
                                 command=self._run_stealth)
        self.srunbtn.pack(side="right")
        tk.Button(ctl, text="Copy all", command=self._copy_stealth)\
            .pack(side="right", padx=6)

        wrap = tk.Frame(outer, bg="white")
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
        for tag, col in self.SEV_TAG.items():
            self.stree.tag_configure(tag, foreground=col)
        self.stree.bind("<<TreeviewSelect>>", self._show_stealth_detail)
        self.ssort = ("sev", False)

        self.sdetail = tk.Text(outer, height=7, wrap="word", bg="#fbfbfb",
                               fg=INK, font=("Consolas", 8), relief="flat",
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
            fg=INK_MUTED,
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
                    fg=WARNING, text="Could not determine this machine's public "
                                     "IP - offline, or every lookup service is "
                                     "unreachable."))
        threading.Thread(target=work, daemon=True, name="pubip").start()

    def _run_stealth(self):
        target = self.starget.get().strip()
        if not target:
            messagebox.showinfo("Infra Monitor", "Enter an IP address or hostname to "
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
            fg=INK_MUTED,
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
                fg=CRITICAL,
                text="STEALTH CHECK DID NOT RUN - this is NOT an all-clear.\n"
                     + str(ssnap.get("error", ""))[:300])
            self.scaveat.config(text="")
            for w in self.stiles.winfo_children():
                w.destroy()
            self.stree.delete(*self.stree.get_children())
            self.srows.clear()
            self.nb.tab(self.stealth_tab, text="Stealth  (failed)")
            return

        col = {"EXPOSED": CRITICAL, "NOT STEALTH": WARNING,
               "UNCONFIRMED": SERIOUS, "STEALTH": GOOD,
               # Not a status colour: a self-probe is neither a pass nor a
               # fault, and giving it one would make a no-op look like a
               # result.
               "SELF-PROBE": INK_MUTED}.get(ssnap["verdict"], INK_MUTED)
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
            self.scaveat.config(fg=SERIOUS, text=ssnap["caveat"])
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
             CRITICAL if c.get("open") else GOOD),
            ("REACHABLE HERE", str(c.get("listeners_open", 0)),
             "our own listeners, from outside",
             CRITICAL if c.get("listeners_open") else GOOD),
            ("CLOSED", str(c.get("closed", 0)), "RST - host reveals itself",
             WARNING if c.get("closed") else GOOD),
            ("STEALTH", str(c.get("stealth", 0)),
             f"{c.get('stealth_pct', 0)}% dropped silently", GOOD),
            # Whether the target proved it exists at all. Without this, a
            # sweep of a switched-off machine renders identically to a
            # perfectly stealthed one - 100% stealth, nothing open - and the
            # tile is the only thing on screen that tells them apart.
            ("HOST IS UP", "yes" if alive else "unproven",
             "ARP/ICMP - is the silence real?", GOOD if alive else SERIOUS),
            ("UNTESTED", str(c.get("untested", 0)), "no conclusive answer",
             WARNING if c.get("untested") else GOOD),
            ("OUR PORTS", str(c.get("listeners", 0)),
             f"{c.get('privileged', 0)} privileged also swept", INK_MUTED),
        ]
        for label, val, note, accent in tiles:
            t = tk.Frame(self.stiles, bg="white", highlightthickness=1,
                         highlightbackground="#e3e3e3")
            t.pack(side="left", padx=(0, 8))
            tk.Frame(t, bg=accent, width=5).pack(side="left", fill="y")
            inner = tk.Frame(t, bg="white"); inner.pack(side="left", padx=10, pady=5)
            tk.Label(inner, text=label, bg="white", fg=INK_MUTED,
                     font=("Segoe UI", 7)).pack(anchor="w")
            tk.Label(inner, text=val, bg="white", fg=INK,
                     font=("Segoe UI", 14, "bold")).pack(anchor="w")
            tk.Label(inner, text=note, bg="white", fg=INK_MUTED,
                     font=("Segoe UI", 7)).pack(anchor="w")

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
        outer = tk.Frame(self.nb, bg="white")
        self.nb.add(outer, text=label)
        cv = tk.Canvas(outer, bg="white", highlightthickness=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=cv.yview)
        inner = tk.Frame(cv, bg="white")
        inner.bind("<Configure>",
                   lambda e, c=cv: c.configure(scrollregion=c.bbox("all")))
        cv.create_window((0, 0), window=inner, anchor="nw")
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
            tk.Label(self.panes["local"]["inner"], bg="white",
                     text="No data yet - first poll in progress.").pack(pady=30)
            return
        gate = ("ON-NETWORK" if snap["gate_ok"] else "OFF-NETWORK")
        self.status.config(
            text=f"{gate} ({snap['gate_note']}, via {snap['gate_id']})   "
                 f"checked {time.strftime('%H:%M:%S', time.localtime(snap['checked_at']))}"
                 f" in {snap['elapsed']}s",
            fg=INK)
        if not snap["machines"]:
            # An empty fleet polls in 0.0s and reports nothing wrong, which
            # looks exactly like a healthy one. Say what is actually going on,
            # and say where the file it wants should be - the usual cause is
            # running a copy of the exe from a folder that has no config.
            missing = not gmconfig.exists()
            self.status.config(
                fg=CRITICAL,
                text=("NO CONFIGURATION - machines.json was not found. "
                      if missing else "No machines configured yet. ")
                     + f"Infra Monitor is reading from {gmpaths.APP_DIR}")
            for key in ("local", "dc"):
                tk.Label(
                    self.panes[key]["inner"], bg="white", fg=INK, justify="left",
                    font=("Segoe UI", 10), padx=20, pady=24,
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
                         bg="white", fg=INK_MUTED).pack(pady=30)
                continue
            tk.Label(pane["inner"], text=note, bg="white", fg=INK_MUTED,
                     font=("Segoe UI", 8)).grid(row=0, column=0, columnspan=self._ncols(), sticky="w", padx=10, pady=(6, 0))
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
        bar = tk.Frame(parent, bg="white")
        bar.grid(row=1, column=0, columnspan=self._ncols(), sticky="ew", padx=8, pady=(6, 2))
        if not live:
            tk.Label(bar, text="No machines reachable.", bg="white",
                     fg=INK_MUTED, font=("Segoe UI", 9)).pack(anchor="w")
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
            t = tk.Frame(bar, bg="white", highlightthickness=1,
                         highlightbackground="#e3e3e3")
            t.pack(side="left", padx=(0, 8))
            tk.Frame(t, bg=col, width=5).pack(side="left", fill="y")
            inner = tk.Frame(t, bg="white"); inner.pack(side="left", padx=10, pady=6)
            tk.Label(inner, text=f"PEAK {label}", bg="white", fg=INK_MUTED,
                     font=("Segoe UI", 7)).pack(anchor="w")
            line = tk.Frame(inner, bg="white"); line.pack(anchor="w")
            tk.Label(line, text=f"{int(val)}%", bg="white", fg=INK,
                     font=("Segoe UI", 14, "bold")).pack(side="left")
            tk.Label(line, text=f"  {word}", bg="white", fg=INK,
                     font=("Segoe UI", 8, "bold")).pack(side="left", pady=(6, 0))
            tk.Label(inner, text=who, bg="white", fg=INK_MUTED,
                     font=("Segoe UI", 7)).pack(anchor="w")

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
                bar = GREY
            elif not r["up"]:
                bar = RED
            elif r["problems"]:
                bar = RED if any("FOREIGN" in p for p in r["problems"]) else AMBER
            else:
                bar = GREEN

            # ONE machine per full-width row. Two narrow columns forced every
            # problem string to be truncated at ~150 chars; a single wide row
            # gives the text the horizontal space it needs, and makes the fleet
            # scan as a list rather than a grid.
            card = tk.Frame(parent, bg="white", highlightthickness=1,
                            highlightbackground="#e8e8e8")
            nc = self._ncols()
            card.grid(row=base_row + i // nc, column=i % nc,
                      padx=3, pady=1, sticky="ew")
            for c in range(nc):
                parent.grid_columnconfigure(c, weight=1, uniform="cards")
            tk.Frame(card, bg=bar, width=4).pack(side="left", fill="y")

            body = tk.Frame(card, bg="white")
            body.pack(side="left", fill="both", expand=True, padx=4, pady=1)

            # Name, address, dials and status all on ONE line. Vertical space
            # is the scarce axis when 13 machines should fit without scrolling;
            # horizontal space is free.
            row0 = tk.Frame(body, bg="white"); row0.pack(fill="x")
            tk.Label(row0, text=r["name"], bg="white", fg=INK, width=7,
                     anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left")
            copyable(row0, r["ip"] or r.get("alias", ""), width=16,
                     fg=INK_MUTED, font=("Consolas", 8)).pack(side="left")

            gpus = m.get("gpus", [])
            if r.get("checked") and r["up"]:
                n = 3 + min(len(gpus), 4)
                cv = tk.Canvas(body, bg="white", height=56, width=n * 58,
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
                lb = tk.Label(row0, text="  " + gtxt[:32], bg="white",
                              fg=INK_MUTED, font=("Segoe UI", 8))
                lb.pack(side="left")
                Tooltip(lb, gtxt)
                qp = m.get("quickpod", "-")
                q = tk.Label(row0, text="  qp:" + qp.split(":")[-1][:8], bg="white", fg=INK_MUTED, font=("Segoe UI", 8))
                q.pack(side="left")
                Tooltip(q, "quickpod: " + qp)
            else:
                note = r.get("note") or "; ".join(r["problems"]) or "unreachable"
                e = copyable(row0, note[:100], fg=INK_MUTED,
                             font=("Segoe UI", 8), width=100)
                e.pack(side="left", fill="x", expand=True)
                Tooltip(e, note)

            if r["problems"]:
                full = "  |  ".join(r["problems"])
                pe = copyable(body, "! " + full, fg=bar,
                              font=("Segoe UI", 8), width=200)
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
        self.geometry("720x520")
        self.configure(bg="white")
        self.rows = {}

        tk.Label(self, bg="white", fg=INK_MUTED, justify="left", anchor="w",
                 font=("Segoe UI", 9), padx=10, pady=5, wraplength=690,
                 text="Turn a check off for machines it does not apply to - a "
                      "permanent warning you cannot act on is what teaches you "
                      "to ignore the panel. Private machines are only polled "
                      "while you are on a known network; public ones are always "
                      "polled.").pack(fill="x")

        head = tk.Frame(self, bg="#f4f4f4"); head.pack(fill="x", padx=10)
        for t, w in (("Machine", 22), ("Network", 12), ("Watch", 8),
                     ("quickpod", 10), ("nvidia-smi", 11), ("Reached via", 14)):
            tk.Label(head, text=t, width=w, anchor="w", bg="#f4f4f4", fg=INK,
                     font=("Segoe UI", 8, "bold")).pack(side="left", pady=4)

        wrap = tk.Frame(self, bg="white"); wrap.pack(fill="both", expand=True, padx=10)
        cv = tk.Canvas(wrap, bg="white", highlightthickness=0)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=cv.yview)
        self.body = tk.Frame(cv, bg="white")
        self.body.bind("<Configure>",
                       lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.create_window((0, 0), window=self.body, anchor="nw")
        cv.configure(yscrollcommand=sb.set)
        cv.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
        cv.bind("<MouseWheel>",
                lambda e: cv.yview_scroll(int(-e.delta / 120), "units"))

        al = tk.Frame(self, bg="white"); al.pack(fill="x", padx=10, pady=(6, 0))
        tk.Label(al, bg="white", fg=INK, font=("Segoe UI", 8, "bold"),
                 text="Allowed SSH peers (comma separated IPs or CIDRs)")\
            .pack(anchor="w")
        tk.Label(al, bg="white", fg=INK_MUTED, font=("Segoe UI", 7),
                 text="Sessions from anywhere else are alerted as intrusions. "
                      "Every monitored machine and both gate networks are "
                      "already allowed automatically - list only extras here.")\
            .pack(anchor="w")
        self.peers = tk.Entry(al, font=("Consolas", 8))
        self.peers.pack(fill="x", pady=(2, 0))

        bar = tk.Frame(self, bg="white"); bar.pack(fill="x", padx=10, pady=8)
        tk.Button(bar, text="Add machine...", command=self.add).pack(side="left")
        tk.Button(bar, text="Remove selected", command=self.remove)\
            .pack(side="left", padx=6)
        tk.Button(bar, text="Export...", command=self.export_cfg)\
            .pack(side="left", padx=(18, 0))
        tk.Button(bar, text="Import...", command=self.import_cfg)\
            .pack(side="left", padx=6)
        tk.Button(bar, text="Save & re-check", command=self.save)\
            .pack(side="right")
        tk.Button(bar, text="Cancel", command=self.destroy)\
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
        for m in self.cfg["machines"]:
            row = tk.Frame(self.body, bg="white"); row.pack(fill="x")
            v = {"watch": tk.BooleanVar(value=m.get("enabled", True)),
                 "quickpod": tk.BooleanVar(value=m.get("check_quickpod", False)),
                 "nvidia": tk.BooleanVar(value=m.get("check_nvidia", True)),
                 "scope": tk.StringVar(
                     value="public" if gmconfig.scope_of(m) == "public" else "private")}
            self.rows[m["name"]] = v
            tk.Radiobutton(row, text="", variable=self.sel, value=m["name"],
                           bg="white").pack(side="left")
            tk.Label(row, text=f"{m['name']}  ({m.get('ip') or m.get('alias','')})",
                     width=20, anchor="w", bg="white", fg=INK,
                     font=("Segoe UI", 9)).pack(side="left")
            ttk.Combobox(row, textvariable=v["scope"], width=9, state="readonly",
                         values=("private", "public")).pack(side="left", padx=(0, 12))
            for key, pad in (("watch", 30), ("quickpod", 44), ("nvidia", 46)):
                tk.Checkbutton(row, variable=v[key], bg="white").pack(side="left")
                tk.Frame(row, bg="white", width=pad).pack(side="left")
            tk.Label(row, text=(gmconfig.relay_of(self.cfg, m) or "direct"),
                     width=14, anchor="w", bg="white", fg=INK_MUTED,
                     font=("Segoe UI", 8)).pack(side="left")

    def add(self):
        d = tk.Toplevel(self); d.title("Add machine"); d.configure(bg="white")
        fields = {}
        for i, (lbl, default) in enumerate((("name", ""), ("ip", ""),
                                            ("user", "root"),
                                            ("alias (optional)", ""),
                                            ("via relay (optional)", ""))):
            tk.Label(d, text=lbl, bg="white", anchor="w", width=18)\
                .grid(row=i, column=0, padx=8, pady=4, sticky="w")
            e = tk.Entry(d, width=28); e.insert(0, default)
            e.grid(row=i, column=1, padx=8, pady=4)
            fields[lbl.split()[0]] = e
        sc = tk.StringVar(value="private")
        ttk.Combobox(d, textvariable=sc, width=10, state="readonly",
                     values=("private", "public")).grid(row=5, column=1, sticky="w",
                                                        padx=8)
        tk.Label(d, text="network", bg="white", anchor="w", width=18)\
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
                messagebox.showerror("Infra Monitor", str(ex), parent=d)
        tk.Button(d, text="Add", command=ok).grid(row=6, column=1, sticky="e",
                                                  padx=8, pady=8)

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
        with_local = has_local and messagebox.askyesno(
            "Infra Monitor", "Include this machine's trusted-image list?\n\n"
            "Those are absolute paths to binaries on THIS PC. On another "
            "machine they are meaningless at best, and at worst a path that "
            "now resolves to a different program.\n\nNo is the safe answer.",
            parent=self, default="no")
        try:
            b = gmexport.export_config(path, with_local=with_local)
        except Exception as ex:
            messagebox.showerror("Infra Monitor", f"Export failed:\n\n{ex}", parent=self)
            return
        log.info("config exported to %s (with_local=%s)", path, with_local)
        messagebox.showinfo(
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
            messagebox.showerror("Infra Monitor", f"Cannot read that file:\n\n{ex}",
                                 parent=self)
            return
        if problems:
            # Refuse rather than import the good half: a config that is
            # partly the old fleet and partly the new one is worse than either.
            messagebox.showerror(
                "Infra Monitor", "This config was NOT imported - nothing has "
                "changed:\n\n" + "\n".join(problems[:12]), parent=self)
            return
        n = len(incoming.get("machines", []))
        merge = messagebox.askyesno(
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
            messagebox.showerror("Infra Monitor", f"Import failed:\n\n{ex}", parent=self)
            return
        log.info("config imported from %s (merge=%s): %s", path, merge, summary)
        messagebox.showinfo(
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
            messagebox.showinfo("Infra Monitor", "Select a machine first.", parent=self)
            return
        if not messagebox.askyesno("Infra Monitor", f"Stop monitoring {name}?\n\n"
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
            messagebox.showerror("Infra Monitor", "Not valid IPs/CIDRs:\n  " +
                                 "\n  ".join(bad) + "\n\nNothing was saved.",
                                 parent=self)
            return
        cfg["allowed_peers"] = peers
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
        self.dash = Dashboard(self.root, self)
        self.dash.withdraw()
        self.icon = pystray.Icon(
            "InfraMonitor", make_icon_image(GREY), "Infra Monitor - starting",
            menu=pystray.Menu(
                pystray.MenuItem("Dashboard", self.show_dash, default=True),
                pystray.MenuItem("Refresh now", lambda *_: self.poll_now()),
                pystray.MenuItem("Settings...", self.show_settings),
                # A checked menu item, not a hidden setting: the app registers
                # itself at logon on first run, and anything that arranges to
                # start itself must show an obvious way to stop it.
                pystray.MenuItem("Start with Windows", self.toggle_autostart,
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

    def show_settings(self, *_):
        self.root.after(0, lambda: Settings(self.root, self))

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
        (messagebox.showinfo if ok else messagebox.showerror)(title, text)
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
        _report("Infra Monitor", f"Start with Windows: {'ON' if on else 'OFF'}\n{note}")
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
               else os.path.join(gmpaths.APP_DIR, "elevated_scan.tmp"))
        snap = gmlocal.scan()
        with open(out, "w", encoding="utf-8") as f:
            json.dump(snap, f)
        return 0 if snap.get("ok") else 1
    App().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())







