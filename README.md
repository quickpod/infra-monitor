# Infra Monitor

A Windows tray monitor for a fleet of Linux/SSH machines. Polls each machine
over SSH, raises Windows toast notifications when something *changes*, and shows
a dashboard of dials for health, load, disk, logins, optional services and
(optionally) GPUs.

It is infrastructure-agnostic: a "machine" is any host you can reach over SSH.
GPU and service checks are **optional per-machine capabilities**, off unless you
turn them on. A fleet of plain web servers never touches them; a fleet of GPU
boxes gets `nvidia-smi` health for free.

Everything is user-configurable through `machines.json` (see
`machines.example.json` for a fully-worked template). Out of the box it monitors
nothing until you add your first machine - by editing `machines.json`, importing
a config, or using **Settings > Add machine...** in the dashboard.

> **100% AI-built and open source**, published on [QuickOpen](https://quickopen.ai/projects/infra-monitor). Apache-2.0.

## Install (recommended)

Download **`InfraMonitor-Setup.exe`** from the
[QuickOpen page](https://quickopen.ai/projects/infra-monitor) or the
[GitHub release](https://github.com/quickpod/infra-monitor/releases/latest) and
double-click it. It installs per-user (no admin), adds Desktop and Start Menu
shortcuts, and can optionally trust the QuickOpen Root CA. The installer is
Authenticode-signed by the QuickOpen Code Signing CA — verify it at
[quickopen.ai/trust](https://quickopen.ai/trust). After installing, add your
machines in `machines.json` (a Start Menu shortcut opens it) or import a config;
see **Configuration** below.

## Why it is shaped this way

**Relay, not direct (optional).** On some networks, direct SSH to a private
range is unreliable - it works, then port 22 silently DROPS for a while while
ICMP keeps answering, so a machine looks up but unreachable. Bursts of
connections provoke it. If you set a `jump_host` (or a per-machine `via`), those
machines are probed *through* the relay as a *command relay*: one connection
leaves your PC per poll and the relay fans out in parallel from inside its own
network. Leave `jump_host` empty and everything is reached directly.

Not a tunnel: `allowtcpforwarding no` / `allowagentforwarding no` on hardened
hosts break ProxyJump/`direct-tcpip`, so the relay runs `ssh` itself. Machines
can be addressed by an **alias** the relay's own SSH config already knows -
which is how a box whose IP you were never told is still reachable.

**Never authenticate speculatively.** A failed key auth is a failed *login*.
Offering your key to a machine that has never seen it is not a free read-only
probe; doing exactly that during an early survey can lock you out host after
host (fail2ban). `bootstrap_ssh.py` makes at most ONE auth attempt per host,
with the username recorded for it, and never falls back to a second credential.

**Alert on transitions, not on state.** A toast every two minutes saying "disk
97% full" trains you to dismiss it, and then the one that matters gets dismissed
too. Recoveries are announced as well as failures - otherwise you cannot tell a
fixed problem from a monitor that died.

**A relay blip is not N outages.** If a relay is unreachable you lost the
vantage point, not the fleet. Those machines report *unknown* and the notifier
skips them, exactly as the network gate does.

**This machine is watched too.** The SSH checks can see every box except the one
they run from, so the *This PC* tab asks the same "is anyone else in here?"
question about your Windows PC: every socket, matched against the process that
owns it, the service it is registered as, and its Authenticode signature.
Anything not accounted for by a validly signed registered system service is
listed, and an unidentified INBOUND session raises an urgent toast.

Three directions, kept apart because conflating them makes the list unreadable:
`IN` (an established session on a port we listen on), `LISTEN` (an open door,
nobody through it yet) and `OUT` (we opened it - the usual shape of a
compromise, so it is shown and never counted in the headline number). Direction
comes from matching (port, owning pid) against the listener table, because "low
port = server" is wrong on Windows.

Loopback-only listeners are collected but never counted as exposed. Half the
developer tooling on a laptop binds `127.0.0.1`; none of it is reachable from
another machine.

**A stealth check cannot be run from the machine it is checking.** The *This PC*
tab reads the socket table from the inside; the *Stealth* tab asks the opposite
question - what does a stranger's packet get back from this address - and that
question has no answer from inside. So the probe runs on a **relay** (the same
relays the fleet check uses), which is a genuinely external vantage. The relay
is chosen to match the target: a private address is probed from a relay on that
private network, a public address from a relay on the internet. Probing a public
address from a relay behind the same NAT you sit behind would hairpin back and
return *stealth* for every port - a perfect score when nothing was tested.
Probing from this PC is still offered; it is the right vantage for *another*
host, and when the target turns out to be this machine the result is labelled
`SELF-PROBE` and raises no findings.

Three answers, and the middle one is the one people misread:

| | |
|---|---|
| `OPEN` | the handshake completed. Something is listening AND reachable. |
| `CLOSED` | the host sent RST. Nothing is listening - but the host *answered*, so a scanner now knows this address is live and worth revisiting. |
| `STEALTH` | nothing came back. The packet was dropped; from outside, the address is indistinguishable from unused space. |

Only the third is stealth. A firewall set to *block* is stealth; one set to
*reject*, or absent behind a router that answers, is not - and from the inside
those two are identical, which is the whole reason the tab exists.

**All-stealth is ambiguous, so it is not reported as a pass on its own.** A
switched-off machine and a perfectly hardened one produce byte-identical
results. So the vantage also reads its **ARP** cache, which the sweep itself has
just populated: a host cannot answer ARP without being powered on and on the
wire. With neither ARP nor ICMP the verdict is `UNCONFIRMED`, not `STEALTH`.

**Two speeds, because the fast one is genuinely provocative.** ~1100 connection
attempts in five seconds is not merely *like* a port scan, it is one, and some
networks drop port 22 for ten minutes when they see a burst. *Gentle* trades
wall-clock for invisibility: two dozen sockets at a time with a pause between
batches. Same ports, same verdicts; the only thing that changes is how loud the
asking is.

**Only post-authentication sessions count as sessions.** A brute-forcer
mid-handshake holds an ESTABLISHED TCP socket on :22 too. `sshd` names its
per-connection processes (`sshd: user@pts/0` post-auth vs `sshd: unknown [net]`
pre-auth) and the `@` is the boundary. Alerting on failed attacks would keep the
panel permanently red on any internet-facing host.

## Files

| file | role |
|---|---|
| `gmconfig.py` | the single source of truth - `machines.json` loader, add/remove |
| `gmpaths.py` | where the app's files live - the one thing freezing breaks |
| `gmautostart.py` | the logon registration, and its off-switch |
| `gmexport.py` | portable config export/import for a new machine |
| `build_exe.py` | freezes it all into one `InfraMonitor.exe` |
| `Install-InfraMonitor.ps1` | deploy / inspect / remove, with `-WhatIf` |
| `sshconn.py` | one place that knows how to reach a machine |
| `gmcheck.py` | network gate, health + metrics collection, session analysis |
| `gmlocal.py` | connections to THIS machine, what accounts for each, and the connection stats |
| `gmstealth.py` | what an address answers *from outside* - the relay-launched port sweep |
| `gmnotify.py` | Windows toasts, fired only on state changes |
| `gmtray.py` | tray icon, dashboard, settings (entry point: `main(argv)`) |
| `gmtheme.py` | the Aura palette, the accent beam and the KPI tile component |
| `aura.py` | the vendored QuickOpen Aura design system (do not edit; re-vendor) |
| `bootstrap_ssh.py` | one-time key install + fail2ban allowlist; fleet add/remove |
| `machines.json` | your config (ships empty; monitors nothing until you add hosts) |
| `machines.example.json` | a documented template with fake example hosts |

## Appearance

Infra Monitor uses the **Aura design system**, the same look every QuickOpen app
and the AIQuick desktop share: deep-space dark or a clean light surface, one
per-app accent, hairline cards, and the accent beam under the header.

It follows your desktop's light/dark setting by default and changes with it
live - no restart. To pin it, click **Theme** in the dashboard header (or the
tray menu) to cycle *System -> Dark -> Light*; the choice is saved as `theme` in
`machines.json`.

The tray ICON is deliberately not themed: it is painted into the notification
area over whatever the shell puts behind it, so it keeps one fixed high-contrast
set of status colours.

## Configuration

Everything lives in `machines.json`, read fresh on every poll. Copy
`machines.example.json` over it and edit, or start from the empty default and
add machines from the dashboard.

Top-level keys:

| key | meaning |
|---|---|
| `version` | config format version (leave as `1`) |
| `machines` | the fleet - list of machine objects (see below) |
| `poll_seconds` | seconds between fleet polls (default `120`) |
| `ssh_timeout` | per-connection SSH timeout in seconds (default `12`) |
| `jump_host` | name of a machine used to reach `local` machines that have no explicit `via`; empty = all direct |
| `gate_domains` | domains whose resolved IPs mean "I am on a trusted network" (legacy public-IP fallback only) |
| `gate_fingerprints` | learned `{name, gateway_mac, gateway_ip}` entries; the gate matches your default gateway's MAC |
| `gate_public_ip_fallback` | `true` restores the old public-IP gate (a request to a third party each poll); default `false` |
| `allowlist` | CIDRs/IPs pushed to each machine's fail2ban `ignoreip` so monitoring never locks you out |
| `expected_login_cidrs` | SSH sessions from outside these ranges are flagged as possible intrusions |
| `expected_login_users` | logins as a user not listed here are flagged (empty = judge on source IP only) |
| `allowed_peers` | extra trusted IPs/CIDRs; every monitored machine is trusted automatically |
| `autostart` | register to start at logon (reconciled to the registry every launch) |
| `local_watch` | settings for watching THIS PC (see below) |

Per-machine object (in `machines`):

| field | meaning |
|---|---|
| `name` | short unique label (letters/digits/`.-_`) |
| `ip` | IP address, or `""` when reached only by `alias` through a relay |
| `user` | SSH username |
| `scope` | `local` (gated: polled only on a known network) or `public` (always polled) |
| `via` | name of a relay machine to reach this one, or `null` for direct / `jump_host` |
| `alias` | Host entry in the relay's own SSH config, used instead of `user@ip` |
| `gpu` | detected, not declared - `true`/`false`/`null` (unknown); set from what `nvidia-smi` actually reports |
| `enabled` | whether this machine is polled at all |
| `bootstrapped` | key auth has been verified from this machine (set by `bootstrap_ssh.py`) |
| `check_nvidia` | optional: run the `nvidia-smi` GPU health check on this machine |
| `check_quickpod` | optional: check that a named background service is running on this machine |

`local_watch` (watches this Windows PC): `enabled`, `poll_seconds`,
`trusted_publishers`, `trusted_images` (full image paths you have judged safe),
`trusted_peers`, `alert_outbound`, `alert_unverified`.

## Use (from source)

```
python bootstrap_ssh.py list
python bootstrap_ssh.py add <name> <ip> <user> [local|public]
python bootstrap_ssh.py check          # read-only
python gmcheck.py                      # one-shot fleet report
python gmlocal.py [--all] [--json]     # one-shot report on THIS machine
python gmnotify.py --local [--dry-run] # local alerts, without the tray
python gmstealth.py <ip> [--gentle]    # what that address answers from outside
pythonw gmtray.py                      # the tray monitor
```

`gmtray.py`'s entry point is `main(argv)`; running it with no arguments starts
the tray app. `gmstealth.py` with no arguments lists the available vantages and
both sweep modes.

## The exe

```
python build_exe.py          # -> InfraMonitor.exe (next to the sources)
```

One `--onefile --windowed` binary; no Python on the target machine. It keeps the
outgoing exe as `InfraMonitor.exe.bak-<date>` first, so undoing a bad build is a
rename.

**Run the exe from the folder that holds `machines.json`.** It reads its config
from its own directory (see `gmpaths` - frozen, `__file__` points into a temp
directory that is deleted on exit, which would silently discard every saved
setting). A missing config is reported loudly in the dashboard, the tray tooltip
and the log, because "nothing configured" and "nothing wrong" must never look
the same.

**It registers itself to start at logon** on first launch - at logon, not at
boot, because a tray icon needs an interactive session. The tray menu has a
checked *Start with Windows* item, and the `autostart` setting in `machines.json`
is what wins: `gmautostart` reconciles the registry to it in both directions on
every launch. It is a per-user `HKCU\...\Run` value - no admin, no scheduled
task, and removing it is deleting one value.

## Deploying to another machine

Carry three files - `InfraMonitor.exe`, an exported config, and
`Install-InfraMonitor.ps1`:

```
powershell -ExecutionPolicy Bypass -File .\Install-InfraMonitor.ps1 -Install -Config .\infra-monitor-config.json
.\Install-InfraMonitor.ps1                     # read-only status; changes nothing
.\Install-InfraMonitor.ps1 -Uninstall          # stop it, unregister it; keeps machines.json
```

Export from a working install with *Settings > Export...*, or:

```
InfraMonitor.exe --export-config infra-monitor-config.json [--with-local]
InfraMonitor.exe --import-config infra-monitor-config.json [--merge] [--quiet]
```

`--quiet` matters for scripting: the exe is a GUI-subsystem binary, so it reports
through a message box and would otherwise block a script until someone clicked
OK. The outcome goes to `inframonitor.log` either way.

**`bootstrapped` is reset on export.** It records that key auth was verified
*from the machine that exported it*. Carrying a `true` across would make the new
install offer a key to hosts that have never seen it - which is not a free probe,
it is a failed login. Run `bootstrap_ssh.py check` on the new machine before
trusting its first poll. Nothing exported is secret, and the writer refuses to
emit anything credential-shaped.

Import validates the whole file first and refuses on any error. The previous
`machines.json` is copied to `machines.json.bak-<timestamp>` first.

## Back up / move your config

Your whole setup is one portable file. Nothing in it is secret.

- **Export** (GUI): *Settings > Export...* - pick a location and save.
  **Export** (CLI): `InfraMonitor.exe --export-config infra-monitor-config.json`
  (from source: `python gmexport.py export infra-monitor-config.json`).
- **What's included:** config only - machines, users, CIDRs, gate settings,
  jump host, poll interval, and the per-machine check toggles. **Never** SSH
  keys, passwords, or `known_hosts`; the exporter refuses to write anything
  credential-shaped, so the file is safe to email, back up, or commit.
- **Import** (GUI): *Settings > Import...* (there is a *merge* prompt).
  **Import** (CLI): `InfraMonitor.exe --import-config infra-monitor-config.json [--merge]`
  (from source: `python gmexport.py import infra-monitor-config.json [--merge]`).
  Import validates first, writes a `machines.json.bak-<timestamp>`, and `--merge`
  folds the fleet into an existing config instead of replacing it.

`local_watch.trusted_images` holds absolute paths meaningful only on one PC, so
it is left out unless you pass `--with-local`. `bootstrapped` flags are reset on
export (see above) unless you pass `--keep-bootstrapped`.

## The network gate

Local machines are polled only when you are on a known network. By default the
gate matches your **default gateway's MAC** against `gate_fingerprints`, decided
locally with no network call. It fails CLOSED - if it cannot tell where you are,
local machines are not probed, because assuming you are on-network means probing
private addresses while attached to somebody else's network.

Run `InfraMonitor.exe --learn-gate "name"` once on each trusted network to record
it. Until a network is learned the gate reads OFF-NETWORK and says so. If you
have no private/gated machines, mark everything `public` and ignore the gate.

`gate_public_ip_fallback: true` restores an older behaviour that asked a public
IP service on every poll and compared it against `gate_domains`; it is off by
default because that is a request to a third party each cycle.

## First-time SSH setup

`bootstrap_ssh.py apply` installs your public key
(`~/.ssh/id_ed25519.pub`) on each machine and writes a fail2ban `ignoreip`
drop-in so routine monitoring can never lock you out. The one first-time login
per host uses a password read from the `INFRAMON_SSH_PASSWORD` environment
variable (or prompted if unset), passed to `sudo` on stdin - never on a command
line, never written to disk, never logged. After key auth is verified the host
is marked `bootstrapped` and only key auth is used thereafter.

## License

Apache-2.0 — see [LICENSE](LICENSE). Infra Monitor is a 100% AI-built project published on QuickOpen; the only human involvement is testing and guidance.
