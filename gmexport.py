#!/usr/bin/env python3
r"""
gmexport - move an Infra Monitor configuration to another machine.

    python gmexport.py export  infra-monitor-config.json [--with-local]
    python gmexport.py import  infra-monitor-config.json [--merge] [--keep-bootstrapped]
    python gmexport.py show    infra-monitor-config.json

Frozen, the same three verbs live on the exe itself:

    InfraMonitor.exe --export-config <file>
    InfraMonitor.exe --import-config <file>

which is the point: the machine you are deploying TO has no Python, so the
importer cannot be a Python script.

WHAT TRAVELS
The fleet list, the gate settings, the SSH peer allowlist, the per-machine
check switches, and the local_watch settings - i.e. CONFIG ONLY. That is the
part that took work to get right and the part that should be identical
everywhere.

NO SECRETS, EVER. The export is CONFIG ONLY: it never contains SSH private
keys, passwords, or known_hosts. SSH keys stay in ~/.ssh and the bootstrap
password is read from the environment (or prompted) at runtime. The writer does
not merely omit secrets, it ASSERTS their absence: _scan_for_secrets() refuses
to emit anything credential-shaped, so an exported file is safe to email or
commit. See PORTABLE_KEYS for the exact allowlist of fields that travel.

WHAT DOES NOT, AND WHY
  secrets           Nothing here has ever held one. The bootstrap password is
                    read from the environment (or prompted) at runtime and never
                    written to disk; SSH keys live in ~/.ssh. An exported config
                    is not sensitive, and it
                    must stay that way - so the writer asserts it rather than
                    assuming it, and refuses to emit a key-shaped value.
  bootstrapped      RESET on export unless you say otherwise. It records that
                    key auth has been VERIFIED FROM THIS MACHINE. Carrying a
                    true across to a machine whose key those hosts have never
                    seen would make the new install offer a credential
                    speculatively - which is not a free probe, it is a failed
                    login, and enough of them get us banned by fail2ban. That
                    rule is the reason bootstrap_ssh exists; an importer that
                    quietly broke it would undo the whole precaution.
                    --keep-bootstrapped when the key travels with the config.
  trusted_images    Absolute paths to binaries on ONE machine. Somewhere else
                    they are at best meaningless and at worst a path that now
                    resolves to a different program. Opt in with --with-local.
  gpu               KEPT. It is a fact about the remote machine, learned by
                    asking nvidia-smi, and it is equally true from anywhere.

Import always writes machines.json.bak-<timestamp> first, so undoing an import
is renaming one file - no network, no re-export, no second copy of this tool.
"""

import json, os, re, shutil, socket, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gmconfig, gmpaths

KIND = "infra-monitor-config"
# Older exports (and the pre-rebrand tool) used this kind string. Accepted on
# import with a warning, so a config exported before the rename still loads.
LEGACY_KINDS = ("inframonitor-config", "gpumon-config")
VERSION = 1

# Keys that carry configuration worth moving. An allowlist, not a blocklist:
# a future key holding something machine-specific should have to be added
# deliberately rather than travel by default.
PORTABLE_KEYS = (
    "version", "gate_domains", "gate_fingerprints", "gate_public_ip_fallback",
    "allowlist", "poll_seconds", "ssh_timeout",
    "jump_host", "expected_login_cidrs", "expected_login_users",
    "allowed_peers", "local_watch", "machines",
)

# Belt and braces on the promise above. Nothing in this config has ever held a
# credential, so anything that looks like one means an assumption broke.
SECRET_HINT = re.compile(
    r"(BEGIN [A-Z ]*PRIVATE KEY|password|passwd|secret|api[_-]?key|token)",
    re.IGNORECASE)


class ExportError(Exception):
    pass


def _scan_for_secrets(obj, path="config"):
    """Refuse to write anything credential-shaped. A leak is not worth being
    relaxed about, and this file is meant to be emailed around."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if SECRET_HINT.search(str(k)):
                raise ExportError(
                    f"{path}.{k} looks like a credential. Nothing in this "
                    f"config should hold one - export refused.")
            _scan_for_secrets(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _scan_for_secrets(v, f"{path}[{i}]")
    elif isinstance(obj, str) and SECRET_HINT.search(obj):
        raise ExportError(f"{path} holds a credential-shaped value - "
                          f"export refused.")


def build_export(cfg=None, with_local=False, keep_bootstrapped=False):
    cfg = cfg or gmconfig.load()
    out = {k: cfg[k] for k in PORTABLE_KEYS if k in cfg}
    out = json.loads(json.dumps(out))          # deep copy; never edit the live cfg

    machines = []
    for m in out.get("machines", []):
        m = dict(m)
        if not keep_bootstrapped:
            m["bootstrapped"] = False
        machines.append(m)
    out["machines"] = machines

    lw = out.get("local_watch")
    if isinstance(lw, dict) and not with_local:
        lw["trusted_images"] = []

    _scan_for_secrets(out)
    return {
        "kind": KIND, "version": VERSION,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "exported_from": socket.gethostname(),
        "notes": ("bootstrapped flags reset - run 'bootstrap_ssh.py add' or "
                  "'check' on the new machine before its first poll"
                  if not keep_bootstrapped else "bootstrapped flags preserved"),
        "config": out,
    }


def export_config(path, with_local=False, keep_bootstrapped=False, cfg=None):
    bundle = build_export(cfg, with_local, keep_bootstrapped)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)
    return bundle


def read_bundle(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    kind = data.get("kind") if isinstance(data, dict) else None
    if kind != KIND:
        if kind in LEGACY_KINDS:
            print(f"NOTE: {path} uses an older export format ({kind!r}); "
                  f"importing it as {KIND!r}.")
        else:
            raise ExportError(f"{path} is not an Infra Monitor config export.")
    if int(data.get("version", 0)) > VERSION:
        raise ExportError(
            f"{path} was written by a newer Infra Monitor (format v"
            f"{data['version']}, this one understands v{VERSION}). "
            f"Upgrade before importing - a partial read would look like a "
            f"successful import that quietly dropped settings.")
    cfg = data.get("config")
    if not isinstance(cfg, dict):
        raise ExportError(f"{path} has no config section.")
    return data, cfg


def validate(cfg):
    """Every problem at once, not the first one.

    An importer that stops at the first bad machine makes you re-run it once
    per typo; the whole point of validating before writing is that you fix them
    together and the live config is never left half-updated."""
    problems, seen = [], set()
    machines = cfg.get("machines")
    if not isinstance(machines, list):
        return ["'machines' is missing or is not a list"]
    for i, m in enumerate(machines):
        if not isinstance(m, dict):
            problems.append(f"machine[{i}] is not an object")
            continue
        name = m.get("name", f"<unnamed {i}>")
        try:
            gmconfig.validate_machine(m.get("name"), m.get("ip"),
                                      m.get("user"), m.get("alias"))
        except gmconfig.ConfigError as ex:
            problems.append(str(ex))
        if m.get("scope") not in (None, "local", "public"):
            problems.append(f"{name}: scope must be local or public")
        key = str(m.get("name", "")).lower()
        if key in seen:
            problems.append(f"{name}: duplicate machine name")
        seen.add(key)
    for m in machines:
        via = m.get("via")
        if via and via.lower() not in seen:
            problems.append(f"{m.get('name')}: relay '{via}' is not in this "
                            f"config - it would be unreachable")
    return problems


def import_config(path, merge=False, dest=None):
    """Validate, back up, then write. Returns (summary, backup_path)."""
    dest = dest or gmconfig.CONFIG_PATH
    _data, incoming = read_bundle(path)
    problems = validate(incoming)
    if problems:
        raise ExportError("This config was NOT imported - nothing changed:\n  "
                          + "\n  ".join(problems))

    added, updated, kept = 0, 0, 0
    if merge and os.path.isfile(dest):
        # Merge keeps THIS machine's own settings and only folds in the fleet:
        # the reason to merge rather than replace is that the local box already
        # has state worth keeping.
        current = gmconfig.load(dest)
        by_name = {m["name"].lower(): m for m in current.get("machines", [])}
        for m in incoming.get("machines", []):
            k = m["name"].lower()
            if k in by_name:
                # Preserve what was learned HERE: whether key auth is verified
                # from this machine is not something the exporter can know.
                boot = by_name[k].get("bootstrapped", False)
                by_name[k].update(m)
                by_name[k]["bootstrapped"] = boot
                updated += 1
            else:
                by_name[k] = m
                added += 1
        current["machines"] = list(by_name.values())
        for key in ("gate_domains", "gate_fingerprints",
                    "gate_public_ip_fallback", "allowlist",
                    "expected_login_cidrs",
                    "expected_login_users", "allowed_peers", "jump_host",
                    "poll_seconds", "ssh_timeout"):
            if key in incoming:
                current[key] = incoming[key]
        kept = len(current.get("local_watch", {}).get("trusted_images", []))
        result = current
    else:
        result = dict(incoming)
        added = len(result.get("machines", []))

    backup = None
    if os.path.isfile(dest):
        backup = f"{dest}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
        shutil.copy2(dest, backup)
    gmconfig.save(result, dest)
    return {"added": added, "updated": updated, "kept_trusted": kept,
            "machines": len(result.get("machines", [])),
            "merge": merge}, backup


def _cli(argv):
    if not argv or argv[0] not in ("export", "import", "show"):
        print(__doc__.strip())
        return 2
    verb, rest = argv[0], argv[1:]
    if not rest:
        print(f"{verb}: needs a file path")
        return 2
    path = rest[0]
    try:
        if verb == "export":
            b = export_config(path, "--with-local" in rest,
                              "--keep-bootstrapped" in rest)
            n = len(b["config"].get("machines", []))
            print(f"exported {n} machine(s) to {path}")
            print(f"  {b['notes']}")
            if "--with-local" not in rest:
                print("  trusted_images not included (--with-local to keep them)")
            return 0
        if verb == "show":
            data, cfg = read_bundle(path)
            print(f"{path}\n  written {data.get('exported_at')} on "
                  f"{data.get('exported_from')}  (format v{data.get('version')})")
            print(f"  {len(cfg.get('machines', []))} machine(s), "
                  f"jump_host={cfg.get('jump_host')}")
            probs = validate(cfg)
            print("  validates clean" if not probs
                  else "  PROBLEMS:\n    " + "\n    ".join(probs))
            for m in cfg.get("machines", []):
                print(f"    {m['name']:<10}{m.get('ip') or m.get('alias', ''):<18}"
                      f"{m.get('scope', 'local')}")
            return 0 if not probs else 1
        summary, backup = import_config(path, "--merge" in rest)
        print(f"imported: {summary['machines']} machine(s) now configured "
              f"({summary['added']} added, {summary['updated']} updated)")
        if backup:
            print(f"  previous config kept as {os.path.basename(backup)}")
        print("  run 'python bootstrap_ssh.py check' before trusting the "
              "first poll - key auth is not verified on this machine yet")
        return 0
    except (ExportError, OSError, ValueError) as ex:
        print(f"FAILED: {ex}")
        return 1


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
