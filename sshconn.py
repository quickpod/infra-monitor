#!/usr/bin/env python3
r"""
sshconn - one place that knows how to reach a machine.

WHY A JUMP HOST
On some networks the target machines are not reliably SSH-able directly: a
connection works sometimes and silently times out at other times (ICMP keeps
answering, so the machines look up but unreachable). A bastion that sits on the
same network answers on port 22 every time, so it is used as the relay and
everything local goes through it. A jump host is optional - leave `jump_host`
empty and everything is reached directly.

Using a jump host is not just a workaround, it is the gentler design: ONE TCP
connection leaves the monitoring host per poll instead of one per machine, and
the fleet sees a single internal peer rather than a burst of external ones.
Whatever might drop us - a gateway rate limiter, an IDS, fail2ban on some
hosts - a burst is exactly what provokes it.

Public machines are reached directly; they are not on the internal network and
the jump host is no help getting to them.

CONNECTION DISCIPLINE, INHERITED FROM A REAL INCIDENT
A failed authentication is not a free probe. An early "read-only" survey of a
fleet offered our key to machines that had never seen it, and those failed
logins got us locked out host by host. So `connect()` will use a password ONLY
when explicitly told to, and callers must never fall back to a second username
or retry a rejected credential.
"""

import socket, warnings
warnings.filterwarnings("ignore")
import paramiko


class Unreachable(Exception):
    """TCP could not be established - a drop or a down host, NOT an auth
    problem. Kept distinct so callers never respond by trying credentials."""


class AuthRejected(Exception):
    """The credential was refused. Never retry this with another credential."""


def port_open(ip, port=22, timeout=4):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _client():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return c


def open_jump(cfg, password=None, timeout=15):
    """Connect to the bastion. Returns None when no jump host is configured,
    which is a valid setup (everything direct), not an error."""
    name = cfg.get("jump_host")
    if not name:
        return None
    # A relay may be a MONITORED machine or a relay-only host (see
    # gmconfig.resolve_hop). It used to have to be a monitored machine, which
    # made a plain bastion impossible to configure.
    jm = gmconfig.resolve_hop(cfg, name)
    if jm is None:
        raise Unreachable(
            f"relay {name!r} is neither a monitored machine nor a relay host")
    if not jm.get("ip"):
        raise Unreachable(f"relay {name!r} has no address to connect to")
    return connect(cfg, jm, password=password, jump=None, timeout=timeout)


def connect(cfg, machine, password=None, jump=None, timeout=15):
    """Open an SSHClient to `machine`.

    `jump` is an already-connected SSHClient for the bastion, or None. It is
    used only for local machines that are not the bastion itself.

    `password` is used ONLY if given; otherwise key auth only. Passing a
    password for a machine already bootstrapped just wastes an attempt, so
    callers should pass it only during bootstrap.
    """
    ip, user = machine["ip"], machine["user"]
    port = int(machine.get("port") or 22)
    sock = None

    use_jump = (jump is not None
                and machine.get("scope", "local") == "local"
                and machine["name"] != cfg.get("jump_host")
                and not machine.get("relay_only"))

    if use_jump:
        try:
            # A direct-tcpip channel through the bastion behaves like a socket,
            # so the target authenticates us end to end - the bastion never
            # sees our credentials for the target.
            sock = jump.get_transport().open_channel(
                "direct-tcpip", (ip, port), ("127.0.0.1", 0), timeout=timeout)
        except Exception as ex:
            raise Unreachable(f"jump channel to {ip}: {type(ex).__name__}: {ex}")
    else:
        if not port_open(ip, port=port, timeout=min(timeout, 6)):
            raise Unreachable(f"{ip}:{port} did not accept a connection")

    cli = _client()
    try:
        if password is not None:
            cli.connect(ip, port=port, username=user, password=password, sock=sock,
                        timeout=timeout, banner_timeout=25, auth_timeout=25,
                        look_for_keys=False, allow_agent=False)
        else:
            cli.connect(ip, port=port, username=user, sock=sock, timeout=timeout,
                        banner_timeout=25, auth_timeout=25,
                        look_for_keys=True, allow_agent=True)
        return cli
    except paramiko.AuthenticationException as ex:
        cli.close()
        raise AuthRejected(f"{user}@{ip}: {ex}")
    except Exception as ex:
        cli.close()
        raise Unreachable(f"{user}@{ip}: {type(ex).__name__}: {ex}")


def run(cli, cmd, password=None, timeout=45):
    """Run a command. If `password` is given it is fed to sudo -S on stdin -
    never on the command line, where it would be visible in the remote ps
    output for as long as the command runs."""
    stdin, out, err = cli.exec_command(cmd, timeout=timeout)
    if password is not None:
        stdin.write(password + "\n")
        stdin.flush()
    o = out.read().decode("utf-8", "replace")
    e = err.read().decode("utf-8", "replace")
    return out.channel.recv_exit_status(), o, e


def close(*clients):
    for c in clients:
        try:
            if c is not None:
                c.close()
        except Exception:
            pass
