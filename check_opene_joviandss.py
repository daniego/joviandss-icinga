#!/usr/bin/env python3
"""
parse_opene_cmk.py

Fetch and parse Checkmk agent output from an Open-E box over SSH
or from a local file, and print structured JSON.

Examples
--------
# 1) SSH (your exact command):
python3 parse_opene_cmk.py --host 10.10.42.10 --port 22224 \
    --user cli --identity ~/Downloads/DEV-OE01.key --command check_mk_agent

# 2) Parse from a saved file:
python3 parse_opene_cmk.py --input-file /path/to/check_mk_results.txt

The parser is generic for <<<section>>> blocks and includes specific
decoders for: zfsget:sep(9), [df] inside zfsget, mem, cpu, uptime, ps_lnx.
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from typing import Dict, List, Tuple, Any, Iterable
from math import isfinite



SECTION_RE = re.compile(r"<<<(?P<name>[a-zA-Z0-9_:-]+)>>>")

# Helper to sanitize perfdata labels
def _sanitize_label(s: str) -> str:
    # For perfdata labels: replace non-alnum/underscore with underscore
    return re.sub(r'[^A-Za-z0-9_]+', '_', s)


SIZE_RE = re.compile(r"^\s*([0-9]*\.?[0-9]+)\s*([KMGTPE]?)(B)?\s*$", re.IGNORECASE)

def _unit_to_pow(unit: str) -> int:
    u = unit.upper()
    return {"": 0, "K": 1, "M": 2, "G": 3, "T": 4, "P": 5, "E": 6}.get(u, 0)

def parse_size_to_bytes(val: str) -> int:
    """
    Convert strings like '123', '123K', '12.5G', '1T', 'none' to bytes.
    Returns None for unknown/non-numeric.
    """
    if val is None:
        return None
    s = str(val).strip()
    if s.lower() in ("none", "-", "inf", "infinite", "unlimited", "na", "n/a"):
        return None
    m = SIZE_RE.match(s)
    if not m:
        # Some zfs props can be a number without unit but already bytes
        try:
            return int(float(s))
        except Exception:
            return None
    num = float(m.group(1))
    unit = m.group(2) or ""
    return int(num * (1024 ** _unit_to_pow(unit)))


def run_ssh(host: str, port: int, user: str, identity: str, command: str, extra_ssh_opts: List[str], timeout: int) -> str:
    ssh_cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-p", str(port),
        "-i", identity,
        f"{user}@{host}",
        command,
    ]
    if extra_ssh_opts:
        # insert each -o X pair before host
        base = ["ssh"]
        for opt in extra_ssh_opts:
            base += ["-o", opt]
        ssh_cmd = base + ["-p", str(port), "-i", identity, f"{user}@{host}", command]

    try:
        cp = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError("ssh not found in PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError("SSH command timed out")

    if cp.returncode != 0:
        raise RuntimeError(f"SSH failed (rc={cp.returncode}): {cp.stderr.strip() or cp.stdout.strip()}")
    return cp.stdout


def read_input(input_file: str) -> str:
    with open(input_file, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def split_sections(raw: str) -> List[Tuple[str, List[str]]]:
    """
    Split into [(section_name, lines), ...].
    Some lines may contain back-to-back tags (as in your sample).
    We handle that by virtually closing the previous section when a new tag starts on the same line.
    """
    out: List[Tuple[str, List[str]]] = []
    current_name = "_preamble"
    current_lines: List[str] = []

    def push():
        nonlocal current_name, current_lines
        if current_lines or current_name != "_preamble":
            out.append((current_name, current_lines))
        current_lines = []

    for line in raw.splitlines():
        # Find all tags in the line, and split accordingly
        tags = list(SECTION_RE.finditer(line))
        if not tags:
            current_lines.append(line)
            continue

        # text before first tag belongs to previous section
        prefix_end = tags[0].start()
        if prefix_end > 0:
            current_lines.append(line[:prefix_end])

        # For each found tag, push the previous section and start a new one
        for i, m in enumerate(tags):
            if i > 0:
                # text between previous tag end and this tag start belongs to the previous section
                between = line[tags[i-1].end():m.start()]
                if between.strip():
                    current_lines.append(between)

            # start new section
            push()
            current_name = m.group("name")
            # Any trailing text after the tag on this same line belongs to the new section
            # (but there could be another tag later on this line—handled at next iteration)
            # We’ll add trailing tail after the last tag below.

        # Tail after the last tag:
        tail = line[tags[-1].end():]
        if tail:
            current_lines.append(tail)

    # push last
    push()
    return out



# ----------- Additional specific decoders -----------

def parse_tcp_conn_stats(block: List[str]) -> Dict[str, int]:
    """
    Parse lines like "01 4692" where the first field is the TCP state in hex as
    in /proc/net/tcp and the second field is the count. Returns a dict with
    human-readable keys such as tcp_established, tcp_time_wait, etc.
    """
    state_map = {
        "01": "established",
        "02": "syn_sent",
        "03": "syn_recv",
        "04": "fin_wait1",
        "05": "fin_wait2",
        "06": "time_wait",
        "07": "close",
        "08": "close_wait",
        "09": "last_ack",
        "0A": "listen",
        "0B": "closing",
    }
    out: Dict[str, int] = {}
    for line in block:
        parts = line.strip().split()
        if len(parts) != 2:
            continue
        code, cnt = parts[0].upper(), parts[1]
        if code in state_map:
            try:
                out[f"tcp_{state_map[code]}"] = int(cnt)
            except ValueError:
                pass
    return out


def parse_zfs_arc_cache(block: List[str]) -> Dict[str, Any]:
    """
    Parse the zfs_arc_cache section of key = value lines. Returns numeric values
    where possible and computes hit ratios if hits/misses are present.
    """
    kv: Dict[str, Any] = {}
    for line in block:
        if "=" not in line:
            continue
        k, v = [s.strip() for s in line.split("=", 1)]
        # convert underscores to safer keys
        key = k.lower().strip()
        # numeric? allow integers only to avoid unit mishaps
        try:
            if v.lower().endswith("b") and v[:-1].strip().isdigit():
                # unlikely format, but strip trailing 'B'
                num = int(v[:-1].strip())
            else:
                num = int(v)
            kv[key] = num
        except Exception:
            # keep raw string as fallback
            kv[key] = v
    # Derive ratios if possible
    try:
        hits = int(kv.get("hits"))
        misses = int(kv.get("misses"))
        total = hits + misses
        if total > 0:
            kv["arc_hit_ratio"] = round(100.0 * hits / total, 2)
    except Exception:
        pass
    try:
        l2_hits = int(kv.get("l2_hits"))
        l2_misses = int(kv.get("l2_misses"))
        total2 = l2_hits + l2_misses
        if total2 > 0:
            kv["l2_hit_ratio"] = round(100.0 * l2_hits / total2, 2)
    except Exception:
        pass
    return kv


def parse_zpool_summary(block: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Parse the compact zpool summary table (with headers like: name size alloc free ckCap frag cap dedup health altroot)
    Returns mapping: {pool_name: {"cap_pct": float, "health": str, "size": str, "alloc": str, ...}}
    Numeric percentages are returned without the '%' sign as floats.
    """
    pools: Dict[str, Dict[str, Any]] = {}
    header = None
    for line in block:
        if not line.strip():
            continue
        parts = line.split()
        if not parts:
            continue
        # detect header row (contains 'name' and 'health')
        if ("name" in parts) and ("health" in parts):
            header = parts
            continue
        if header is None:
            # skip until header found
            continue
        # align to header length; some fields like 'altroot' may be missing
        row = parts
        name = row[0]
        # Build a dict aligning by index when header is known
        data: Dict[str, Any] = {}
        for i, h in enumerate(header[1:], start=1):
            if i < len(row):
                data[h] = row[i]
        # Normalize cap -> cap_pct
        cap_raw = data.get("cap") or data.get("ckCap") or data.get("capacity")
        cap_pct = None
        if isinstance(cap_raw, str):
            m = re.match(r"(\d+(?:\.\d+)?)%", cap_raw)
            if m:
                cap_pct = float(m.group(1))
        data["cap_pct"] = cap_pct
        pools[name] = data
    return pools


def parse_lnx_if_upcount(block: List[str]) -> int:
    """
    Count interfaces with state UP from `ip -o link`-style lines in lnx_if.
    """
    cnt = 0
    for line in block:
        if ":" in line and "state UP" in line:
            cnt += 1
    return cnt


def parse_postfix_mailq(block: List[str]) -> int:
    """
    Return the number of queued mails if present, else 0 when 'Mail queue is empty'.
    """
    text = "\n".join(block)
    if "Mail queue is empty" in text:
        return 0
    # Look for lines like "-- 10 Kbytes in 5 Requests."
    m = re.search(r"(\d+)\s+Requests", text)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            pass
    # Fallback: unknown -> None
    return None


# ----------- Specific decoders for known sections -----------

def parse_keyval_kb(block: List[str]) -> Dict[str, int]:
    """
    For 'mem' style sections: "Key:    123 kB"
    Returns values in BYTES where meaningful (kB -> *1024), unknown -> raw.
    """
    out: Dict[str, int] = {}
    for line in block:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        v = v.strip()
        # Expect numbers, maybe with 'kB'
        m = re.match(r"(-?\d+)\s*kB$", v)
        if m:
            out[k] = int(m.group(1)) * 1024
        else:
            # fallback: take int if numeric, else ignore
            mn = re.match(r"(-?\d+)$", v)
            if mn:
                out[k] = int(mn.group(1))
    return out


def parse_cpu_load(block: List[str]) -> Dict[str, Any]:
    """
    Example: "0.54 0.55 0.55 5/1514 15828 40"
    First three are load1, load5, load15.
    """
    if not block:
        return {}
    parts = block[0].split()
    out = {}
    try:
        out["load1"] = float(parts[0])
        out["load5"] = float(parts[1])
        out["load15"] = float(parts[2])
    except Exception:
        pass
    return out


def parse_uptime(block: List[str]) -> Dict[str, Any]:
    """
    First number: uptime seconds (float). Second: idle time (kernel dependent).
    """
    if not block:
        return {}
    parts = block[0].split()
    out = {}
    try:
        out["uptime_seconds"] = float(parts[0])
    except Exception:
        pass
    if len(parts) > 1:
        try:
            out["idle_seconds"] = float(parts[1])
        except Exception:
            pass
    return out


def parse_zfsget_sep9(block: List[str]) -> Dict[str, Any]:
    """
    Parse zfs get output. Supports both tab-separated (preferred) and
    whitespace-separated lines. Expected columns:
        dataset  key  value  source
    Return: { dataset: {key: {"value": ..., "bytes": ..., "source": ...}, ...}, ... }
    """
    datasets: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for line in block:
        if not line.strip():
            continue
        # Stop if the df sub-block marker appears embedded here
        if line.strip() == "[df]":
            break
        parts = line.split("\t")
        if len(parts) < 4:
            # Fall back to whitespace split into 4 columns max
            parts = line.split(None, 3)
        if len(parts) < 4:
            # Not a valid row; skip
            continue
        ds, key, value, source = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()
        datasets.setdefault(ds, {})
        val_bytes = parse_size_to_bytes(value)
        datasets[ds][key] = {"value": value, "bytes": val_bytes, "source": source}
    return datasets


def parse_df_like(block: Iterable[str]) -> List[Dict[str, Any]]:
    """
    Parses df-style lines:
    <name> <fstype> <size> <used> <avail> <use%> <mountpoint>
    Numbers are bytes; some agent outputs already in bytes (your sample looks like bytes).
    """
    rows: List[Dict[str, Any]] = []
    for line in block:
        if not line.strip() or line.strip() == "[df]":
            continue
        parts = line.split()
        if len(parts) < 7:
            continue
        name = parts[0]
        fstype = parts[1]
        try:
            size = int(parts[2])
            used = int(parts[3])
            avail = int(parts[4])
        except ValueError:
            continue
        usep_txt = parts[5]
        m = re.match(r"(\d+)%", usep_txt)
        usep = int(m.group(1)) if m else None
        mnt = " ".join(parts[6:])  # mountpoints can have spaces
        rows.append({
            "fs": name,
            "fstype": fstype,
            "size_bytes": size,
            "used_bytes": used,
            "avail_bytes": avail,
            "use_percent": usep,
            "mountpoint": mnt,
        })
    return rows


def parse_ps_lnx(block: List[str]) -> Dict[str, Any]:
    """
    Store header and N lines (we won’t try to fully parse every process).
    """
    procs = []
    header = None
    for line in block:
        if not line.strip():
            continue
        if line.startswith("[header]"):
            header = line[len("[header]"):].strip()
            continue
        procs.append(line)
    return {"header": header, "lines": procs}


def parse_plugins_list(block: List[str]) -> Dict[str, Any]:
    """
    From the concatenated 'cmk_agent_ctl_status' + 'checkmk_agent_plugins_lnx' you posted.
    We’ll capture plugin/local dirs and discovered plugin paths.
    """
    plugins = {
        "pluginsdir": None,
        "localdir": None,
        "entries": [],
    }
    for line in block:
        line = line.strip()
        if not line:
            continue
        if line.startswith("pluginsdir "):
            plugins["pluginsdir"] = line.split(" ", 1)[1]
        elif line.startswith("localdir "):
            plugins["localdir"] = line.split(" ", 1)[1]
        elif line.startswith("/") and (":CMK_VERSION=" in line or "CMK_VERSION=" in line):
            # e.g. /usr/lib/check_mk_agent/plugins/zfs_arc_cache:CMK_VERSION="unversioned"
            path, _, ver = line.partition(":")
            m = re.search(r'CMK_VERSION="([^"]*)"', ver)
            plugins["entries"].append({"path": path, "cmk_version": m.group(1) if m else None})
    return plugins


def dataset_usage_from_zfsget(
    zfsget: Dict[str, Dict[str, Dict[str, Any]]], dataset: str, df_rows: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Compute usage for a ZFS dataset taking quota/refquota into account.
    Preference order for quota: refquota > quota.
    Preference order for used: usedbydataset > used (fallback).
    If there is no quota, try to derive capacity from df (by matching the dataset's mountpoint).
    Returns dict with used_bytes, quota_bytes, used_pct (if quota/capacity present).
    """
    if not zfsget or dataset not in zfsget:
        # Try df fallback by matching df fs name to the dataset string
        if df_rows:
            for row in df_rows:
                if row.get("fs") == dataset:
                    size = row.get("size_bytes")
                    used = row.get("used_bytes")
                    used_pct = round(100.0 * used / size, 2) if size else None
                    return {"used_bytes": used, "quota_bytes": size, "used_pct": used_pct}
        return {}
    props = zfsget[dataset]
    # pick used
    used_b = None
    for k in ("usedbydataset", "used"):
        if k in props:
            used_b = props[k].get("bytes")
            if used_b is not None:
                break
    # pick quota
    quota_b = None
    for k in ("refquota", "quota"):
        if k in props:
            quota_b = props[k].get("bytes")
            if quota_b:
                break
    # Fallback: if no quota, try capacity from df using mountpoint
    capacity_b = None
    if (not quota_b or quota_b == 0) and props.get("mountpoint", {}).get("value") not in (None, "none", "-", "legacy"):
        mnt = props.get("mountpoint", {}).get("value")
        if df_rows:
            for row in df_rows:
                if row.get("mountpoint") == mnt:
                    capacity_b = row.get("size_bytes")
                    # If we don't have used bytes yet, use df used
                    if used_b is None:
                        used_b = row.get("used_bytes")
                    break
    # Compute percent
    used_pct = None
    denom = quota_b if quota_b and quota_b > 0 else capacity_b
    if denom and denom > 0 and used_b is not None:
        try:
            used_pct = round(100.0 * float(used_b) / float(denom), 2)
        except Exception:
            used_pct = None
    return {"used_bytes": used_b, "quota_bytes": quota_b or capacity_b, "used_pct": used_pct}

# Compute all datasets usage
def all_datasets_usage(zfsget: Dict[str, Dict[str, Dict[str, Any]]], df_rows: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Build a list of usage entries for all datasets found in zfsget,
    or fallback to df rows if zfsget is empty/missing.
    """
    if zfsget:
        out: List[Dict[str, Any]] = []
        for ds in sorted(zfsget.keys()):
            usage = dataset_usage_from_zfsget(zfsget, ds, df_rows=df_rows)
            if usage:
                entry = {"dataset": ds}
                entry.update(usage)
                out.append(entry)
        return out
    # Fallback: build from df rows only
    if not df_rows:
        return []
    out: List[Dict[str, Any]] = []
    for row in df_rows:
        size = row.get("size_bytes")
        used = row.get("used_bytes")
        used_pct = round(100.0 * used / size, 2) if size else None
        out.append({
            "dataset": row.get("fs"),
            "used_bytes": used,
            "quota_bytes": size,  # treat filesystem size as capacity
            "used_pct": used_pct,
        })
    return out

def find_df_entry(df_rows: List[Dict[str, Any]], *, mountpoint: str = None, fs: str = None) -> Dict[str, Any]:
    if not df_rows:
        return {}
    for row in df_rows:
        if mountpoint and row.get("mountpoint") == mountpoint:
            return row
        if fs and row.get("fs") == fs:
            return row
    return {}


# ---- Metric documentation block ----
METRIC_HELP_TEXT = (
    "Supported metrics (use with --metric):\n"
    "  CPU: load (1,5,15) (unit: load avg)\n"
    "  Uptime: uptime_seconds | idle_seconds (unit: seconds)\n"
    "  Memory: mem_used_pct (unit: %) | mem_used_bytes (unit: B) | mem_total_bytes (unit: B)\n"
    "  Processes: process_count (unit: count)\n"
    "  TCP connections: tcp_established | tcp_syn_sent | tcp_syn_recv | tcp_fin_wait1 | tcp_fin_wait2 | tcp_time_wait | tcp_close | tcp_close_wait | tcp_last_ack | tcp_listen | tcp_closing (unit: sockets)\n"
    "  Filesystem-by-mount or fs name (require --mount or --fs):\n"
    "    fs_used_pct (unit: %) | fs_used_bytes (unit: B) | fs_total_bytes (unit: B) | fs_avail_bytes (unit: B)\n"
    "  Filesystem summary (across all filesystems):\n"
    "    df_used_pct (unit: %) | df_used_bytes (unit: B) | df_total_bytes (unit: B) | filesystem_count (unit: count)\n"
    "  ZFS ARC cache: arc_size_bytes | arc_compressed_size_bytes | arc_uncompressed_size_bytes | l2_size_bytes | l2_asize_bytes | arc_hit_ratio (unit: %) | l2_hit_ratio (unit: %)\n"
    "  ZFS pools: zpool_worst_cap_pct (unit: %) | zpool_unhealthy_count (unit: pools) | zpool_pool_cap_pct (requires --pool, unit: %)\n"
    "  ZFS datasets (require --dataset for single dataset):\n"
    "    dataset_used_pct (unit: %) | dataset_used_bytes (unit: B) | dataset_quota_bytes (unit: B) | all_datasets\n"
    "  Plugins/inventory: plugins_count (unit: count)\n"
    "  Mail: postfix_queue_length (unit: messages)\n"
)

def pick_metric_value(parsed: Dict[str, Any], args) -> Tuple[str, float]:
    """
    Returns (label, value) for the requested metric.
    """
    m = args.metric
    if not m:
        return (None, None)

    # Unified CPU load metric: returns load1 as the primary numeric value
    if m == "load":
        val = parsed.get("cpu", {}).get("load1")
        return ("load", float(val)) if val is not None else ("load", None)

    # (Legacy) individual CPU load metrics
    if m in ("load1", "load5", "load15"):
        val = parsed.get("cpu", {}).get(m)
        return (m, float(val)) if val is not None else (m, None)

    # Uptime
    if m == "uptime_seconds":
        val = parsed.get("uptime", {}).get("uptime_seconds")
        return (m, float(val)) if val is not None else (m, None)
    if m == "idle_seconds":
        val = parsed.get("uptime", {}).get("idle_seconds")
        return (m, float(val)) if val is not None else (m, None)

    # Memory
    if m == "mem_used_pct":
        val = parsed.get("mem_summary", {}).get("used_pct")
        return (m, float(val)) if val is not None else (m, None)
    if m == "mem_used_bytes":
        val = parsed.get("mem_summary", {}).get("used_bytes")
        return (m, float(val)) if val is not None else (m, None)
    if m == "mem_total_bytes":
        val = parsed.get("mem_summary", {}).get("total_bytes")
        return (m, float(val)) if val is not None else (m, None)

    # Processes
    if m == "process_count":
        try:
            val = len(parsed.get("ps_lnx", {}).get("lines", []) or [])
        except Exception:
            val = None
        return (m, float(val)) if val is not None else (m, None)

    # Filesystem by mount or fs
    if m in ("fs_used_pct", "fs_used_bytes", "fs_total_bytes", "fs_avail_bytes"):
        row = find_df_entry(parsed.get("df", []), mountpoint=args.mount, fs=args.fs)
        if not row:
            return (m, None)
        if m == "fs_used_pct":
            val = row.get("use_percent")
            return (m, float(val)) if val is not None else (m, None)
        if m == "fs_used_bytes":
            val = row.get("used_bytes")
            return (m, float(val)) if val is not None else (m, None)
        if m == "fs_total_bytes":
            val = row.get("size_bytes")
            return (m, float(val)) if val is not None else (m, None)
        if m == "fs_avail_bytes":
            val = row.get("avail_bytes")
            return (m, float(val)) if val is not None else (m, None)

    # Filesystem summary across all
    if m == "df_used_pct":
        val = parsed.get("df_summary", {}).get("used_pct")
        return (m, float(val)) if val is not None else (m, None)
    if m == "df_used_bytes":
        val = parsed.get("df_summary", {}).get("used_bytes")
        return (m, float(val)) if val is not None else (m, None)
    if m == "df_total_bytes":
        val = parsed.get("df_summary", {}).get("total_bytes")
        return (m, float(val)) if val is not None else (m, None)
    if m == "filesystem_count":
        try:
            val = len(parsed.get("df", []) or [])
        except Exception:
            val = None
        return (m, float(val)) if val is not None else (m, None)

    # ZFS dataset metrics
    if m in ("dataset_used_pct", "dataset_used_bytes", "dataset_quota_bytes"):
        usage = dataset_usage_from_zfsget(parsed.get("zfsget", {}), args.dataset, df_rows=parsed.get("df", [])) if args.dataset else {}
        if m == "dataset_used_pct":
            return (m, float(usage.get("used_pct"))) if usage.get("used_pct") is not None else (m, None)
        if m == "dataset_used_bytes":
            return (m, float(usage.get("used_bytes"))) if usage.get("used_bytes") is not None else (m, None)
        if m == "dataset_quota_bytes":
            return (m, float(usage.get("quota_bytes"))) if usage.get("quota_bytes") is not None else (m, None)

    if m == "all_datasets":
        entries = all_datasets_usage(parsed.get("zfsget", {}), df_rows=parsed.get("df", []))
        return (m, entries if entries is not None else None)

    # Plugins / inventory
    if m == "plugins_count":
        try:
            val = len((parsed.get("plugins") or {}).get("entries", []) or [])
        except Exception:
            val = None
        return (m, float(val)) if val is not None else (m, None)

    # TCP connection states
    if m.startswith("tcp_"):
        val = (parsed.get("tcp_conn_stats") or {}).get(m)
        return (m, float(val)) if val is not None else (m, None)

    # ZFS ARC cache metrics
    if m in ("arc_size_bytes", "arc_compressed_size_bytes", "arc_uncompressed_size_bytes", "l2_size_bytes", "l2_asize_bytes", "arc_hit_ratio", "l2_hit_ratio"):
        key_map = {
            "arc_size_bytes": "size",
            "arc_compressed_size_bytes": "compressed_size",
            "arc_uncompressed_size_bytes": "uncompressed_size",
            "l2_size_bytes": "l2_size",
            "l2_asize_bytes": "l2_asize",
            "arc_hit_ratio": "arc_hit_ratio",
            "l2_hit_ratio": "l2_hit_ratio",
        }
        k = key_map[m]
        val = (parsed.get("zfs_arc_cache") or {}).get(k)
        return (m, float(val)) if val is not None else (m, None)

    # ZFS pool metrics
    if m == "zpool_worst_cap_pct":
        val = (parsed.get("zpool_summary") or {}).get("worst_cap_pct")
        return (m, float(val)) if val is not None else (m, None)
    if m == "zpool_unhealthy_count":
        val = (parsed.get("zpool_summary") or {}).get("unhealthy_count")
        return (m, float(val)) if val is not None else (m, None)
    if m == "zpool_pool_cap_pct":
        pools = parsed.get("zpool", {})
        p = args.pool
        if not (p and p in pools):
            return (m, None)
        val = pools[p].get("cap_pct")
        return (m, float(val)) if val is not None else (m, None)

    # Network interfaces
    if m == "net_up_if_count":
        val = (parsed.get("net_if") or {}).get("up_count")
        return (m, float(val)) if val is not None else (m, None)

    # Mail queue size
    if m == "postfix_queue_length":
        val = (parsed.get("postfix") or {}).get("queue_length")
        return (m, float(val)) if val is not None else (m, None)

    return (m, None)


# ----------- Master parse function -----------

def parse_agent_output(raw: str) -> Dict[str, Any]:
    sections = split_sections(raw)
    result: Dict[str, Any] = {"_raw_sections": {}}

    # store raw text per section too (helps debugging)
    for name, lines in sections:
        result["_raw_sections"][name] = len(lines)

    # Now decode specific sections we care about
    # Some blocks to combine: "zfsget:sep(9)" and the following "[df]" chunk (until next <<<)
    # We’ll scan once and parse.
    i = 0
    while i < len(sections):
        name, lines = sections[i]

        if name.startswith("zfsget:sep(9)"):
            zfsget = parse_zfsget_sep9(lines)
            # Peek into same section for embedded [df]
            df_start = None
            for idx, l in enumerate(lines):
                if l.strip() == "[df]":
                    df_start = idx + 1
                    break
            if df_start is not None:
                df_rows = parse_df_like(lines[df_start:])
            else:
                # Next section might actually be "zfsget" without :sep, or a separate <<<zfsget>>> with [df]
                df_rows = []

            result["zfsget"] = zfsget
            if df_rows:
                result["df"] = df_rows

        elif name == "zfsget":
            # Some agents split plain zfsget and the df table
            if lines and lines[0].strip() == "[df]":
                result["df"] = parse_df_like(lines)
            else:
                result["zfsget"] = parse_zfsget_sep9(lines)

        elif name == "mem":
            result["mem"] = parse_keyval_kb(lines)

        elif name == "cpu":
            result["cpu"] = parse_cpu_load(lines)

        elif name == "uptime":
            result["uptime"] = parse_uptime(lines)

        elif name == "ps_lnx":
            result["ps_lnx"] = parse_ps_lnx(lines)

        elif name in ("cmk_agent_ctl_status", "checkmk_agent_plugins_lnx"):
            # These sometimes come concatenated on one physical line; we’ll merge them
            prev = result.get("plugins") or {"pluginsdir": None, "localdir": None, "entries": []}
            parsed = parse_plugins_list(lines)
            # merge
            result["plugins"] = {
                "pluginsdir": parsed["pluginsdir"] or prev.get("pluginsdir"),
                "localdir": parsed["localdir"] or prev.get("localdir"),
                "entries": (prev.get("entries") or []) + parsed["entries"],
            }

        elif name.startswith("tcp_conn_stats"):
            result["tcp_conn_stats"] = parse_tcp_conn_stats(lines)

        elif name == "zfs_arc_cache":
            result["zfs_arc_cache"] = parse_zfs_arc_cache(lines)

        elif name == "zpool":
            result["zpool"] = parse_zpool_summary(lines)

        elif name == "zpool_status":
            # Not strictly needed if summary provides health, but we keep count of non-ONLINE as a safeguard
            text = "\n".join(lines)
            # crude detection: if any line "state: <STATE>" and STATE != ONLINE, we will later count it
            result.setdefault("_zpool_status_text", text)

        elif name == "lnx_if":
            result["net_if"] = {"up_count": parse_lnx_if_upcount(lines)}

        elif name == "postfix_mailq":
            q = parse_postfix_mailq(lines)
            result["postfix"] = {"queue_length": q}

        # You can add more section decoders here if needed.

        i += 1

    # Convenience summaries
    if "df" in result:
        try:
            total = sum(x["size_bytes"] for x in result["df"])
            used = sum(x["used_bytes"] for x in result["df"])
            result["df_summary"] = {
                "total_bytes": total,
                "used_bytes": used,
                "used_pct": round(100.0 * used / total, 2) if total else None,
            }
        except Exception:
            pass

    if "mem" in result:
        m = result["mem"]
        total = m.get("MemTotal")
        free = m.get("MemFree")
        cached = m.get("Cached")
        if total and free is not None and cached is not None:
            used = total - free - cached
            result["mem_summary"] = {
                "total_bytes": total,
                "used_bytes": used,
                "used_pct": round(100.0 * used / total, 2),
            }

    # Zpool derived summary
    if "zpool" in result:
        pools = result["zpool"] or {}
        worst = None
        unhealthy = 0
        for name, data in pools.items():
            cap = data.get("cap_pct")
            health = (data.get("health") or "").upper()
            if isinstance(cap, (int, float)):
                worst = cap if worst is None else max(worst, cap)
            if health and health not in ("ONLINE", "HEALTHY"):
                unhealthy += 1
        result["zpool_summary"] = {"worst_cap_pct": worst, "unhealthy_count": unhealthy}

    # Normalize key names for ARC sizes to *_bytes for metric picker
    if "zfs_arc_cache" in result:
        arc = result["zfs_arc_cache"]
        # ensure numeric type for size-like fields
        for k in ("size", "compressed_size", "uncompressed_size", "l2_size", "l2_asize"):
            v = arc.get(k)
            try:
                if isinstance(v, str) and v.isdigit():
                    arc[k] = int(v)
            except Exception:
                pass

    # Convenience dataset summaries (no change to existing returns, just keep as is)
    # (No code needed here per instructions)

    return result


def main():
    ap = argparse.ArgumentParser(description="Fetch and parse Checkmk agent output from Open-E. Supports JSON, single-value outputs, and a rich set of --metric selections (see --metric help).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--input-file", help="Parse from local file (saved agent output)")
    src.add_argument("--host", help="SSH host/IP of Open-E")

    ap.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    ap.add_argument("--user", default="cli", help="SSH username (default: cli)")
    ap.add_argument("--identity", help="Path to SSH private key (required if using --host)")
    ap.add_argument("--command", default="check_mk_agent", help="Remote command to run")
    ap.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds")
    ap.add_argument("--ssh-opt", action="append", default=[], help="Extra -o options (e.g. 'HostKeyAlgorithms=+ssh-rsa')")

    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    ap.add_argument("--format", choices=["json", "value", "kv", "nagios"], default="json",
                    help="Output format. 'json' (default) prints the full parsed JSON. 'value' prints only the metric value. 'kv' prints 'name=value'. 'nagios' prints a single-line status with perfdata (requires --metric).")
    ap.add_argument(
        "--metric",
        help=(
            "Select a specific metric to output. "
            "The special metric 'all_datasets' returns a JSON structure with every dataset's usage/quota.\n\n"
            + METRIC_HELP_TEXT
        ),
    )
    ap.add_argument("--mount", help="Mountpoint for fs_* metrics (use with --metric fs_used_pct).")
    ap.add_argument("--fs", help="Filesystem/device name for fs_* metrics (alternative to --mount).")
    ap.add_argument("--dataset", help="ZFS dataset name for dataset_* metrics.")
    ap.add_argument("--pool", help="ZFS pool name for zpool_* metrics.")
    ap.add_argument("--warn", type=float, help="Warning threshold (used with --format nagios).")
    ap.add_argument("--crit", type=float, help="Critical threshold (used with --format nagios).")

    args = ap.parse_args()

    if args.input_file:
        raw = read_input(args.input_file)
    else:
        if not args.identity:
            ap.error("--identity is required when using --host")
        raw = run_ssh(
            host=args.host,
            port=args.port,
            user=args.user,
            identity=os.path.expanduser(args.identity),
            command=args.command,
            extra_ssh_opts=args.ssh_opt or [],
            timeout=args.timeout,
        )

    parsed = parse_agent_output(raw)

    # If a specific metric is requested, extract it
    if args.metric:
        label, value = pick_metric_value(parsed, args)
        # Special handling for the composite 'all_datasets' metric
        if args.metric == "all_datasets":
            entries = value if isinstance(value, list) else []
            if args.format == "json":
                out = {"metric": label, "value": entries, "source": "agent"}
                print(json.dumps(out, indent=2 if args.pretty else None))
                return
            # derive worst used_pct among datasets (quota-backed or df-capacity fallback)
            usable = [(e["dataset"], e.get("used_pct")) for e in entries if e.get("used_pct") is not None]
            if not usable:
                if args.format == "nagios":
                    print("UNKNOWN - no datasets with capacity info found | worst_dataset_used_pct=NaN;;;;")
                    sys.exit(3)
                elif args.format == "kv":
                    print("worst_dataset_used_pct=NaN")
                    return
                else:
                    print("NaN")
                    return
            worst_ds, worst_pct = max(usable, key=lambda t: t[1])
            if args.format == "value":
                print(f"{worst_pct}")
                return
            if args.format == "kv":
                print(f"worst_dataset_used_pct={worst_pct}")
                return
            if args.format == "nagios":
                state = 0
                warn = args.warn
                crit = args.crit
                if crit is not None and worst_pct >= crit:
                    state = 2
                elif warn is not None and worst_pct >= warn:
                    state = 1
                text = ["OK", "WARNING", "CRITICAL", "UNKNOWN"][state]
                # Build perfdata for each dataset as dsname_used_pct
                perf_parts = []
                for ds, pct in usable:
                    lbl = _sanitize_label(f"{ds}_used_pct")
                    perf_parts.append(f"{lbl}={pct};{'' if warn is None else warn};{'' if crit is None else crit}")
                # Also include a summary 'worst_dataset_used_pct'
                perf_parts.append(f"worst_dataset_used_pct={worst_pct};{'' if warn is None else warn};{'' if crit is None else crit}")
                print(f"{text} - worst dataset {worst_ds} at {worst_pct}% | " + " ".join(perf_parts))
                sys.exit(state)
                return

        # Special handling for the unified 'load' metric
        if args.metric == "load":
            cpu = parsed.get("cpu", {}) or {}
            l1 = cpu.get("load1")
            l5 = cpu.get("load5")
            l15 = cpu.get("load15")
            # JSON returns all three values
            if args.format == "json":
                out = {"metric": "load", "value": {"load1": l1, "load5": l5, "load15": l15}, "source": "agent"}
                print(json.dumps(out, indent=2 if args.pretty else None))
                return
            # KV prints all three keys
            if args.format == "kv":
                parts = []
                parts.append(f"load1={l1 if l1 is not None else 'NaN'}")
                parts.append(f"load5={l5 if l5 is not None else 'NaN'}")
                parts.append(f"load15={l15 if l15 is not None else 'NaN'}")
                print(" ".join(parts))
                return
            # Nagios: evaluate thresholds against load1, but expose all three as perfdata
            if args.format == "nagios":
                value = l1
                if value is None:
                    print("UNKNOWN - load not available | load1=NaN;;;; load5=NaN;;;; load15=NaN;;;;")
                    sys.exit(3)
                state = 0
                warn = args.warn
                crit = args.crit
                if crit is not None and value >= crit:
                    state = 2
                elif warn is not None and value >= warn:
                    state = 1
                text = ["OK", "WARNING", "CRITICAL", "UNKNOWN"][state]
                w = "" if warn is None else warn
                c = "" if crit is None else crit
                perf = [
                    f"load1={value};{w};{c}",
                    f"load5={l5 if l5 is not None else 'NaN'};{w};{c}",
                    f"load15={l15 if l15 is not None else 'NaN'};{w};{c}",
                ]
                print(f"{text} - load={value} | " + " ".join(perf))
                sys.exit(state)
                return
            # For 'value' (and any other fallthrough), we already picked load1 in pick_metric_value

        if args.format == "json":
            out = {"metric": label, "value": value, "source": "agent", "context": {
                "mount": args.mount, "fs": args.fs, "dataset": args.dataset
            }}
            print(json.dumps(out, indent=2 if args.pretty else None))
            return
        if value is None:
            if args.format == "nagios":
                print(f"UNKNOWN - {label} not available | {label}=NaN;;;;")
                sys.exit(3)
            elif args.format == "kv":
                print(f"{label}=NaN")
                return
            else:
                print("NaN")
                return

        if args.format == "value":
            # raw numeric value
            print(f"{value}")
            return

        if args.format == "kv":
            print(f"{label}={value}")
            return

        if args.format == "nagios":
            # Higher-is-bad by default, except for availability we might invert later if needed.
            state = 0
            warn = args.warn
            crit = args.crit
            if crit is not None and value >= crit:
                state = 2
            elif warn is not None and value >= warn:
                state = 1
            text = ["OK", "WARNING", "CRITICAL", "UNKNOWN"][state]
            # Emit perfdata with warn/crit if provided
            w = "" if warn is None else warn
            c = "" if crit is None else crit
            print(f"{text} - {label}={value} | {label}={value};{w};{c}")
            sys.exit(state)
            return

    # Default behavior: dump full JSON like before
    if args.pretty or args.format == "json":
        print(json.dumps(parsed, indent=2 if args.pretty else None, sort_keys=True))
    else:
        print(json.dumps(parsed))


if __name__ == "__main__":
    main()
