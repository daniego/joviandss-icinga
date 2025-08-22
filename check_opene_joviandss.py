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



SECTION_RE = re.compile(r"<<<(?P<name>[^>]+)>>>")

# Helper to sanitize perfdata labels
def _sanitize_label(s: str) -> str:
    # For perfdata labels: replace non-alnum/underscore with underscore
    return re.sub(r'[^A-Za-z0-9_]+', '_', s)

# Threshold evaluator: handles higher-is-bad (default) and a few lower-is-bad metrics
def _eval_thresh(metric_name: str, value: float, warn: float, crit: float) -> int:
    """
    Return Nagios state code 0/1/2 for OK/WARNING/CRITICAL based on thresholds.
    By default, higher values are worse (>= crit => CRITICAL, >= warn => WARNING).
    For metrics where lower is worse (e.g., cache hit ratios), invert the logic.
    Also treat warn==0 specially so that value==0 stays OK.
    """
    if value is None:
        return 3

    LOWER_IS_BAD = {"arc_hit_ratio", "l2_hit_ratio", "uptime_hours"}

    if metric_name in LOWER_IS_BAD:
        if crit is not None and value <= crit:
            return 2
        if warn is not None and value <= warn:
            return 1
        return 0

    # Default: higher is bad
    if crit is not None and value >= crit:
        return 2
    if warn is not None:
        if warn == 0 and value == 0:
            return 0
        if value >= warn:
            return 1
    return 0


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
    Parse the compact zpool summary table (with headers like:
    name size alloc free frag cap dedup health altroot)
    Returns mapping: {pool_name: {"cap_pct": float, "health": str, "size": str, ...}}
    Numeric percentages are returned without the '%' sign as floats.

    This version is resilient to header variations such as 'cap', 'cap%',
    'capacity', or vendor-specific labels, and will also fall back to:
      1) locating the column whose header contains 'cap'
      2) selecting the last percentage-looking token in the row
      3) accepting numbers without a trailing '%'
      4) computing cap_pct from alloc/size when possible
    It also tolerates comma decimal separators (e.g. '12,3%').
    """
    pools: Dict[str, Dict[str, Any]] = {}
    header = None
    header_lower = None

    def _norm_num_token(tok: str) -> str:
        """Normalize localized numeric tokens (convert commas to dots, strip %)."""
        if not isinstance(tok, str):
            return None
        s = tok.strip()
        # strip trailing percent and spaces
        if s.endswith("%"):
            s = s[:-1].strip()
        # replace comma decimal with dot
        s = s.replace(",", ".")
        return s

    def _tok_to_pct_loose(tok: str):
        """Accept tokens like '12%', '12.3%', '12,3%', or just '12'/'12.3'."""
        if not isinstance(tok, str):
            return None
        s = _norm_num_token(tok)
        if s is None:
            return None
        try:
            # Some pools may print '-' or 'na'
            if s in ("-", "na", "n/a", "NA", "N/A", ""):  # ignore
                return None
            val = float(s)
            # Cap percentages should be 0..100, tolerate a tiny bit over
            if 0.0 <= val <= 101.0:
                return round(val, 2)
        except Exception:
            pass
        return None

    for line in block:
        # Skip accidental embedded section tags (if splitting ever misses them)
        if line.strip().startswith("<<<") and line.strip().endswith(">>>"):
            continue
        if not line.strip():
            continue
        parts = line.split()
        if not parts:
            continue

        lparts = [p.lower() for p in parts]
        # detect header row (case-insensitive). Accept 'name' or 'pool' and require 'health'.
        if (("name" in lparts) or ("pool" in lparts)) and ("health" in lparts):
            header = parts
            header_lower = lparts
            continue
        if header is None:
            # skip until header found
            continue

        # Require at least 3 tokens in data rows (name + at least two columns)
        if len(parts) < 3:
            continue

        row = parts
        name = row[0]

        # Build a dict aligning by index when header is known, using lowercase keys
        data: Dict[str, Any] = {}
        for i, h in enumerate(header[1:], start=1):
            if i < len(row):
                data[h.lower()] = row[i]

        # Try to find the capacity (%) column robustly
        cap_pct = None

        # 1) Prefer header that contains 'cap'
        cap_idx = None
        for i, h in enumerate(header):
            if "cap" in h.lower():
                cap_idx = i
                break

        def _parse_cap_token(tok: str):
            """Parse CAP token strictly as a percentage. Accept '12%', '12.3%', '12,3%' or bare numbers that are clearly percentages.
            If a bare number is in [0,1], treat it as a ratio and scale by 100.
            Reject tokens with non-numeric suffixes like '1.00x'."""
            if not isinstance(tok, str):
                return None
            s = tok.strip()
            # quick reject common non-percentage CAP-adjacent tokens
            if s.lower().endswith("x"):  # e.g., '1.00x' (dedup ratio)
                return None
            if s in ("-", "na", "n/a", "", "NA", "N/A"):
                return None
            had_percent = s.endswith("%")
            s = s[:-1] if had_percent else s
            s = s.replace(",", ".")
            # Reject if contains any alpha after stripping % (prevents units like 'T', 'G')
            if re.search(r"[A-Za-z]", s):
                return None
            try:
                v = float(s)
            except Exception:
                return None
            # If we saw a percent sign, accept in 0..101
            if had_percent:
                if 0.0 <= v <= 101.0:
                    return round(v, 2)
                return None
            # No percent sign: interpret heuristically
            # - values in [0,1] -> ratio -> scale to %
            # - values in (1, 101] -> already a percent
            if 0.0 <= v <= 1.0:
                return round(v * 100.0, 2)
            if 0.0 < v <= 101.0:
                return round(v, 2)
            return None

        # Parse from the CAP column if we found one
        if cap_idx is not None and cap_idx < len(row):
            cap_pct = _parse_cap_token(row[cap_idx])
            # Some odd outputs split CAP value across columns; try neighbors if needed
            if cap_pct is None:
                if cap_idx + 1 < len(row):
                    cap_pct = _parse_cap_token(row[cap_idx + 1])
                if cap_pct is None and cap_idx > 0:
                    cap_pct = _parse_cap_token(row[cap_idx - 1])

        # 2) Fallback to dict keys that look like capacity
        if cap_pct is None:
            for key in list(data.keys()):
                lk = key.lower()
                if lk in ("cap", "cap%", "capacity", "ckcap", "ckcap%"):
                    cap_pct = _parse_cap_token(str(data[key]))
                    if cap_pct is not None:
                        break

        # 3) Final fallback: compute from alloc/size
        if cap_pct is None:
            size_idx = None
            alloc_idx = None
            for i2, h2 in enumerate(header):
                hl2 = h2.lower()
                if size_idx is None and "size" in hl2:
                    size_idx = i2
                if alloc_idx is None and ("alloc" in hl2 or "allocated" in hl2):
                    alloc_idx = i2
            try:
                if size_idx is not None and alloc_idx is not None and size_idx < len(row) and alloc_idx < len(row):
                    size_b = parse_size_to_bytes(row[size_idx])
                    alloc_b = parse_size_to_bytes(row[alloc_idx])
                    if size_b and alloc_b is not None and size_b > 0:
                        cap_pct = round(100.0 * float(alloc_b) / float(size_b), 2)
            except Exception:
                pass

        # Normalize health and clamp cap_pct to [0, 100]
        if "health" in data:
            data["health"] = str(data["health"]).upper()
        if cap_pct is not None:
            try:
                if cap_pct < 0:
                    cap_pct = 0.0
                elif cap_pct > 100:
                    cap_pct = 100.0
            except Exception:
                pass

        # Normalize/derive extra pool fields
        size_b = parse_size_to_bytes(data.get("size")) if "size" in data else None
        alloc_b = parse_size_to_bytes(data.get("alloc")) if "alloc" in data else None
        free_b  = parse_size_to_bytes(data.get("free"))  if "free"  in data else None

        # FRAG to percent
        frag_pct = None
        if "frag" in data and isinstance(data["frag"], str):
            m = re.match(r"^\s*([0-9]*\.?[0-9]+)\s*%?\s*$", data["frag"])
            if m:
                try:
                    frag_pct = float(m.group(1))
                except Exception:
                    frag_pct = None

        # DEDUP to float (strip trailing 'x')
        dedup_ratio = None
        if "dedup" in data and isinstance(data["dedup"], str):
            s = data["dedup"].strip()
            if s.lower().endswith("x"):
                s = s[:-1]
            s = s.replace(",", ".")
            try:
                dedup_ratio = float(s)
            except Exception:
                dedup_ratio = None

        if size_b is not None:   data["size_bytes"]  = size_b
        if alloc_b is not None:  data["alloc_bytes"] = alloc_b
        if free_b is not None:   data["free_bytes"]  = free_b
        if frag_pct is not None: data["frag_pct"]    = frag_pct
        if dedup_ratio is not None: data["dedup_ratio"] = dedup_ratio

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


# ----------- HA/Pacemaker and Checkmk helpers -----------

def parse_check_mk_info(block: List[str]) -> Dict[str, Any]:
    """
    Parse the generic check_mk info block to extract the local hostname and misc fields.
    Looks for lines like "Hostname: <name>" or "host_name <name>".
    Returns keys: hostname (str|None).
    """
    info: Dict[str, Any] = {"hostname": None}
    for line in block:
        s = line.strip()
        if not s:
            continue
        # Common formats
        m = re.search(r"Hostname:\s*(\S+)", s, re.IGNORECASE)
        if m:
            info["hostname"] = m.group(1)
            continue
        m = re.search(r"host_name\s+(\S+)", s, re.IGNORECASE)
        if m and not info.get("hostname"):
            info["hostname"] = m.group(1)
            continue
    return info


def parse_heartbeat_crm(block: List[str]) -> Dict[str, Any]:
    """
    Parse Pacemaker/CRM summary from the <<<heartbeat_crm>>> section.
    Extract online nodes and where resources are started. Example lines:
      "Online: [ nw-oe01 nw-oe02 ]"
      "resource zpool-nas Started nw-oe01"
    Returns: {"online_nodes": [...], "resources": {res_name: node_started}, "started_counts": {node: cnt}}
    """
    online_nodes: List[str] = []
    resources: Dict[str, str] = {}
    started_counts: Dict[str, int] = {}

    for line in block:
        s = line.strip()
        if not s:
            continue
        # Online nodes line
        m = re.search(r"Online:\s*\[(.*?)\]", s, re.IGNORECASE)
        if m:
            inside = m.group(1).strip()
            if inside:
                online_nodes = [tok for tok in inside.split() if tok]
            continue
        # Resource started matcher
        m = re.search(r"^(?P<res>\S.*?)\s+Started\s+(?P<node>\S+)$", s, re.IGNORECASE)
        if m:
            res = m.group("res").strip()
            node = m.group("node").strip()
            resources[res] = node
            started_counts[node] = started_counts.get(node, 0) + 1
            continue
    return {"online_nodes": online_nodes, "resources": resources, "started_counts": started_counts}


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
                    # Prefer df's own percentage if available to avoid unit mismatches
                    df_pct = row.get("use_percent")
                    used_pct = float(df_pct) if df_pct is not None else (round(100.0 * used / size, 2) if size else None)
                    return {"used_bytes": used, "quota_bytes": size, "used_pct": used_pct}
        return {}
    props = zfsget[dataset]
    # Determine quotas
    refquota_b = None
    quota_b = None
    if "refquota" in props:
        refquota_b = props["refquota"].get("bytes")
    if "quota" in props:
        quota_b = props["quota"].get("bytes")

    # Select denominator and matching usage:
    #  - If refquota is set (>0): use referenced (or usedbydataset as fallback)
    #  - Else if quota is set (>0): use used (or usedbydataset as fallback)
    used_b = None
    denom = None
    if refquota_b and refquota_b > 0:
        denom = refquota_b
        if "referenced" in props and props["referenced"].get("bytes") is not None:
            used_b = props["referenced"].get("bytes")
        elif "usedbydataset" in props and props["usedbydataset"].get("bytes") is not None:
            used_b = props["usedbydataset"].get("bytes")
        else:
            used_b = props.get("used", {}).get("bytes")
    elif quota_b and quota_b > 0:
        denom = quota_b
        if "used" in props and props["used"].get("bytes") is not None:
            used_b = props["used"].get("bytes")
        elif "usedbydataset" in props and props["usedbydataset"].get("bytes") is not None:
            used_b = props["usedbydataset"].get("bytes")
        else:
            used_b = props.get("referenced", {}).get("bytes")
    else:
        denom = None  # no quota present; we may fall back to df below
    # Fallback: if no quota, try capacity from df using mountpoint
    capacity_b = None
    df_pct = None
    df_used_b = None
    df_size_b = None
    if denom is None and props.get("mountpoint", {}).get("value") not in (None, "none", "-", "legacy"):
        mnt = props.get("mountpoint", {}).get("value")
        if df_rows:
            for row in df_rows:
                if row.get("mountpoint") == mnt:
                    capacity_b = row.get("size_bytes")
                    # If we don't have used bytes yet, use df used
                    if used_b is None:
                        used_b = row.get("used_bytes")
                    df_pct = row.get("use_percent")
                    df_used_b = row.get("used_bytes")
                    df_size_b = row.get("size_bytes")
                    break
    # Compute percent strictly from the chosen denominator
    used_pct = None
    if denom and denom > 0 and used_b is not None:
        try:
            used_pct = round(100.0 * float(used_b) / float(denom), 2)
        except Exception:
            used_pct = None

    # If no quota-derived denominator, and we fell back to df capacity, prefer df's percent
    if denom is None and capacity_b is not None:
        if df_pct is not None:
            try:
                used_pct = float(df_pct)
            except Exception:
                used_pct = used_pct
        elif df_used_b is not None and df_size_b:
            try:
                used_pct = round(100.0 * float(df_used_b) / float(df_size_b), 2)
            except Exception:
                pass

    return {"used_bytes": used_b, "quota_bytes": denom or capacity_b, "used_pct": used_pct}

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
        df_pct = row.get("use_percent")
        used_pct = float(df_pct) if df_pct is not None else (round(100.0 * used / size, 2) if size else None)
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
    "  Uptime: uptime_hours (unit: hours; lower is bad) | uptime_seconds | idle_seconds (unit: seconds)\n"
    "  Memory: mem_used_pct (unit: %) | mem_used_bytes (unit: B) | mem_total_bytes (unit: B)\n"
    "  Processes: process_count (unit: count)\n"
    "  TCP connections: tcp_established | tcp_syn_sent | tcp_syn_recv | tcp_fin_wait1 | tcp_fin_wait2 | tcp_time_wait | tcp_close | tcp_close_wait | tcp_last_ack | tcp_listen | tcp_closing (unit: sockets)\n"
    "  Filesystem-by-mount or fs name (require --mount or --fs). If omitted, fs_used_pct defaults to the worst-used filesystem:\n"
    "    fs_used_pct (unit: %) | fs_used_bytes (unit: B) | fs_total_bytes (unit: B) | fs_avail_bytes (unit: B)\n"
    "  Filesystem summary (across all filesystems):\n"
    "    df_used_pct (unit: %) | df_used_bytes (unit: B) | df_total_bytes (unit: B) | filesystem_count (unit: count)\n"
    "  ZFS ARC cache: arc_size_bytes | arc_compressed_size_bytes | arc_uncompressed_size_bytes | l2_size_bytes | l2_asize_bytes | arc_hit_ratio (unit: %, warn/crit are minimums) | l2_hit_ratio (unit: %, warn/crit are minimums)\n"
    "  ZFS pools: zpool_worst_cap_pct (unit: %, Nagios includes per-pool SIZE/ALLOC/FREE/FRAG/CAP/DEDUP/HEALTH text + perfdata) | zpool_unhealthy_count (unit: pools) | zpool_pool_cap_pct (requires --pool, unit: %)\n"
    "  ZFS datasets (require --dataset for a specific dataset). If omitted, dataset_* defaults to the worst-used dataset:\n"
    "    dataset_used_pct (unit: %) | dataset_used_bytes (unit: B) | dataset_quota_bytes (unit: B) | all_datasets\n"
    "  High Availability (Pacemaker/CRM): ha_role (unit: string: active|passive|unknown) | ha_resources_on_local (unit: count)\n"
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
    if m == "uptime_hours":
        val = parsed.get("uptime", {}).get("uptime_seconds")
        if val is not None:
            return ("uptime_hours", float(val) / 3600.0)
        return ("uptime_hours", None)
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
        # Fallback for fs_used_pct: if no selector provided, pick the worst-used filesystem
        if not row and m == "fs_used_pct":
            rows = parsed.get("df", []) or []
            if rows:
                row = max(rows, key=lambda r: (r.get("use_percent") is not None, r.get("use_percent", -1)))
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
        if args.dataset:
            usage = dataset_usage_from_zfsget(parsed.get("zfsget", {}), args.dataset, df_rows=parsed.get("df", []))
        else:
            # Fallback to worst-used dataset across all
            entries = all_datasets_usage(parsed.get("zfsget", {}), df_rows=parsed.get("df", []))
            usage = None
            if entries:
                # choose by used_pct if available; otherwise by used_bytes
                def _score(e):
                    up = e.get("used_pct")
                    return (up is not None, up if up is not None else -1, e.get("used_bytes") or -1)
                worst = max(entries, key=_score)
                usage = worst
        if not usage:
            return (m, None)
        if m == "dataset_used_pct":
            v = usage.get("used_pct")
            return (m, float(v)) if v is not None else (m, None)
        if m == "dataset_used_bytes":
            v = usage.get("used_bytes")
            return (m, float(v)) if v is not None else (m, None)
        if m == "dataset_quota_bytes":
            v = usage.get("quota_bytes")
            return (m, float(v)) if v is not None else (m, None)

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

    # HA metrics
    if m == "ha_role":
        val = (parsed.get("ha") or {}).get("role")
        # For value-like outputs we keep it string; Nagios/KV handled later
        return (m, val)
    if m == "ha_resources_on_local":
        val = (parsed.get("ha") or {}).get("resources_on_local")
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

        elif name == "check_mk":
            result["check_mk"] = parse_check_mk_info(lines)

        elif name == "heartbeat_crm":
            result["heartbeat_crm"] = parse_heartbeat_crm(lines)

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
            # Accept numeric cap only, clamp to [0, 100]
            capf = None
            try:
                if isinstance(cap, str):
                    cap = cap.replace(",", ".").rstrip("% ")
                    if re.search(r"[A-Za-z]", cap):
                        cap = None
                if cap is not None and cap != "":
                    capf = float(cap)
                    if capf < 0:
                        capf = 0.0
                    elif capf > 100:
                        capf = 100.0
            except Exception:
                capf = None
            if capf is not None:
                worst = capf if worst is None else max(worst, capf)
            if health and health not in ("ONLINE", "HEALTHY"):
                unhealthy += 1
        result["zpool_summary"] = {"worst_cap_pct": worst, "unhealthy_count": unhealthy}

    # HA role derivation (active/passive/unknown)
    # Prefer heartbeat_crm if available; fallback to presence/absence of imported zpools
    local_host = ((result.get("check_mk") or {}).get("hostname"))
    crm = result.get("heartbeat_crm") or {}
    role = "unknown"
    resources_on_local = None

    if crm:
        started_counts = crm.get("started_counts") or {}
        if local_host and local_host in started_counts:
            resources_on_local = started_counts.get(local_host, 0)
            role = "active" if resources_on_local > 0 else "passive"
        else:
            # If we don't know local_host, pick the node with most started resources; if tied, unknown
            if started_counts:
                # find max
                max_node = max(started_counts.items(), key=lambda kv: kv[1])
                # If zpool section suggests active here, we can still hint
                if (result.get("zpool") or {}):
                    role = "active"
                else:
                    role = "passive" if max_node[1] == 0 else "unknown"
                resources_on_local = None
    # Fallback heuristic if no CRM data
    if role == "unknown":
        if result.get("zpool"):
            role = "active"
            resources_on_local = resources_on_local if resources_on_local is not None else 0
        else:
            # If zpool says "no pools available" it is typically the passive node
            role = "passive"
            resources_on_local = resources_on_local if resources_on_local is not None else 0

    result["ha"] = {"role": role, "resources_on_local": resources_on_local}

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
    ap = argparse.ArgumentParser(description="Fetch and parse Checkmk agent output from Open-E. Supports JSON, single-value outputs, and a rich set of --metric selections (CPU, memory, filesystems, ZFS pools/datasets/ARC, TCP, Postfix, and HA via Pacemaker/CRM).")
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
                warn = args.warn
                crit = args.crit
                state = _eval_thresh("load", value, warn, crit)
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

        # Special handling for HA role metric
        if args.metric == "ha_role":
            ha = parsed.get("ha") or {}
            role = ha.get("role")
            res_cnt = ha.get("resources_on_local")
            if args.format == "json":
                out = {"metric": "ha_role", "value": role, "source": "agent", "context": {"resources_on_local": res_cnt}}
                print(json.dumps(out, indent=2 if args.pretty else None))
                return
            if role is None:
                if args.format == "nagios":
                    print("UNKNOWN - ha_role not available | ha_resources_on_local=NaN;;;;")
                    sys.exit(3)
                elif args.format == "kv":
                    print("ha_role=NaN")
                    return
                else:
                    print("NaN")
                    return
            if args.format == "kv":
                print(f"ha_role={role}")
                return
            if args.format == "nagios":
                # For HA role there is no warn/crit; always OK if known
                state = 0
                text = ["OK", "WARNING", "CRITICAL", "UNKNOWN"][state]
                perf = []
                if res_cnt is not None:
                    perf.append(f"ha_resources_on_local={res_cnt};;;\;")
                print(f"{text} - ha_role={role} | " + (" ".join(perf) if perf else ""))
                sys.exit(state)
                return
            # value format: print the string
            print(role)
            return

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

        # Special Nagios formatting for zpool_worst_cap_pct: include per-pool details & perfdata
        if args.metric == "zpool_worst_cap_pct" and args.format == "nagios":
            pools = parsed.get("zpool") or {}
            if value is None or not pools:
                print("UNKNOWN - zpool_worst_cap_pct not available | zpool_worst_cap_pct=NaN;;;;")
                sys.exit(3)

            # Identify worst pool by CAP
            worst_name, worst_val = None, None
            for pname, pdata in pools.items():
                cap = pdata.get("cap_pct")
                try:
                    capf = float(cap) if cap is not None else None
                except Exception:
                    capf = None
                if capf is not None and (worst_val is None or capf > worst_val):
                    worst_name, worst_val = pname, capf
            if worst_val is None:
                worst_val = float(value)

            warn, crit = args.warn, args.crit
            state = _eval_thresh("zpool_worst_cap_pct", worst_val, warn, crit)
            text = ["OK", "WARNING", "CRITICAL", "UNKNOWN"][state]
            w = "" if warn is None else warn
            c = "" if crit is None else crit

            # Human summary and perfdata
            human_bits = []
            perf = [f"zpool_worst_cap_pct={worst_val};{w};{c}"]

            for pname, pdata in pools.items():
                # Only include entries that look like real zpool rows (must have SIZE/ALLOC/FREE or CAP)
                looks_like_pool = any(k in pdata for k in ("size", "alloc", "free", "cap", "cap_pct"))
                if not looks_like_pool:
                    continue
                base = _sanitize_label(pname)

                cap   = pdata.get("cap_pct")
                frag  = pdata.get("frag_pct")
                dedup = pdata.get("dedup_ratio")
                sizeb = pdata.get("size_bytes")
                alloc = pdata.get("alloc_bytes")
                freeb = pdata.get("free_bytes")

                ckpoint  = pdata.get("ckpoint")  or "-"
                expandsz = pdata.get("expandsz") or "-"
                health   = pdata.get("health")   or "NA"
                altroot  = pdata.get("altroot")  or "-"

                human_bits.append(
                    f"{pname} SIZE={pdata.get('size','-')} ALLOC={pdata.get('alloc','-')} FREE={pdata.get('free','-')} "
                    f"CKPOINT={ckpoint} EXPANDSZ={expandsz} FRAG={pdata.get('frag','-')} CAP={pdata.get('cap','-')} "
                    f"DEDUP={pdata.get('dedup','-')} HEALTH={health} ALTROOT={altroot}"
                )

                if cap   is not None: perf.append(f"{base}_cap_pct={cap};{w};{c}")
                if frag  is not None: perf.append(f"{base}_frag_pct={frag};;;")
                if dedup is not None: perf.append(f"{base}_dedup_ratio={dedup};;;")
                if sizeb is not None: perf.append(f"{base}_size_bytes={int(sizeb)}B;;;")
                if alloc is not None: perf.append(f"{base}_alloc_bytes={int(alloc)}B;;;")
                if freeb is not None: perf.append(f"{base}_free_bytes={int(freeb)}B;;;")

            summary_text = " || ".join(human_bits)
            print(f"{text} - worst pool {worst_name} at {worst_val}% :: {summary_text} | " + " ".join(perf))
            sys.exit(state)
            return

        if args.format == "nagios":
            warn = args.warn
            crit = args.crit
            state = _eval_thresh(label, value, warn, crit)
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
