#!/usr/bin/env python3
import subprocess
import argparse
import sys

# Define metrics with their thresholds
metrics = [
    {"name": "load", "warning": 0.5, "critical": 2},
    {"name": "uptime_seconds", "warning": None, "critical": None},
    {"name": "idle_seconds", "warning": None, "critical": None},
    {"name": "mem_used_pct", "warning": 80, "critical": 90},
    {"name": "mem_used_bytes", "warning": None, "critical": None},
    {"name": "mem_total_bytes", "warning": None, "critical": None},
    {"name": "process_count", "warning": 500, "critical": 1000},
    {"name": "fs_used_pct", "warning": 80, "critical": 90},
    {"name": "df_used_pct", "warning": 80, "critical": 90},
    {"name": "filesystem_count", "warning": None, "critical": None},
    {"name": "dataset_used_pct", "warning": 80, "critical": 90},
    {"name": "all_datasets", "warning": 80, "critical": 90},
    {"name": "plugins_count", "warning": None, "critical": None},
    {"name": "tcp_established", "warning": 2000, "critical": 4000},
    {"name": "arc_hit_ratio", "warning": 70, "critical": 50},  # ratio should not drop too low
    {"name": "zpool_worst_cap_pct", "warning": 80, "critical": 90},
    {"name": "zpool_unhealthy_count", "warning": 0, "critical": 1},
    {"name": "net_up_if_count", "warning": None, "critical": None},
    {"name": "postfix_queue_length", "warning": 50, "critical": 200},
]

def run_metric(script, args, metric, warn, crit):
    cmd = [
        sys.executable, script,
        "--host", args.host,
        "--port", str(args.port),
        "--user", args.user,
        "--identity", args.identity,
        "--command", "check_mk_agent",
        "--metric", metric,
        "--format", "nagios",
    ]
    if warn is not None:
        cmd.extend(["--warn", str(warn)])
    if crit is not None:
        cmd.extend(["--crit", str(crit)])

    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return output.strip()
    except subprocess.CalledProcessError as e:
        return f"ERROR ({e.returncode}): {e.output.strip()}"

def main():
    parser = argparse.ArgumentParser(description="Test all JovianDSS metrics with thresholds.")
    parser.add_argument("--script", default="check_opene_joviandss.py", help="Path to the main check script")
    parser.add_argument("--host", required=True, help="Target host")
    parser.add_argument("--port", type=int, default=22224, help="SSH port (default 22224)")
    parser.add_argument("--user", default="cli", help="SSH user (default: cli)")
    parser.add_argument("--identity", required=True, help="Path to SSH private key")
    args = parser.parse_args()

    for m in metrics:
        print(f"=== Testing {m['name']} ===")
        result = run_metric(args.script, args, m["name"], m["warning"], m["critical"])
        print(result)
        print()

if __name__ == "__main__":
    main()
