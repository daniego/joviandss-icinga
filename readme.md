# joviandss-icinga

Monitoring plugin for Open-E JovianDSS systems, using the embedded
Checkmk agent output over SSH.
It allows you to collect metrics like CPU, memory, uptime, processes, filesystems, and ZFS dataset usage,
and expose them in a format compatible with Icinga2 (Nagios plugin style).

## Features

- Fetch agent data via SSH (`check_mk_agent`).
- Parse and extract structured JSON for:
  - CPU load averages
  - Uptime
  - Memory usage
  - Process counts
  - Filesystem usage (per mount, per fs, or aggregated)
  - ZFS dataset usage (quota-aware, with df fallback)
  - High Availability (Pacemaker/CRM) role detection (active/passive) and resource counts
  - Plugins/inventory
- Flexible output formats:
  - `json` — full parsed JSON
  - `value` — raw metric value
  - `kv` — key=value pairs
  - `nagios` — single-line status with perfdata for Icinga2/Nagios

## Requirements

- Python 3.7+
- SSH access to the JovianDSS node with the `cli` user (and private key).
- `check_mk_agent` available on the target system (standard in JovianDSS).

## Usage

### Fetch via SSH

```bash
python3 check_opene_joviandss.py \
  --host 10.10.42.10 \
  --port 22224 \
  --user cli \
  --identity ~/Downloads/DEV-OE01.key \
  --command check_mk_agent \
  --metric mem_used_pct \
  --format nagios --warn 80 --crit 90
```

### Parse from a saved file

```bash
python3 check_opene_joviandss.py --input-file samples/checkmk_output.txt --metric load1 --format value
```


### Available Metrics

- **CPU:**
  - `load` (unit: load average, includes load1/load5/load15; thresholds apply to load1)
- **Uptime:**
  - `uptime_seconds`, `idle_seconds` (unit: seconds)
  - `uptime_hosurs`, `idle_hours` (unit: hours)
- **Memory:**
  - `mem_used_pct` (unit: %)
  - `mem_used_bytes`, `mem_total_bytes` (unit: bytes)
- **Processes:**
  - `process_count` (unit: count)
- **Filesystem by mount/fs** (requires `--mount` or `--fs`):
  - `fs_used_pct` (unit: %)
  - `fs_used_bytes`, `fs_total_bytes`, `fs_avail_bytes` (unit: bytes)
- **Filesystem summary (all filesystems):**
  - `df_used_pct` (unit: %)
  - `df_used_bytes`, `df_total_bytes` (unit: bytes)
  - `filesystem_count` (unit: count)
- **ZFS datasets:**
  - `dataset_used_pct` (unit: %)
  - `dataset_used_bytes`, `dataset_quota_bytes` (unit: bytes)
  - `all_datasets` (unit: list / % when summarized)

- **High Availability (Pacemaker/CRM):**
  - `ha_role` (unit: string: active|passive|unknown)
  - `ha_resources_on_local` (unit: count)
- **Plugins:**
  - `plugins_count` (unit: count)
- **TCP connections:**
  - `tcp_established`, `tcp_syn_sent`, `tcp_syn_recv`, `tcp_fin_wait1`, `tcp_fin_wait2`, `tcp_time_wait`, `tcp_close`, `tcp_close_wait`, `tcp_last_ack`, `tcp_listen`, `tcp_closing` (unit: sockets)
- **ZFS ARC cache:**
  - `arc_size_bytes`, `arc_compressed_size_bytes`, `arc_uncompressed_size_bytes`, `l2_size_bytes`, `l2_asize_bytes`, `arc_hit_ratio`, `l2_hit_ratio`
    - On passive HA nodes these will return OK with NaN values.
- **ZFS pools:**
  - `zpool_worst_cap_pct`, `zpool_unhealthy_count`, `zpool_pool_cap_pct` (requires --pool)
    - On passive HA nodes `zpool_worst_cap_pct` will return OK with NaN values.
- **Network interfaces:**
  - `net_up_if_count` (unit: count)
- **Mail queue:**
  - `postfix_queue_length` (unit: messages)

### Metrics and Units Table

| Metric               | Description                               | Unit           |
|----------------------|-------------------------------------------|----------------|
| load                 | CPU load average (includes load1/load5/load15; thresholds apply to load1) | load           |
| uptime_seconds       | System uptime                             | seconds        |
| uptime_hours.        | System uptime                             | hours          |
| idle_seconds         | System idle time                          | seconds        |
| mem_used_pct         | Memory used                               | %              |
| mem_used_bytes       | Memory used                               | bytes          |
| mem_total_bytes      | Memory total                              | bytes          |
| process_count        | Number of processes                       | count          |
| fs_used_pct          | Filesystem used                           | %              |
| fs_used_bytes        | Filesystem used                           | bytes          |
| fs_total_bytes       | Filesystem total                          | bytes          |
| fs_avail_bytes       | Filesystem available                      | bytes          |
| df_used_pct          | Total FS used                             | %              |
| df_used_bytes        | Total FS used                             | bytes          |
| df_total_bytes       | Total FS                                  | bytes          |
| filesystem_count     | Filesystem count                          | count          |
| dataset_used_pct     | ZFS dataset used                          | %              |
| dataset_used_bytes   | ZFS dataset used                          | bytes          |
| dataset_quota_bytes  | ZFS dataset quota                         | bytes          |
| all_datasets         | All ZFS datasets (summary/worst %)        | % or list      |
| ha_role             | HA role (active/passive/unknown)          | string        |
| ha_resources_on_local | Number of cluster resources started on this node | count   |
| plugins_count        | Plugins count                             | count          |
| tcp_established      | TCP established connections               | sockets        |
| tcp_syn_sent         | TCP SYN sent connections                   | sockets        |
| tcp_syn_recv         | TCP SYN received connections               | sockets        |
| tcp_fin_wait1        | TCP FIN-WAIT1 connections                  | sockets        |
| tcp_fin_wait2        | TCP FIN-WAIT2 connections                  | sockets        |
| tcp_time_wait        | TCP TIME-WAIT connections                  | sockets        |
| tcp_close            | TCP CLOSE state                            | sockets        |
| tcp_close_wait       | TCP CLOSE-WAIT state                       | sockets        |
| tcp_last_ack         | TCP LAST-ACK state                         | sockets        |
| tcp_listen           | TCP LISTEN sockets                         | sockets        |
| tcp_closing          | TCP CLOSING state                          | sockets        |
| arc_size_bytes       | ZFS ARC size                              | bytes          |
| arc_compressed_size_bytes | ZFS ARC compressed size                 | bytes          |
| arc_uncompressed_size_bytes | ZFS ARC uncompressed size             | bytes          |
| l2_size_bytes        | ZFS L2ARC size                            | bytes          |
| l2_asize_bytes       | ZFS L2ARC allocated size                  | bytes          |
| arc_hit_ratio        | ZFS ARC hit ratio                         | %              |
| l2_hit_ratio         | ZFS L2ARC hit ratio                       | %              |
| zpool_worst_cap_pct  | Worst capacity across pools               | %              |
| zpool_unhealthy_count| Unhealthy pool count                      | pools          |
| zpool_pool_cap_pct   | Capacity of specified pool                | %              |
| net_up_if_count      | Interfaces in UP state                     | count          |
| postfix_queue_length | Postfix queue length                      | messages       |

### Output formats
- `json`: full JSON result
- `value`: print only the numeric value
- `kv`: print as metric=value
- `nagios`: plugin-compatible output with perfdata

### Thresholds
- For the `nagios` format, you can pass `--warn` and `--crit` thresholds.
- Thresholds are evaluated against the main numeric value of the metric.
- For `load`, thresholds apply to the 1-minute load average (`load1`).
- Other metrics (like percentages) compare directly to the numeric value.
- On passive HA nodes, storage-specific metrics like `zpool_worst_cap_pct` and ARC/L2ARC metrics (`arc_hit_ratio`, etc.) are reported as OK (not applicable) instead of UNKNOWN.

### Icinga2 Integration

Example command definition:
```
object CheckCommand "joviandss-metric" {
  import "plugin-check-command"
  command = [ PluginDir + "/check_opene_joviandss.py" ]

  arguments += {
    "--host" = "$joviandss_host$"
    "--port" = "$joviandss_port$"
    "--user" = "$joviandss_user$"
    "--identity" = "$joviandss_identity$"
    "--ssh-opt" = {
        value = "$joviandss_ssh_opt$"
        repeat_key = true
    }
    "--command" = "check_mk_agent"
    "--metric" = "$joviandss_metric$"
    "--format" = "nagios"
    "--warn" = {
      set_if = "$joviandss_warn$"
      value = "$joviandss_warn$"
    }
    "--crit" = {
      set_if = "$joviandss_crit$"
      value = "$joviandss_crit$"
    }
  }
  vars.joviandss_ssh_opt = [
    "HostKeyAlgorithms=+ssh-rsa",
    "PubkeyAcceptedAlgorithms=+ssh-rsa",
    "IdentitiesOnly=yes",
    "PreferredAuthentications=publickey",
    "StrictHostKeyChecking=accept-new"
  ]
}
```

Example service check:
```
apply Service "joviandss-datasets" {
  import "generic-service"
  check_command = "joviandss-metric"

  vars.joviandss_host = "10.10.42.10"
  vars.joviandss_port = 22224
  vars.joviandss_user = "cli"
  vars.joviandss_identity = "/etc/icinga2/conf.d/DEV-OE01.key"
  vars.joviandss_metric = "all_datasets"
  vars.joviandss_warn = 80
  vars.joviandss_crit = 90

  assign where host.name == "joviandss01"
}
```


You can define additional services for load1, mem_used_pct, etc.

### Development & Testing

Save raw agent output:
```bash
ssh -i ~/Downloads/DEV-OE01.key -p 22224 cli@10.10.42.10 check_mk_agent > samples/output.txt
```

Run parser locally:
```bash
python3 check_opene_joviandss.py --input-file samples/output.txt --metric process_count --format value
```

### License
MIT License. Contributions welcome!
