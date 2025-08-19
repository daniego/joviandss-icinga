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
  - `load1`, `load5`, `load15` (unit: load average)
- **Uptime:**
  - `uptime_seconds`, `idle_seconds` (unit: seconds)
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
- **Plugins:**
  - `plugins_count` (unit: count)

### Metrics and Units Table

| Metric               | Description                               | Unit           |
|----------------------|-------------------------------------------|----------------|
| load1/load5/load15   | CPU load average                          | load           |
| uptime_seconds       | System uptime                             | seconds        |
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
| plugins_count        | Plugins count                             | count          |

### Output formats
- `json`: full JSON result
- `value`: print only the numeric value
- `kv`: print as metric=value
- `nagios`: plugin-compatible output with perfdata

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
    "--command" = "check_mk_agent"
    "--metric" = "$joviandss_metric$"
    "--format" = "nagios"
    "--warn" = "$joviandss_warn$"
    "--crit" = "$joviandss_crit$"
  }
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

