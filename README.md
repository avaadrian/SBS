# SBS: Linux endpoint detection agent and benchmark

SBS is a small EDR / antivirus agent for Linux, written in Go, plus a benchmark
harness that measures it against safe attack simulations.

- **`sbs-agent`** runs on the host. It watches every process execution and changes to
  sensitive files, scans binaries and dropped files against malware signatures,
  evaluates detection rules, and writes alerts as JSON lines.
- **`sbs-bench`** starts the agent, replays 17 harmless attack simulations mapped
  to MITRE ATT&CK, runs a benign workload, and reports detection rate, time to
  detect, false positives, exec visibility and the agent's CPU and memory cost.

```
                 ┌────────────── sbs-agent ──────────────┐
 kernel netlink ─┤ process collector ─┐                  │
 (or /proc poll) │                    ├─► scanner ─┐     │
 inotify ────────┤ file collector ────┘            ├─► alerts.jsonl
                 │                    └─► rules ───┘     │
                 └───────────────────────────────────────┘
```

## Quick start

Needs Go 1.24+ and Linux. The agent should run as root (or with `CAP_NET_ADMIN`) to get
kernel exec events; without it, it falls back to polling `/proc`.

```sh
make build                       # bin/sbs-agent, bin/sbs-bench (static, no cgo)
sudo ./bin/sbs-agent run         # alerts to stdout, default watch list
sudo ./bin/sbs-agent run -config configs/agent.yaml -alerts /var/log/sbs/alerts.jsonl
./bin/sbs-agent scan /home /tmp  # on-demand antivirus scan, exit 1 on detection
./bin/sbs-agent rules            # list active rules
sudo make bench                  # writes reports/bench.{json,md}
```

To install as a service: copy the binary to `/usr/local/bin`, the config to
`/etc/sbs/agent.yaml`, and `deploy/sbs-agent.service` to `/etc/systemd/system/`.

An alert looks like this:

```json
{"time":"2026-10-09T09:10:01Z","rule_id":"SBS-PROC-003","title":"Shell with network socket on stdin/stdout (reverse shell)",
 "severity":"critical","mitre":["T1059.004","T1071"],
 "event":{"type":"process","source":"netlink","process":{"pid":4121,"ppid":4100,"uid":0,"exe":"/usr/bin/dash",
 "comm":"sh","cmdline":"/bin/sh -i","stdin":"inet","stdout":"inet","remote":"127.0.0.1:41235", "...": "..."}}}
```

## What it detects

| Layer | How | Examples |
|---|---|---|
| Process execution | Netlink process connector (every `exec`), enriched from `/proc`: exe, cmdline, parent, uid, cwd, and whether stdin/stdout is a TCP/UDP socket | reverse shells, `curl … \| sh`, base64 payloads, memfd/fileless execution, running from `/tmp`, `/etc/shadow` access, history and log wiping, SUID chmod, miners, webserver spawning a shell |
| File integrity | inotify on tagged paths | cron/systemd/init persistence, `authorized_keys`, `/etc/ld.so.preload`, passwd/sudoers, executables and SUID files in temp dirs |
| Signatures (AV) | SHA-256 hashes, plus YARA-style string sets (`any`, `all`, `N` of), text or hex, optional case-insensitive | EICAR, coin miners, reverse-shell scripts, Mirai strings, LD_PRELOAD rootkits, PHP webshells |

Every new process's binary is scanned when it runs, and every file written under a
watched path is scanned once it's closed. Results are cached by path, size and mtime.

### Rules

Rules are YAML, Sigma-style. Built-ins live in `assets/rules/` and are compiled into
the binary. Add your own with `rules:` in the config.

```yaml
- id: SBS-PROC-003
  title: Shell with network socket on stdin/stdout (reverse shell)
  severity: critical            # info | low | medium | high | critical
  mitre: [T1059.004, T1071]
  event: process                # process | file
  match:
    all:
      - field: process.name
        value: [sh, bash, dash, zsh, ksh, ash, busybox]
      - any:
          - {field: process.stdin, value: inet}
          - {field: process.stdout, value: inet}
```

Ops: `equals` (default), `contains`, `startswith`, `endswith`, `regex`, `exists`; `nocase: true`;
`value` can be a string or a list (any of). Nodes: `all`, `any`, `not`.

Fields:
`process.{pid,ppid,uid,exe,name,cmdline,cwd,stdin,stdout,remote}`,
`parent.{exe,name,cmdline}`, `file.{path,name,op,tag,size,mode,sha256}`, `event.{type,source}`.
`stdin`/`stdout` are `inet`, `socket` (Unix domain), `pipe`, `tty`, `file`, `null` or `none`.

### Signatures

```yaml
hashes:
  - {sha256: 275a021b…, name: EICAR-Test-File, severity: low}
signatures:
  - name: Linux.CoinMiner.Generic
    severity: high
    nocase: true
    strings: ["stratum+tcp://", "xmrig", "--donate-level", "hex:72616e646f6d78"]
    condition: "2"               # any | all | N
```

## Benchmark

`sbs-bench` must run as root. Everything it does is harmless: network targets are
`127.0.0.1` (usually a closed port), files go only into a temp sandbox whose
directories carry the same tags as the real persistence locations, the reverse
shell connects to a listener inside the benchmark, and the "malware" is EICAR or
inert text.

Phases:

1. **Benign workload.** 45 normal admin commands (ls, tar, curl --version, base64 round-trips, chmod 644 …). Any alert counts as a false positive.
2. **Attack scenarios.** 17 techniques across execution, persistence, privilege escalation, defense evasion, credential access, C2 and impact. Each passes if an expected rule or signature fires within `-timeout` (3s).
3. **Exec burst.** 300 short-lived processes, to measure how many the agent actually sees.

The agent's CPU and RSS are sampled from `/proc` throughout.

Flags: `-only <name>`, `-source procfs|netlink`, `-load N`, `-json`, `-md`, `-keep`,
`-min-detection 1.0` and `-max-fp 0` (gates for CI).

Reference results from this repo's dev container (kernel 6.18):

| | netlink (default) | /proc polling |
|---|---|---|
| Detection rate | 17/17 | 17/17 |
| Median time to detect | 1 ms | 20 ms |
| False positives | 0 / 45 | 0 / 45 |
| Short-lived exec visibility | **300/300** | **0/300** |
| Agent CPU avg / peak | 2.6% / 32% | 2.5% / 16% |
| Agent peak RSS | 14 MB | 9.5 MB |

Full tables: [docs/benchmark-netlink.md](docs/benchmark-netlink.md), [docs/benchmark-procfs.md](docs/benchmark-procfs.md).

**Read these numbers carefully.** The rules and the scenarios were written together,
so 17/17 shows the pipeline works end to end. It does not show how well SBS catches
attacks it wasn't tuned for. To get an honest number, add scenarios written
independently of the rules, for example ported from Atomic Red Team, and track the
rate over time. Exec visibility is the more telling metric: polling misses nearly
every short-lived process, which is why the netlink collector is the default.

CI (`.github/workflows/ci.yml`) runs unit tests and then the benchmark as root, fails on
any missed detection or false positive, and puts the Markdown report in the job summary.

## Layout

```
cmd/sbs-agent            agent CLI (run, scan, rules, version)
cmd/sbs-bench            benchmark CLI
internal/collector/proc  netlink exec events, /proc polling, process enrichment
internal/collector/fs    inotify watcher
internal/scanner         hash + string signature engine
internal/rules           rule engine
internal/agent           pipeline, dedup, output
internal/bench           scenarios, runner, reports
assets/                  built-in rules and signatures (embedded)
configs/, deploy/        example config, systemd unit
```

## Known limits and next steps

- **Exec race.** The netlink connector reports the PID, and the agent then reads `/proc`. A process that exits within microseconds can be gone first. An **eBPF** collector (tracepoints `sched_process_exec`, `security_bprm_check`) would capture argv in the kernel and add network connects and file opens per process.
- **No prevention yet.** The agent detects and alerts but does not block. Next would be: kill or suspend on critical alerts, quarantine files, and `fanotify` permission events to block execution of known-bad binaries.
- **Signatures are basic.** The matcher uses `bytes.Contains`; Aho-Corasick or real YARA (cgo + libyara) would scale to large rule sets.
- **Single host.** Next would be: ship alerts to a central server or SIEM (HTTP, syslog, Kafka), handle rule updates, and add a heartbeat and tamper protection.
- **Linux only.** Windows would need ETW and a different collector set.
