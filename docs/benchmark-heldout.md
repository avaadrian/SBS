# SBS benchmark report

2026-10-09 09:46 UTC · suite `heldout` · kernel `6.18.44-fc-v80` · process source `netlink`

| Metric | Value |
|---|---|
| Detection rate | 10/14 (71%) |
| Median time to detect | 1 ms |
| False positives | 0 over 45 benign commands |
| Exec visibility (short-lived) | 300/300 (100.0%) |
| Agent CPU (avg / peak) | 3.1% / 116.0% |
| Agent peak RSS | 46.1 MB |

| Scenario | ATT&CK | Tactic | Result | Latency | Alerts raised |
|---|---|---|---|---|---|
| python-reverse-shell | T1059.006 | command-and-control | ✅ SBS-PROC-003 | 206 ms | SBS-PROC-003 |
| perl-reverse-shell | T1059.004 | command-and-control | ✅ SBS-PROC-003 | 119 ms | SBS-PROC-003 |
| ruby-reverse-shell | T1059.004 | command-and-control | ✅ SBS-PROC-003 | 522 ms | SBS-PROC-003 |
| setsid-detached-miner | T1496 | impact | ✅ SBS-PROC-010 | 1 ms | SBS-PROC-010 |
| nohup-download-exec | T1059.004 | execution | ✅ SBS-PROC-001 | 1 ms | SBS-PROC-001 |
| python-ossystem-spawn-sh | T1059.006 | execution | ✅ SBS-PROC-001 | 1 ms | SBS-PROC-001 |
| dropper-script-home-exec | T1204.002 | execution | ❌ missed | – |  |
| base64-elf-home-exec | T1027 | defense-evasion | ✅ SBS-PROC-005 | 2 ms | SBS-PROC-005 |
| reverse-shell-script-dropped | T1059.004 | command-and-control | ✅ sig:Linux.Backdoor.ReverseShell.Script | 0 ms | sig:Linux.Backdoor.ReverseShell.Script |
| mirai-sample-dropped | T1105 | command-and-control | ✅ sig:Linux.Trojan.Mirai.Strings | 0 ms | sig:Linux.Trojan.Mirai.Strings |
| ldpreload-source-dropped | T1574.006 | persistence | ✅ sig:Linux.Rootkit.LDPreload.Generic | 1 ms | sig:Linux.Rootkit.LDPreload.Generic |
| systemd-run-transient | T1053.006 | persistence | ❌ missed | – |  |
| ssh-key-nonstandard-path | T1098.004 | persistence | ❌ missed | – |  |
| ldpreload-alt-filename | T1574.006 | persistence | ❌ missed | – |  |
