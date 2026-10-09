# SBS benchmark report

2026-10-09 09:11 UTC · kernel `6.18.44-fc-v80` · process source `netlink`

| Metric | Value |
|---|---|
| Detection rate | 17/17 (100%) |
| Median time to detect | 1 ms |
| False positives | 0 over 45 benign commands |
| Exec visibility (short-lived) | 300/300 (100.0%) |
| Agent CPU (avg / peak) | 2.6% / 32.0% |
| Agent peak RSS | 14.0 MB |

| Scenario | ATT&CK | Tactic | Result | Latency | Alerts raised |
|---|---|---|---|---|---|
| download-piped-to-shell | T1059.004 | execution | ✅ SBS-PROC-001 | 1 ms | SBS-PROC-001 |
| base64-payload-to-shell | T1140 | defense-evasion | ✅ SBS-PROC-002 | 1 ms | SBS-PROC-002 |
| reverse-shell-tcp-socket | T1059.004 | command-and-control | ✅ SBS-PROC-003 | 3 ms | SBS-PROC-003 |
| reverse-shell-dev-tcp | T1059.004 | command-and-control | ✅ SBS-PROC-004 | 1 ms | SBS-PROC-004 |
| exec-from-tmp | T1204.002 | execution | ✅ SBS-PROC-005 | 1 ms | SBS-FILE-005, SBS-PROC-005 |
| fileless-memfd-exec | T1620 | defense-evasion | ✅ SBS-PROC-006 | 1 ms | SBS-PROC-006 |
| shadow-file-access | T1003.008 | credential-access | ✅ SBS-PROC-007 | 1 ms | SBS-PROC-007 |
| history-clearing | T1070.003 | defense-evasion | ✅ SBS-PROC-008 | 1 ms | SBS-PROC-008 |
| log-deletion | T1070.002 | defense-evasion | ✅ SBS-PROC-013 | 1 ms | SBS-PROC-013 |
| suid-backdoor | T1548.001 | privilege-escalation | ✅ SBS-PROC-009 | 1 ms | SBS-PROC-009, SBS-FILE-006 |
| miner-command-line | T1496 | impact | ✅ SBS-PROC-010 | 1 ms | SBS-PROC-010 |
| cron-persistence | T1053.003 | persistence | ✅ SBS-FILE-001 | 0 ms | SBS-FILE-001 |
| ssh-authorized-keys | T1098.004 | persistence | ✅ SBS-FILE-002 | 0 ms | SBS-FILE-002 |
| ld-preload-rootkit | T1574.006 | persistence | ✅ SBS-FILE-003 | 0 ms | SBS-FILE-003 |
| eicar-test-file | T1204 | execution | ✅ sig:EICAR-Test-File | 1 ms | sig:EICAR-Test-File, sig:EICAR-Test-File.Strings |
| miner-config-drop | T1496 | impact | ✅ sig:Linux.CoinMiner.Generic | 3 ms | sig:Linux.CoinMiner.Generic |
| php-webshell-drop | T1505.003 | persistence | ✅ sig:Webshell.PHP.Generic | 0 ms | sig:Webshell.PHP.Generic |
