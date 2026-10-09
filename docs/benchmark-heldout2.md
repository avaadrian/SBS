# SBS benchmark report

2026-10-09 11:17 UTC · suite `heldout2` · kernel `6.18.44-fc-v80` · process source `netlink`

| Metric | Value |
|---|---|
| Detection rate | 1/16 (6%) |
| Median time to detect | 1 ms |
| False positives | 0 over 45 benign commands |
| Agent CPU (avg / peak) | 0.3% / 28.0% |
| Agent peak RSS | 13.9 MB |

| Scenario | ATT&CK | Tactic | Result | Latency | Alerts raised |
|---|---|---|---|---|---|
| system-discovery-chain | T1082 | discovery | ❌ missed | – |  |
| suid-binary-discovery | T1083 | discovery | ❌ missed | – |  |
| proc-environ-cred-dump | T1003.007 | credential-access | ❌ missed | – |  |
| shell-profile-persistence | T1546.004 | persistence | ❌ missed | – |  |
| udev-rule-persistence | T1546 | persistence | ❌ missed | – |  |
| gtfobins-find-exec | T1059.004 | execution | ❌ missed | – |  |
| gtfobins-awk-system | T1059.004 | execution | ❌ missed | – |  |
| rsyslog-config-tamper | T1562.001 | defense-evasion | ❌ missed | – |  |
| base64-env-obfuscated-exec | T1140 | defense-evasion | ❌ missed | – |  |
| timestomp-backdate | T1070.006 | defense-evasion | ❌ missed | – |  |
| ld-preload-env-launch | T1574.006 | defense-evasion | ❌ missed | – |  |
| ldpreload-shell-append | T1574.006 | persistence | ✅ SBS-FILE-003 | 1 ms | SBS-PROC-019, SBS-FILE-003, SBS-FILE-007 |
| mkfifo-nc-reverse-shell | T1059.004 | command-and-control | ❌ missed | – |  |
| python-http-exfil | T1041 | exfiltration | ❌ missed | – |  |
| nsenter-container-escape | T1611 | privilege-escalation | ❌ missed | – |  |
| unshare-user-namespace | T1611 | privilege-escalation | ❌ missed | – |  |
