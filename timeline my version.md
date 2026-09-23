# Investigation Timeline

| Time | Source | Event / Observation | Assessment |
|------|--------|---------------------|------------|
| 23-09-2026 16:50:15 | PowerShell | Investigation timestamp recorded | Baseline |
| 20-09-2026 11:53:06 | Windows | Last system boot recorded | Host context |
| 20-09-2026 12:03 | Windows | `dell` active console session identified | User context |
| 23-09-2026 | PowerShell | Host information collected | Baseline |
| 23-09-2026 | PowerShell | Logged-on users collected | Baseline |
| 23-09-2026 | PowerShell | Running processes enumerated | Triage |
| 23-09-2026 | PowerShell | Windows services enumerated | Triage |
| 23-09-2026 | PowerShell | Scheduled tasks enumerated | Triage |
| 23-09-2026 | PowerShell | Listening TCP ports collected | Network baseline |
| 23-09-2026 | Sysmon Event ID 1 | Elastic Endpoint process creation observed | Security telemetry |
| 23-09-2026 | Elastic Defend | Prevention referenced WMI CommandLine Event Consumer execution | Significant finding |
| 23-09-2026 | Sysmon Event ID 3 | Network connections observed | Network telemetry |
| 23-09-2026 | Wazuh | Registry integrity change detected | Requires context |
| 23-09-2026 | Windows Security | Events `4624`, `4625`, and `4672` unavailable | Investigation limitation |

