# Troubleshooting Notes

## 1. `$EvidencePath` Is Not Defined

The evidence collection commands depend on the `$EvidencePath` variable.

If the variable is missing or empty, evidence files may be written to an unexpected location or the command may fail.

Reinitialize the investigation workspace:

```powershell
$LabPath = "C:\WindowsHostTriageLab"
$EvidencePath = "$LabPath\Evidence"

New-Item -ItemType Directory -Path $EvidencePath -Force
```

Verify the directories:

```powershell
Test-Path $LabPath
Test-Path $EvidencePath
```

Expected result:

```text
True
True
```

---

## 2. Security Events Are Not Available

The following query returned no matching Security events:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4624,4625,4672
} -MaxEvents 100
```

Do not interpret this as proof that no logons or privileged activity occurred.

Instead, document it as a telemetry limitation.

Check the Security log:

```powershell
Get-WinEvent -ListLog Security |
Select-Object LogName, IsEnabled, RecordCount
```

Useful fields include:

- `LogName`
- `IsEnabled`
- `RecordCount`

If the log exists but contains no relevant records, document the limitation in the investigation notes.

---

## 3. Sysmon Event ID 1 Is Not Available

Sysmon Event ID `1` represents process creation telemetry.

Check for process creation events:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 1
} -MaxEvents 50 |
Select-Object TimeCreated, Id, Message
```

If no results are returned, check whether the Sysmon service is running:

```powershell
Get-Service Sysmon64 -ErrorAction SilentlyContinue
```

If the service name differs, enumerate Sysmon-related services:

```powershell
Get-Service |
Where-Object {
    $_.Name -match "Sysmon"
} |
Select-Object Name, Status, DisplayName
```

---

## 4. Sysmon Event ID 3 Is Not Available

Sysmon Event ID `3` provides network connection telemetry when enabled by the Sysmon configuration.

Check for network events:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 3
} -MaxEvents 50 |
Select-Object TimeCreated, Id, Message
```

If no results are returned, do not automatically assume that there was no network activity.

Sysmon Event ID `3` may not be enabled by the active Sysmon configuration.

Native Windows network telemetry can still be collected using:

```powershell
Get-NetTCPConnection
```

---

## 5. Process Enumeration Produces Incomplete Information

Process information was collected with:

```powershell
Get-CimInstance Win32_Process |
Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
```

Some processes may not expose complete command-line or executable-path information.

Possible reasons include:

- Permission restrictions
- Protected processes
- Process termination during collection
- Limited process metadata
- Security software protection

Repeat the query when necessary:

```powershell
Get-CimInstance Win32_Process |
Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
```

Do not treat missing command-line information as evidence of malicious activity.

---

## 6. Listening Ports Need Process Correlation

Listening ports should not be classified as suspicious based only on the port number.

Collect listeners:

```powershell
Get-NetTCPConnection -State Listen |
Select-Object LocalAddress, LocalPort, OwningProcess |
Sort-Object LocalPort
```

Identify the process associated with a PID:

```powershell
Get-Process -Id <PID>
```

For more detailed process information:

```powershell
Get-CimInstance Win32_Process -Filter "ProcessId = <PID>" |
Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
```

The correct investigation sequence is:

```text
Listening Port
      ↓
Owning PID
      ↓
Process
      ↓
Executable Path
      ↓
Command Line
      ↓
User Context
      ↓
Expected or Suspicious
```

---

## 7. Wazuh Telemetry Is Unavailable

If Wazuh events are not appearing, first check the Windows agent service:

```powershell
Get-Service WazuhSvc
```

The service should normally show a running state when the agent is active.

On the Wazuh manager, agent status can be checked with:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

If the agent is active but events are still missing, investigate:

- Agent connectivity
- Manager connectivity
- Agent configuration
- Log collection configuration
- Time synchronization
- Event generation
- Wazuh alert rules

---

## 8. Elastic Defend Prevention Event

The Elastic Defend prevention event referenced:

```text
Execution via WMI CommandLine Event Consumer
```

The correct response is not to treat the alert alone as proof of successful compromise.

Correlate the event with:

- Event timestamp
- Process creation
- Parent process
- Command line
- WMI activity
- User context
- Security context
- Sysmon telemetry
- Wazuh telemetry
- Persistence artifacts
- EDR prevention status

A prevention event establishes that the security control detected and prevented the associated behavior. Additional evidence is required to determine whether related malicious activity occurred before prevention.

---

## 9. Network Connection Requires Context

An external network connection should not automatically be considered malicious.

Collect the current connections:

```powershell
Get-NetTCPConnection |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
```

Identify the owning process:

```powershell
Get-Process -Id <PID>
```

For more context:

```powershell
Get-CimInstance Win32_Process -Filter "ProcessId = <PID>" |
Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
```

Review:

- Process
- Destination
- Port
- Timestamp
- User
- Parent process
- Application purpose
- EDR telemetry

Do not classify a connection as malicious solely because the destination is external.

---

## 10. Scheduled Task Requires Deeper Inspection

If a scheduled task appears unusual, collect additional information:

```powershell
Get-ScheduledTask |
Select-Object TaskName, TaskPath, State
```

Then inspect an individual task:

```powershell
Get-ScheduledTask -TaskName "<TaskName>" -TaskPath "<TaskPath>" |
Get-ScheduledTaskInfo
```

Review the task definition when required:

```powershell
Export-ScheduledTask -TaskName "<TaskName>" -TaskPath "<TaskPath>"
```

Important fields include:

- Task name
- Task path
- Actions
- Triggers
- Run-as account
- Author
- Creation context
- Executable
- Arguments

---

## 11. Service Requires Additional Validation

An unfamiliar service should not automatically be considered malicious.

Review the service:

```powershell
Get-CimInstance Win32_Service |
Where-Object {
    $_.Name -eq "<ServiceName>"
} |
Select-Object Name, DisplayName, State, StartMode, StartName, PathName
```

Then investigate:

- Executable path
- Digital signature
- Service account
- Parent process
- Creation time if available
- Related registry configuration
- EDR telemetry

---

## 12. Evidence File Was Not Created

If an evidence file is missing, first verify the destination:

```powershell
Test-Path $EvidencePath
```

List the evidence directory:

```powershell
Get-ChildItem $EvidencePath
```

If the directory does not exist, recreate it:

```powershell
New-Item -ItemType Directory -Path $EvidencePath -Force
```

Avoid relying on variables from an earlier PowerShell session because variables may not persist after opening a new session.

---

## 13. Permission-Related Errors

Some Windows security and process information requires elevated PowerShell privileges.

If information is incomplete or access is denied:

1. Close the current PowerShell window.
2. Open PowerShell as Administrator.
3. Repeat the collection command.
4. Document any remaining limitations.

Do not treat a permission-related collection failure as evidence that the activity did not occur.

---

## 14. Evidence Collection Principle

When a collection command fails, the correct approach is:

```text
Command Failure
      ↓
Identify Reason
      ↓
Retry or Validate
      ↓
Document Limitation
      ↓
Continue With Available Evidence
```

The investigation should preserve both successful findings and telemetry limitations.

A missing artifact is not automatically evidence of an absence of activity.
