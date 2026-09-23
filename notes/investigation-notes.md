# Investigation Notes

## Investigation Overview

**Lab:** Windows Host Triage Investigation  
**Host:** `DESKTOP-9MMM37V`  
**Operating System:** Windows 11 Pro  
**Environment:** `WORKGROUP`  
**Investigation Date:** 23 September 2026

The investigation was performed as a host-level triage exercise to establish endpoint situational awareness and identify activity requiring deeper investigation.

The approach combined native Windows PowerShell commands with Sysmon, Wazuh, and Elastic Defend telemetry.

---

## 1. Host Identification

The endpoint was identified as:

- Hostname: `DESKTOP-9MMM37V`
- Manufacturer: Dell Inc.
- Model: Latitude 5420
- Operating System: Windows 11 Pro
- Version: `10.0.26200`
- Domain: `WORKGROUP`
- Domain Role: `0`
- Last Boot: `20 September 2026 11:53:06`

The host was therefore treated as a standalone Windows workstation rather than a domain-joined endpoint or domain controller.

The host information established the baseline required for interpreting subsequent process, network, service, and security telemetry.

---

## 2. Logged-On User

The active console session showed:

- User: `dell`
- Session: `console`
- Session ID: `2`
- State: `Active`

Additional Windows system accounts were visible through `Win32_LoggedOnUser`, including:

- `SYSTEM`
- `LOCAL SERVICE`
- `NETWORK SERVICE`
- `DWM`
- `UMFD`

These accounts were treated as normal operating-system context unless additional evidence indicated otherwise.

The presence of an account or session alone was not considered evidence of malicious activity.

---

## 3. Process Triage

Running processes were collected using:

```powershell
Get-CimInstance Win32_Process |
Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
Sort-Object Name
```

The collected information included:

- Process ID
- Parent Process ID
- Process name
- Executable path
- Command line

The process inventory included normal applications, Windows components, and security tooling.

Examples included:

- Chrome
- Adobe components
- `cmd.exe`
- Windows system processes
- Elastic Endpoint
- Other installed applications

Parent and child process relationships were retained because process ancestry can provide important context during endpoint investigations.

The presence of PowerShell, `cmd.exe`, scripting engines, or other administrative tools was not automatically classified as malicious.

---

## 4. Sysmon Process Creation

Sysmon Event ID `1` was reviewed for process creation activity.

The telemetry included an Elastic Endpoint process associated with an Elastic Defend prevention notification.

Relevant event context included:

- Image: `elastic-endpoint.exe`
- User: `NT AUTHORITY\SYSTEM`
- Integrity Level: `System`
- Product: Elastic Defend
- Parent Image: `elastic-endpoint.exe`

The command-line information referenced an Elastic Security prevention notification associated with:

```text
Execution via WMI CommandLine Event Consumer
```

This was considered a significant defensive telemetry observation.

The event demonstrates that Elastic Defend detected and prevented the behavior.

However, the event alone does not establish that the endpoint was successfully compromised.

Further investigation would require correlation with WMI activity, process ancestry, command-line information, timestamps, and persistence artifacts.

---

## 5. Service Triage

Windows services were collected using:

```powershell
Get-CimInstance Win32_Service |
Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
Sort-Object Name
```

The endpoint contained numerous automatically started services.

Security-related services included:

- Elastic Agent
- Elastic Endpoint

The service inventory was preserved in CSV format for later analysis.

Services were treated as baseline information and potential investigation candidates.

An automatically started service or third-party service was not automatically classified as malicious without additional evidence.

---

## 6. Scheduled Task Triage

Scheduled tasks were enumerated using:

```powershell
Get-ScheduledTask |
Select-Object TaskName, TaskPath, State |
Sort-Object TaskPath, TaskName
```

Scheduled tasks were included because they can provide useful context when investigating persistence and recurring execution.

The presence of a scheduled task alone does not demonstrate malicious persistence.

Further analysis would require reviewing:

- Task name
- Task path
- Author
- Actions
- Executable
- Arguments
- Trigger
- Run-as account
- Creation or modification time

---

## 7. Network Triage

Listening TCP connections were collected using:

```powershell
Get-NetTCPConnection -State Listen |
Select-Object LocalAddress, LocalPort, OwningProcess |
Sort-Object LocalPort
```

Observed listening ports included:

- `135`
- `139`
- `445`
- `902`
- `912`
- `5037`
- `5040`
- `5985`
- `6789`
- `6791`
- `47001`
- Dynamic RPC ports

Ports `135`, `139`, and `445` are commonly associated with Windows networking.

Port `5985` is associated with WinRM.

These observations were treated as network baseline information.

The appropriate next step for a potentially interesting port is to identify its owning process and determine whether the listener is expected for the host.

---

## 8. Network Connections

Sysmon Event ID `3` was reviewed for network connection activity.

One observed connection involved:

```text
Process: Zoho Mail - Desktop.exe
Source: 192.168.1.6
Destination: 169.148.149.132
Destination Port: 443
Protocol: TCP
```

The connection used HTTPS and was associated with a user-level application.

No malicious conclusion was made solely from the destination IP address or the existence of an external network connection.

The process, destination, timestamp, user context, and surrounding endpoint activity should be correlated before making an assessment.

---

## 9. Windows Security Events

The following Windows Security event IDs were searched:

- `4624` — Successful logon
- `4625` — Failed logon
- `4672` — Special privileges assigned

The query used was:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4624,4625,4672
} -MaxEvents 100 |
Select-Object TimeCreated, Id, Message
```

No matching events were available during the investigation.

This is an important telemetry limitation.

The absence of these events does not prove that no authentication or privileged activity occurred. It means that the expected Security event data was not available for analysis in the current environment.

---

## 10. Wazuh Telemetry

Wazuh provided endpoint integrity monitoring during the investigation.

A registry integrity event was observed involving a Windows biometric-related registry path.

The event reported a modification associated with the registry object's modification time and was categorized by Wazuh as a registry key integrity checksum change.

The registry event was treated as telemetry requiring additional context rather than automatically classified as malicious.

Relevant follow-up questions include:

- What process modified the registry?
- Which user context was involved?
- When did the modification occur?
- Was the registry location expected to change?
- Was the change associated with software installation or configuration?
- Did other telemetry show related activity?

---

## 11. Elastic Defend Finding

Elastic Defend produced the strongest security-relevant observation in the available telemetry.

The prevention message referenced:

```text
Malicious Behavior Prevention Alert
Execution via WMI CommandLine Event Consumer
```

The event was generated by the Elastic Endpoint security component.

The event indicates that endpoint protection detected and prevented behavior associated with WMI CommandLine Event Consumer execution.

This should be treated as a significant investigation lead.

The next investigative step would be to determine:

1. What initiated the WMI activity?
2. Which process was responsible?
3. What command line was involved?
4. Which user or security context initiated the activity?
5. Was a WMI subscription created?
6. Were any persistence artifacts created?
7. Did Sysmon record related process activity?
8. Did Wazuh record related file or registry activity?
9. Was the activity prevented before successful execution?

---

## 12. Cross-Telemetry Correlation

The investigation demonstrated the value of correlating multiple evidence sources.

A useful correlation model is:

```text
Process
   ↓
Process ID / Parent PID
   ↓
Sysmon Event ID 1
   ↓
Network Activity / Sysmon Event ID 3
   ↓
Wazuh Telemetry
   ↓
Elastic Defend Detection or Prevention
   ↓
Final Assessment
```

This approach is stronger than treating a single artifact as proof of compromise.

For example, an external network connection may be normal application traffic, while a WMI-related EDR prevention may require deeper investigation.

The assessment should therefore be based on the combined evidence available.

---

## 13. Assessment

### Confirmed

- Windows host triage data was collected.
- The endpoint was operating in a `WORKGROUP` environment.
- The `dell` account had an active console session.
- Sysmon process creation telemetry was available.
- Sysmon network connection telemetry was available.
- Wazuh endpoint telemetry was available.
- Elastic Defend generated a prevention event.
- Multiple Windows services and listening ports were identified.

### Suspicious / Requires Investigation

- Elastic Defend prevention involving WMI CommandLine Event Consumer execution.
- Any related WMI persistence or execution artifacts discovered during follow-up analysis.
- Any process ancestry or command-line activity associated with the prevented behavior.

### Configuration / Expected

- Standard Windows services.
- Windows networking and RPC-related ports.
- Normal user and system processes.
- HTTPS traffic generated by installed applications.
- Security and endpoint-management software processes.

### Inconclusive

- Authentication activity could not be evaluated because Security Events `4624`, `4625`, and `4672` were unavailable.
- Individual network connections could not be classified as malicious solely from connection metadata.
- The Wazuh registry integrity event could not independently establish malicious modification.

---

## 14. Investigation Limitations

The investigation was limited by:

- Missing Windows Security authentication events.
- No Active Directory domain environment.
- Limited contextual information in some event outputs.
- No complete packet-level network capture.
- No complete memory acquisition.
- No independent confirmation of successful WMI execution.
- Limited visibility into the underlying WMI object or consumer responsible for the prevention event.

These limitations were documented rather than interpreted as evidence that the activity did not occur.

---

## 15. Conclusion

The Windows host triage established a useful endpoint baseline and identified one significant security-relevant event.

The most important finding was an Elastic Defend prevention associated with WMI CommandLine Event Consumer execution.

The investigation did not establish successful compromise from the available evidence.

The result is therefore best represented as:

```text
Suspicious activity detected and prevented;
successful compromise not established from the available telemetry.
```

Further investigation should focus on WMI artifacts, process ancestry, command-line information, persistence mechanisms, and correlated endpoint telemetry.
