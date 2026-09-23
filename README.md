# Windows Host Triage Investigation

## Lab Overview

This lab demonstrates a practical **Windows host triage workflow** using native PowerShell commands and endpoint security telemetry.

The investigation focuses on rapidly establishing the state of a Windows endpoint by collecting information about the host, logged-on users, processes, services, scheduled tasks, network connections, Windows Security events, Sysmon telemetry, Wazuh activity, and Elastic Defend detections.

The objective is to demonstrate how a SOC or DFIR analyst can establish endpoint situational awareness, identify investigation leads, correlate multiple telemetry sources, and document limitations without automatically treating individual indicators as malicious.

## Environment

- Operating System: Windows 11 Pro
- Hostname: `DESKTOP-9MMM37V`
- Manufacturer: Dell Inc.
- Model: Latitude 5420
- Domain Status: `WORKGROUP`
- Domain Role: `0`
- PowerShell: `7.6.6`
- Sysmon: Enabled
- Wazuh Agent: Enabled
- Elastic Defend: Enabled

## Investigation Areas

- Host and operating system identification
- Last boot information
- Logged-on user identification
- Running process inventory
- Parent and child process relationships
- Windows service enumeration
- Scheduled task enumeration
- Listening TCP ports
- Active network connections
- Windows Security event availability
- Sysmon process creation telemetry
- Sysmon network connection telemetry
- Wazuh endpoint telemetry
- Elastic Defend security prevention telemetry
- Evidence preservation
- Investigation timeline construction
- Triage assessment and limitations

## Investigation Workflow

The investigation followed a structured host-triage sequence:

```text
Host Identity
      ↓
Logged-On Users
      ↓
Processes
      ↓
Services
      ↓
Scheduled Tasks
      ↓
Network Activity
      ↓
Windows Security Events
      ↓
Sysmon
      ↓
Wazuh
      ↓
Elastic Defend
      ↓
Evidence Correlation
      ↓
Triage Assessment
```

## Key Findings

The endpoint was operating as a standalone Windows `WORKGROUP` system rather than a domain-joined workstation.

The active console session belonged to the local `dell` account.

Process enumeration provided visibility into applications, Windows processes, and security tooling running on the endpoint, including Elastic Endpoint.

Multiple listening ports were identified, including Windows networking and RPC-related ports and WinRM-related ports. These were treated as host-triage observations rather than automatically classified as malicious.

Sysmon Event ID `1` provided process creation telemetry, while Sysmon Event ID `3` provided network connection telemetry.

Windows Security Events `4624`, `4625`, and `4672` were not available during the investigation. This limited authentication and privileged-activity analysis.

Wazuh provided endpoint integrity telemetry, including a registry integrity event associated with a Windows biometric-related registry path.

Elastic Defend generated a prevention event associated with:

```text
Execution via WMI CommandLine Event Consumer
```

This was treated as the most significant security-relevant observation in the available telemetry.

The prevention event demonstrates that endpoint protection detected and prevented the behavior. It does not, by itself, establish that the endpoint was successfully compromised.

## Evidence Sources

### Windows PowerShell

Native PowerShell commands were used to collect:

- Host information
- Operating system information
- Logged-on users
- Processes
- Services
- Scheduled tasks
- Network connections
- Listening ports
- Windows Security events

### Sysmon

Sysmon telemetry was used to correlate endpoint activity through:

- Event ID `1` — Process creation
- Event ID `3` — Network connection

### Wazuh

Wazuh provided centralized endpoint telemetry and integrity monitoring.

### Elastic Defend

Elastic Defend provided endpoint detection and prevention telemetry.

The WMI-related prevention event became an important correlation point for the investigation.

## Investigation Philosophy

The investigation follows an evidence-first approach.

A process, service, listening port, network connection, registry modification, or security alert is treated as an observation that requires context.

Individual indicators are not automatically considered proof of compromise.

The assessment distinguishes between:

- Confirmed activity
- Suspicious activity requiring investigation
- Expected or configuration-related activity
- Inconclusive findings
- Missing or unavailable telemetry

## Important Finding

The most significant security-relevant observation was the Elastic Defend prevention associated with WMI CommandLine Event Consumer execution.

The appropriate investigative response is to correlate the alert with:

- Process creation
- Parent process
- Command line
- WMI activity
- User context
- Timestamps
- Persistence mechanisms
- Sysmon telemetry
- Wazuh telemetry
- Other endpoint evidence

The alert should therefore be treated as a strong investigation lead rather than as standalone proof of successful compromise.

## Limitations

The investigation had several limitations:

- Windows Security authentication events were unavailable.
- The endpoint was not part of an Active Directory domain.
- Some telemetry provided limited contextual information.
- No complete packet-level network capture was available.
- The available evidence did not independently establish successful compromise.
- The Elastic Defend prevention event required additional WMI-specific investigation.

## Conclusion

This lab demonstrates how Windows host triage can rapidly establish endpoint context and identify areas requiring deeper investigation.

The investigation combined native Windows evidence with Sysmon, Wazuh, and Elastic Defend telemetry.

The primary lesson is that host triage is not simply a search for malicious processes or unusual ports. It is a structured process of establishing system context, validating observations, correlating multiple telemetry sources, documenting limitations, and determining whether deeper DFIR investigation is warranted.

The final assessment was:

```text
Suspicious activity detected and prevented;
successful compromise not established from the available telemetry.
```
