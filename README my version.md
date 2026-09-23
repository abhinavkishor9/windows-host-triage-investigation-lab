# windows-host-triage-investigation-lab
## Lab Overview
Windows Host Triage is the process of quickly collecting and reviewing the most useful information from a Windows endpoint during a security investigation.

The goal is not to perform a complete forensic acquisition. Instead, triage answers questions such as:

What is this host and who is using it?
What network connections are currently active?
Which processes and services are running?
Are there suspicious persistence mechanisms?
What recent system activity or security events are available?
Are there obvious indicators that require deeper investigation?

A good host-triage investigation follows a structured sequence:

Host identity → Users → Processes → Services → Network → Persistence → Event logs → Evidence summary

The important SOC principle is that triage indicators are not automatically malicious. A listening port, PowerShell process, scheduled task, unfamiliar service, or external connection should be treated as an investigation lead and correlated with additional evidence.


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

## Lab Objectives

- Establish a structured **Windows host triage workflow** for rapid endpoint situational awareness.
- Collect and document basic **host identity and operating system information**, including hostname, OS version, domain/workgroup status, and last boot time.
- Identify **currently logged-on users and active sessions** to establish user context during the investigation.
- Enumerate running **processes and parent-child process relationships** to identify execution activity that may require further investigation.
- Review **Windows services and scheduled tasks** for potential execution and persistence mechanisms.
- Collect **active network connections and listening TCP ports**, then correlate network activity with the owning processes.
- Review available **Windows Security events** related to authentication and privileged activity, while documenting any missing telemetry.
- Analyze **Sysmon process creation and network connection telemetry** to provide additional endpoint execution and network context.
- Correlate native Windows findings with **Wazuh endpoint telemetry** and identify related integrity or security events.
- Review **Elastic Defend detection and prevention telemetry** and determine what additional evidence is required to validate the alert.
- Preserve collected information as structured **investigation evidence** that can be reviewed or correlated later.
- Distinguish between **normal system activity, investigation leads, suspicious behavior, confirmed activity, and telemetry limitations**.
- Apply an **evidence-first approach** in which individual processes, ports, services, registry changes, or alerts are not automatically treated as proof of compromise.
- Build a concise **host triage assessment** to determine whether the available evidence justifies deeper DFIR investigation.

## Lab Scenario

A SOC analyst is asked to perform an initial **Windows host triage investigation** on a workstation that is already monitored by **Sysmon, Wazuh, and Elastic Defend**. The purpose of the investigation is to quickly establish the current state of the endpoint and identify any activity that may require deeper analysis.

The analyst begins by collecting basic host information and reviewing the currently logged-on users. Process and service inventories are then examined to understand what is executing on the system and which applications or services may require additional investigation.

The investigation also includes network and persistence-related checks:

- Review active TCP connections and listening ports.
- Correlate network connections with their owning processes.
- Review Windows services and scheduled tasks.
- Examine available Windows Security events related to authentication and privileges.
- Review Sysmon process creation and network connection telemetry.
- Correlate endpoint findings with Wazuh and Elastic Defend telemetry.

During the investigation, Elastic Defend reports a **prevention event associated with WMI CommandLine Event Consumer execution**. The analyst must determine what can be established from the available evidence and avoid treating the alert alone as proof of successful compromise.

The investigation is therefore focused on **evidence correlation rather than isolated indicators**. Processes, services, ports, registry activity, and security alerts are evaluated in their respective contexts, while unavailable or incomplete telemetry is documented as an investigation limitation.

The final objective is to produce a concise host-triage assessment that identifies:

- What was observed on the endpoint.
- Which findings require further investigation.
- Which activity appears consistent with normal system or application behavior.
- What telemetry was unavailable or insufficient.
- Whether the available evidence supports escalation to a deeper DFIR investigation.


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

