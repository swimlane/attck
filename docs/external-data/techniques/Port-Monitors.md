
# Port Monitors

## Description

### MITRE Description

> A port monitor can be set through the  (Citation: AddMonitor) API call to set a DLL to be loaded at startup. (Citation: AddMonitor) This DLL can be located in <code>C:\Windows\System32</code> and will be loaded by the print spooler service, spoolsv.exe, on boot. The spoolsv.exe process also runs under SYSTEM level permissions. (Citation: Bloxham) Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to <code>HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors</code>. 

The Registry key contains entries for the following:

* Local Port
* Standard TCP/IP Port
* USB Monitor
* WSD Port

Adversaries can use this technique to load malicious code at startup that will persist on system reboot and execute as SYSTEM.

## Additional Attributes

* Bypass: None
* Effective Permissions: ['SYSTEM']
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1013

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Local Port Monitor',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           'registry_key_path contains '
           '"\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Print\\\\Monitors\\\\"'}]
```

## Raw Dataset

```json

```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors

None
