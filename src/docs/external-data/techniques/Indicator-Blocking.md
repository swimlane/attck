
# Indicator Blocking

## Description

### MITRE Description

> An adversary may attempt to block indicators or events typically captured by sensors from being gathered and analyzed. This could include maliciously redirecting (Citation: Microsoft Lamin Sept 2017) or even disabling host-based sensors, such as Event Tracing for Windows (ETW),(Citation: Microsoft About Event Tracing 2018) by tampering settings that control the collection and flow of event telemetry. (Citation: Medium Event Tracing Tampering 2018) These settings may be stored on the system in configuration files and/or in the Registry as well as being accessible via administrative utilities such as [PowerShell](https://attack.mitre.org/techniques/T1086) or [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047).

ETW interruption can be achieved multiple ways, however most directly by defining conditions using the PowerShell Set-EtwTraceProvider cmdlet or by interfacing directly with the registry to make alterations.

In the case of network-based reporting of indicators, an adversary may block traffic associated with reporting to prevent central analysis. This may be accomplished by many means, such as stopping a local process responsible for forwarding telemetry and/or creating a host-based firewall rule to block traffic to specific hosts responsible for aggregating events, such as security information and event management (SIEM) products. 

## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti-virus', 'Log analysis', 'Host intrusion prevention systems']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1054

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': {'author': '@neu5ron',
                  'description': 'Detects scenarios where system auditing (ie: '
                                 'windows event log auditing) is disabled. '
                                 'This may be used in a scenario where an '
                                 'entity would want to bypass local logging to '
                                 'evade detection when windows event logging '
                                 'is enabled and reviewed. Also, it is '
                                 'recommended to turn off "Local Group Policy '
                                 'Object Processing" via GPO, which will make '
                                 'sure that Active Directory GPOs take '
                                 'precedence over local/edited computer '
                                 'policies via something such as "gpedit.msc". '
                                 'Please note, that disabling "Local Group '
                                 'Policy Object Processing" may cause an issue '
                                 'in scenarios of one off specific GPO '
                                 'modifications -- however it is recommended '
                                 'to perform these modifications in Active '
                                 'Directory anyways.',
                  'detection': {'condition': 'selection',
                                'selection': {'AuditPolicyChanges': 'removed',
                                              'EventID': 4719}},
                  'falsepositives': ['Unknown'],
                  'id': '69aeb277-f15f-4d2d-b32a-55e883609563',
                  'level': 'high',
                  'logsource': {'definition': 'Requirements: Audit Policy : '
                                              'Computer Management > Audit '
                                              'Policy Configuration, Group '
                                              'Policy : Computer '
                                              'Configuration\\Windows '
                                              'Settings\\Security '
                                              'Settings\\Advanced Audit Policy '
                                              'Configuration\\Audit '
                                              'Policies\\Policy Change\\Audit '
                                              'Authorization Policy Change',
                                'product': 'windows',
                                'service': 'security'},
                  'references': ['https://bit.ly/WinLogsZero2Hero'],
                  'tags': ['attack.defense_evasion', 'attack.t1054'],
                  'title': 'Disabling Windows Event Auditing'}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688.0']},
 {'data_source': ['Sensor health and status']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Sensor health and status']}]
```

## Potential Queries

```json
[{'name': 'Indicator Blocking Driver Unloaded',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains "fltmc.exe" '
           'or process_command_line contains "*fltmc*unload*")'},
 {'name': 'Indicator Blocking Sysmon Registry Edited From Other Source',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == '
           '14)and  (registry_key_path contains '
           '"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\SysmonDrv\\\\*"or '
           'registry_key_path contains '
           '"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Sysmon\\\\*"or '
           'registry_key_path contains '
           '"HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\Sysmon64\\\\*")and '
           '(process_path !contains "Sysmon64.exe" or process_path !contains '
           '"Sysmon.exe")'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: Stop Windows Defense Service\n'
           'description: win7 simulation test results\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           'product: windows\n'
           'service: system\n'
           'detection:\n'
           'selection:\n'
           'EventID: 7036\n'
           "Message: 'Windows Firewall service is stopped. '\n"
           'condition: selection\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows log Clear\n'
           'description: win7 and windows server 2003 simulation test results\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           'product: windows\n'
           'service: security\n'
           'detection:\n'
           'selection:\n'
           'EventID:\n'
           '\\ --1102\n'
           '\\ --517\n'
           'condition: selection\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows log Clear\n'
           'description: win7 simulation test results\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           'product: windows\n'
           'service: system\n'
           'detection:\n'
           'selection:\n'
           'EventID: 104\n'
           'condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json

```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors

None
