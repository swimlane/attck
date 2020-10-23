
# System Checks

## Description

### MITRE Description

> Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) during automated discovery to shape follow-on behaviors. 

Specific checks may will vary based on the target and/or adversary, but may involve behaviors such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047), [PowerShell](https://attack.mitre.org/techniques/T1059/001), [System Information Discovery](https://attack.mitre.org/techniques/T1082), and [Query Registry](https://attack.mitre.org/techniques/T1012) to obtain system information and search for VME artifacts. Adversaries may search for VME artifacts in memory, processes, file system, hardware, and/or the Registry. Adversaries may use scripting to automate these checks  into one script and then have the program exit if it determines the system to be a virtual environment. 

Checks could include generic system properties such as uptime and samples of network traffic. Adversaries may also check the network adapters addresses, CPU core count, and available memory/drive size. 

Other common checks may enumerate services running that are unique to these applications, installed programs on the system, manufacturer/product fields for strings relating to virtual machine applications, and VME-specific hardware/processor instructions.(Citation: McAfee Virtual Jan 2017) In applications like VMWare, adversaries can also use a special I/O port to send commands and receive output. 
 
Hardware checks, such as the presence of the fan, temperature, and audio devices, could also be used to gather evidence that can be indicative a virtual environment. Adversaries may also query for specific readings from these devices.(Citation: Unit 42 OilRig Sept 2018)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Static File Analysis', 'Signature-based detection', 'Host forensic analysis', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1497/001

## Potential Commands

```
get-wmiobject win32_computersystem | fl model
```

## Commands Dataset

```
[{'command': 'get-wmiobject win32_computersystem | fl model\n',
  'name': 'Determine if the system is virtualized or physical',
  'source': 'data/abilities/discovery/5dc841fd-28ad-40e2-b10e-fb007fe09e81.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - Determine if the system is virtualized or physical': {'description': 'Determine '
                                                                                          'if '
                                                                                          'the '
                                                                                          'system '
                                                                                          'is '
                                                                                          'virtualized '
                                                                                          'or '
                                                                                          'physical',
                                                                           'id': '5dc841fd-28ad-40e2-b10e-fb007fe09e81',
                                                                           'name': 'Virtual '
                                                                                   'or '
                                                                                   'Real',
                                                                           'platforms': {'windows': {'psh': {'command': 'get-wmiobject '
                                                                                                                        'win32_computersystem '
                                                                                                                        '| '
                                                                                                                        'fl '
                                                                                                                        'model\n'}}},
                                                                           'tactic': 'discovery',
                                                                           'technique': {'attack_id': 'T1497.001',
                                                                                         'name': 'Virtualization/Sandbox '
                                                                                                 'Evasion: '
                                                                                                 'System '
                                                                                                 'Checks'}}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Discovery](../tactics/Discovery.md)
    

# Mitigations

None

# Actors


* [Frankenstein](../actors/Frankenstein.md)

