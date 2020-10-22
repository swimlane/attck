
# Virtualization/Sandbox Evasion

## Description

### MITRE Description

> Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) during automated discovery to shape follow-on behaviors. 

Adversaries may use several methods to accomplish [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) such as checking for security monitoring tools (e.g., Sysinternals, Wireshark, etc.) or other system artifacts associated with analysis or virtualization. Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment. Additional methods include use of sleep timers or loops within malware code to avoid operating within a temporary sandbox.(Citation: Unit 42 Pirpi July 2015)



## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti-virus', 'Host forensic analysis', 'Signature-based detection', 'Static File Analysis']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows', 'macOS', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1497

## Potential Commands

```
{'windows': {'psh': {'command': 'get-wmiobject win32_computersystem | fl model\n'}}}
```

## Commands Dataset

```
[{'command': {'windows': {'psh': {'command': 'get-wmiobject '
                                             'win32_computersystem | fl '
                                             'model\n'}}},
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
                                                                           'technique': {'attack_id': 'T1497',
                                                                                         'name': 'Virtualization '
                                                                                                 'Sandbox '
                                                                                                 'Evasion'}}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Discovery](../tactics/Discovery.md)
    

# Mitigations

None

# Actors

None
