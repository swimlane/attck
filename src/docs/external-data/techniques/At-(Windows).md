
# At (Windows)

## Description

### MITRE Description

> Adversaries may abuse the <code>at.exe</code> utility to perform task scheduling for initial or recurring execution of malicious code. The [at](https://attack.mitre.org/software/S0110) utility exists as an executable within Windows for scheduling tasks at a specified time and date. Using [at](https://attack.mitre.org/software/S0110) requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group. 

An adversary may use <code>at.exe</code> in Windows environments to execute programs at system startup or on a scheduled basis for persistence. [at](https://attack.mitre.org/software/S0110) can also be abused to conduct remote Execution as part of Lateral Movement and or to run a process under the context of a specified account (such as SYSTEM).

Note: The <code>at.exe</code> command line utility has been deprecated in current versions of Windows in favor of <code>schtasks</code>.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: True
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1053/002

## Potential Commands

```
at 13:20 /interactive cmd
```

## Commands Dataset

```
[{'command': 'at 13:20 /interactive cmd\n',
  'name': None,
  'source': 'atomics/T1053.002/T1053.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Scheduled Task/Job: At (Windows)': {'atomic_tests': [{'auto_generated_guid': '4a6c0dc4-0f2a-4203-9298-a5a9bdc21ed8',
                                                                                'description': 'Executes '
                                                                                               'cmd.exe\n'
                                                                                               'Note: '
                                                                                               'deprecated '
                                                                                               'in '
                                                                                               'Windows '
                                                                                               '8+\n'
                                                                                               '\n'
                                                                                               'Upon '
                                                                                               'successful '
                                                                                               'execution, '
                                                                                               'cmd.exe '
                                                                                               'will '
                                                                                               'spawn '
                                                                                               'at.exe '
                                                                                               'and '
                                                                                               'create '
                                                                                               'a '
                                                                                               'scheduled '
                                                                                               'task '
                                                                                               'that '
                                                                                               'will '
                                                                                               'spawn '
                                                                                               'cmd '
                                                                                               'at '
                                                                                               'a '
                                                                                               'specific '
                                                                                               'time.\n',
                                                                                'executor': {'command': 'at '
                                                                                                        '13:20 '
                                                                                                        '/interactive '
                                                                                                        'cmd\n',
                                                                                             'elevation_required': False,
                                                                                             'name': 'command_prompt'},
                                                                                'name': 'At.exe '
                                                                                        'Scheduled '
                                                                                        'task',
                                                                                'supported_platforms': ['windows']}],
                                                              'attack_technique': 'T1053.002',
                                                              'display_name': 'Scheduled '
                                                                              'Task/Job: '
                                                                              'At '
                                                                              '(Windows)'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    
* [Audit](../mitigations/Audit.md)
    

# Actors


* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)

* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT18](../actors/APT18.md)
    
