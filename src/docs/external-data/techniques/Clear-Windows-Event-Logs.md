
# Clear Windows Event Logs

## Description

### MITRE Description

> Adversaries may clear Windows Event Logs to hide the activity of an intrusion. Windows Event Logs are a record of a computer's alerts and notifications. There are three system-defined sources of events: System, Application, and Security, with five event types: Error, Warning, Information, Success Audit, and Failure Audit.

The event logs can be cleared with the following utility commands:

* <code>wevtutil cl system</code>
* <code>wevtutil cl application</code>
* <code>wevtutil cl security</code>

These logs may also be cleared through other mechanisms, such as the event viewer GUI or [PowerShell](https://attack.mitre.org/techniques/T1059/001).

## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti Virus', 'Host Intrusion Prevention Systems', 'Log Analysis']
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1070/001

## Potential Commands

```
wevtutil cl System
$logs = Get-EventLog -List | ForEach-Object {$_.Log}
$logs | ForEach-Object {Clear-EventLog -LogName $_ }
Get-EventLog -list
```

## Commands Dataset

```
[{'command': 'wevtutil cl System\n',
  'name': None,
  'source': 'atomics/T1070.001/T1070.001.yaml'},
 {'command': '$logs = Get-EventLog -List | ForEach-Object {$_.Log}\n'
             '$logs | ForEach-Object {Clear-EventLog -LogName $_ }\n'
             'Get-EventLog -list\n',
  'name': None,
  'source': 'atomics/T1070.001/T1070.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Indicator Removal on Host: Clear Windows Event Logs': {'atomic_tests': [{'auto_generated_guid': 'e6abb60e-26b8-41da-8aae-0c35174b0967',
                                                                                                   'description': 'Upon '
                                                                                                                  'execution '
                                                                                                                  'this '
                                                                                                                  'test '
                                                                                                                  'will '
                                                                                                                  'clear '
                                                                                                                  'Windows '
                                                                                                                  'Event '
                                                                                                                  'Logs. '
                                                                                                                  'Open '
                                                                                                                  'the '
                                                                                                                  'System.evtx '
                                                                                                                  'logs '
                                                                                                                  'at '
                                                                                                                  'C:\\Windows\\System32\\winevt\\Logs '
                                                                                                                  'and '
                                                                                                                  'verify '
                                                                                                                  'that '
                                                                                                                  'it '
                                                                                                                  'is '
                                                                                                                  'now '
                                                                                                                  'empty.\n',
                                                                                                   'executor': {'command': 'wevtutil '
                                                                                                                           'cl '
                                                                                                                           '#{log_name}\n',
                                                                                                                'elevation_required': True,
                                                                                                                'name': 'command_prompt'},
                                                                                                   'input_arguments': {'log_name': {'default': 'System',
                                                                                                                                    'description': 'Windows '
                                                                                                                                                   'Log '
                                                                                                                                                   'Name, '
                                                                                                                                                   'ex '
                                                                                                                                                   'System',
                                                                                                                                    'type': 'String'}},
                                                                                                   'name': 'Clear '
                                                                                                           'Logs',
                                                                                                   'supported_platforms': ['windows']},
                                                                                                  {'auto_generated_guid': 'b13e9306-3351-4b4b-a6e8-477358b0b498',
                                                                                                   'description': 'Clear '
                                                                                                                  'event '
                                                                                                                  'logs '
                                                                                                                  'using '
                                                                                                                  'built-in '
                                                                                                                  'PowerShell '
                                                                                                                  'commands.\n'
                                                                                                                  'Upon '
                                                                                                                  'successful '
                                                                                                                  'execution, '
                                                                                                                  'you '
                                                                                                                  'should '
                                                                                                                  'see '
                                                                                                                  'the '
                                                                                                                  'list '
                                                                                                                  'of '
                                                                                                                  'deleted '
                                                                                                                  'event '
                                                                                                                  'logs\n'
                                                                                                                  'Upon '
                                                                                                                  'execution, '
                                                                                                                  'open '
                                                                                                                  'the '
                                                                                                                  'Security.evtx '
                                                                                                                  'logs '
                                                                                                                  'at '
                                                                                                                  'C:\\Windows\\System32\\winevt\\Logs '
                                                                                                                  'and '
                                                                                                                  'verify '
                                                                                                                  'that '
                                                                                                                  'it '
                                                                                                                  'is '
                                                                                                                  'now '
                                                                                                                  'empty '
                                                                                                                  'or '
                                                                                                                  'has '
                                                                                                                  'very '
                                                                                                                  'few '
                                                                                                                  'logs '
                                                                                                                  'in '
                                                                                                                  'it.\n',
                                                                                                   'executor': {'command': '$logs '
                                                                                                                           '= '
                                                                                                                           'Get-EventLog '
                                                                                                                           '-List '
                                                                                                                           '| '
                                                                                                                           'ForEach-Object '
                                                                                                                           '{$_.Log}\n'
                                                                                                                           '$logs '
                                                                                                                           '| '
                                                                                                                           'ForEach-Object '
                                                                                                                           '{Clear-EventLog '
                                                                                                                           '-LogName '
                                                                                                                           '$_ '
                                                                                                                           '}\n'
                                                                                                                           'Get-EventLog '
                                                                                                                           '-list\n',
                                                                                                                'elevation_required': True,
                                                                                                                'name': 'powershell'},
                                                                                                   'name': 'Delete '
                                                                                                           'System '
                                                                                                           'Logs '
                                                                                                           'Using '
                                                                                                           'Clear-EventLog',
                                                                                                   'supported_platforms': ['windows']}],
                                                                                 'attack_technique': 'T1070.001',
                                                                                 'display_name': 'Indicator '
                                                                                                 'Removal '
                                                                                                 'on '
                                                                                                 'Host: '
                                                                                                 'Clear '
                                                                                                 'Windows '
                                                                                                 'Event '
                                                                                                 'Logs'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)

* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)
    
* [Remote Data Storage](../mitigations/Remote-Data-Storage.md)
    
* [Indicator Removal on Host Mitigation](../mitigations/Indicator-Removal-on-Host-Mitigation.md)
    

# Actors


* [APT28](../actors/APT28.md)

* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [APT32](../actors/APT32.md)
    
* [FIN5](../actors/FIN5.md)
    
* [FIN8](../actors/FIN8.md)
    
* [APT38](../actors/APT38.md)
    
* [APT41](../actors/APT41.md)
    
