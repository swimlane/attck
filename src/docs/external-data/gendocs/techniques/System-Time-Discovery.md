
# System Time Discovery

## Description

### MITRE Description

> An adversary may gather the system time and/or time zone from a local or remote system. The system time is set and stored by the Windows Time Service within a domain to maintain time synchronization between systems and services in an enterprise network. (Citation: MSDN System Time) (Citation: Technet Windows Time Service)

System time information may be gathered in a number of ways, such as with [Net](https://attack.mitre.org/software/S0039) on Windows by performing <code>net time \\hostname</code> to gather the system time on a remote system. The victim's time zone may also be inferred from the current system time or gathered by using <code>w32tm /tz</code>. (Citation: Technet Windows Time Service) The information could be useful for performing other techniques, such as executing a file with a [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) (Citation: RSA EU12 They're Inside), or to discover locality information based on time zone to assist in victim targeting.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1124

## Potential Commands

```
net time \\localhost
w32tm /tz

Get-Date

{'darwin': {'sh': {'command': 'date -u +"%Y-%m-%dT%H:%M:%SZ"\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}}, 'linux': {'sh': {'command': 'date -u +"%Y-%m-%dT%H:%M:%SZ"\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}}, 'windows': {'psh': {'command': "Get-Date -UFormat '+%Y-%m-%dT%H:%M:%SZ'\n", 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}}}
```

## Commands Dataset

```
[{'command': 'net time \\\\localhost\nw32tm /tz\n',
  'name': None,
  'source': 'atomics/T1124/T1124.yaml'},
 {'command': 'Get-Date\n', 'name': None, 'source': 'atomics/T1124/T1124.yaml'},
 {'command': {'darwin': {'sh': {'command': 'date -u +"%Y-%m-%dT%H:%M:%SZ"\n',
                                'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}},
              'linux': {'sh': {'command': 'date -u +"%Y-%m-%dT%H:%M:%SZ"\n',
                               'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}},
              'windows': {'psh': {'command': 'Get-Date -UFormat '
                                             "'+%Y-%m-%dT%H:%M:%SZ'\n",
                                  'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}}},
  'name': 'get current system time (ISO 8601)',
  'source': 'data/abilities/discovery/fa6e8607-e0b1-425d-8924-9b894da5a002.yml'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['API monitoring']}]
```

## Potential Queries

```json
[{'name': 'System Time Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_path contains '
           '"*\\\\net.exe"and process_command_line contains "*net* time*")or '
           'process_path contains "w32tm.exe"or process_command_line contains '
           '"*Get-Date*"'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - System Time Discovery': {'atomic_tests': [{'auto_generated_guid': '20aba24b-e61f-4b26-b4ce-4784f763ca20',
                                                                     'description': 'Identify '
                                                                                    'the '
                                                                                    'system '
                                                                                    'time. '
                                                                                    'Upon '
                                                                                    'execution, '
                                                                                    'the '
                                                                                    'local '
                                                                                    'computer '
                                                                                    'system '
                                                                                    'time '
                                                                                    'and '
                                                                                    'timezone '
                                                                                    'will '
                                                                                    'be '
                                                                                    'displayed.\n',
                                                                     'executor': {'command': 'net '
                                                                                             'time '
                                                                                             '\\\\#{computer_name}\n'
                                                                                             'w32tm '
                                                                                             '/tz\n',
                                                                                  'name': 'command_prompt'},
                                                                     'input_arguments': {'computer_name': {'default': 'localhost',
                                                                                                           'description': 'computer '
                                                                                                                          'name '
                                                                                                                          'to '
                                                                                                                          'query',
                                                                                                           'type': 'string'}},
                                                                     'name': 'System '
                                                                             'Time '
                                                                             'Discovery',
                                                                     'supported_platforms': ['windows']},
                                                                    {'auto_generated_guid': '1d5711d6-655c-4a47-ae9c-6503c74fa877',
                                                                     'description': 'Identify '
                                                                                    'the '
                                                                                    'system '
                                                                                    'time '
                                                                                    'via '
                                                                                    'PowerShell. '
                                                                                    'Upon '
                                                                                    'execution, '
                                                                                    'the '
                                                                                    'system '
                                                                                    'time '
                                                                                    'will '
                                                                                    'be '
                                                                                    'displayed.\n',
                                                                     'executor': {'command': 'Get-Date\n',
                                                                                  'name': 'powershell'},
                                                                     'name': 'System '
                                                                             'Time '
                                                                             'Discovery '
                                                                             '- '
                                                                             'PowerShell',
                                                                     'supported_platforms': ['windows']}],
                                                   'attack_technique': 'T1124',
                                                   'display_name': 'System '
                                                                   'Time '
                                                                   'Discovery'}},
 {'Mitre Stockpile - get current system time (ISO 8601)': {'description': 'get '
                                                                          'current '
                                                                          'system '
                                                                          'time '
                                                                          '(ISO '
                                                                          '8601)',
                                                           'id': 'fa6e8607-e0b1-425d-8924-9b894da5a002',
                                                           'name': 'Get System '
                                                                   'Time',
                                                           'platforms': {'darwin': {'sh': {'command': 'date '
                                                                                                      '-u '
                                                                                                      '+"%Y-%m-%dT%H:%M:%SZ"\n',
                                                                                           'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}},
                                                                         'linux': {'sh': {'command': 'date '
                                                                                                     '-u '
                                                                                                     '+"%Y-%m-%dT%H:%M:%SZ"\n',
                                                                                          'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}},
                                                                         'windows': {'psh': {'command': 'Get-Date '
                                                                                                        '-UFormat '
                                                                                                        "'+%Y-%m-%dT%H:%M:%SZ'\n",
                                                                                             'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}}},
                                                           'tactic': 'discovery',
                                                           'technique': {'attack_id': 'T1124',
                                                                         'name': 'System '
                                                                                 'Time '
                                                                                 'Discovery'}}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [System Time Discovery Mitigation](../mitigations/System-Time-Discovery-Mitigation.md)


# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Turla](../actors/Turla.md)
    
* [The White Company](../actors/The-White-Company.md)
    
