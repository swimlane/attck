
# Boot or Logon Initialization Scripts

## Description

### MITRE Description

> Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.  

Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. 

An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1037

## Potential Commands

```
\Environment\UserInitMprLogonScript
python/persistence/multi/desktopfile
python/persistence/osx/loginhook
```

## Commands Dataset

```
[{'command': '\\Environment\\UserInitMprLogonScript',
  'name': None,
  'source': 'SysmonHunter - Logon Scripts'},
 {'command': '\\Environment\\UserInitMprLogonScript',
  'name': None,
  'source': 'SysmonHunter - Logon Scripts'},
 {'command': 'python/persistence/multi/desktopfile',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/persistence/multi/desktopfile',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/persistence/osx/loginhook',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/persistence/osx/loginhook',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'action': 'global',
                  'author': 'Tom Ueltschi (@c_APT_ure)',
                  'description': 'Detects creation or execution of '
                                 'UserInitMprLogonScript persistence method',
                  'falsepositives': ['exclude legitimate logon scripts',
                                     'penetration tests, red teaming'],
                  'id': '0a98a10c-685d-4ab0-bddc-b6bdd1d48458',
                  'level': 'high',
                  'references': ['https://attack.mitre.org/techniques/T1037/'],
                  'status': 'experimental',
                  'tags': ['attack.t1037',
                           'attack.persistence',
                           'attack.lateral_movement'],
                  'title': 'Logon Scripts (UserInitMprLogonScript)'}},
 {'data_source': {'detection': {'condition': 'exec_selection and not '
                                             'exec_exclusion1 and not '
                                             'exec_exclusion2',
                                'exec_exclusion1': {'Image': '*\\explorer.exe'},
                                'exec_exclusion2': {'CommandLine': '*\\netlogon.bat'},
                                'exec_selection': {'ParentImage': '*\\userinit.exe'}},
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'}}},
 {'data_source': {'detection': {'condition': 'create_keywords_cli',
                                'create_keywords_cli': {'CommandLine': '*UserInitMprLogonScript*'}},
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'}}},
 {'data_source': {'detection': {'condition': 'create_selection_reg and '
                                             'create_keywords_reg',
                                'create_keywords_reg': {'TargetObject': '*UserInitMprLogonScript*'},
                                'create_selection_reg': {'EventID': [11,
                                                                     12,
                                                                     13,
                                                                     14]}},
                  'logsource': {'product': 'windows', 'service': 'sysmon'}}},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']}]
```

## Potential Queries

```json
[{'name': 'Logon Scripts',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and process_command_line contains '
           '"*REG*ADD*HKCU\\\\Environment*UserInitMprLogonScript*"'}]
```

## Raw Dataset

```json
[{'SysmonHunter - T1037': {'description': None,
                           'level': 'medium',
                           'name': 'Logon Scripts',
                           'phase': 'Persistence',
                           'query': [{'process': {'cmdline': {'pattern': '\\Environment\\UserInitMprLogonScript'}},
                                      'type': 'process'},
                                     {'reg': {'path': {'pattern': '\\Environment\\UserInitMprLogonScript'}},
                                      'type': 'reg'}]}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1037',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/persistence/multi/desktopfile":  '
                                                                                 '["T1037"],',
                                            'Empire Module': 'python/persistence/multi/desktopfile',
                                            'Technique': 'Logon Scripts'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1037',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/persistence/osx/loginhook":  '
                                                                                 '["T1037"],',
                                            'Empire Module': 'python/persistence/osx/loginhook',
                                            'Technique': 'Logon Scripts'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Logon Scripts Mitigation](../mitigations/Logon-Scripts-Mitigation.md)

* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    
* [Restrict Registry Permissions](../mitigations/Restrict-Registry-Permissions.md)
    

# Actors


* [Rocke](../actors/Rocke.md)

