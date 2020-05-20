
# Control Panel Items

## Description

### MITRE Description

> Windows Control Panel items are utilities that allow users to view and adjust computer settings. Control Panel items are registered executable (.exe) or Control Panel (.cpl) files, the latter are actually renamed dynamic-link library (.dll) files that export a CPlApplet function. (Citation: Microsoft Implementing CPL) (Citation: TrendMicro CPL Malware Jan 2014) Control Panel items can be executed directly from the command line, programmatically via an application programming interface (API) call, or by simply double-clicking the file. (Citation: Microsoft Implementing CPL) (Citation: TrendMicro CPL Malware Jan 2014) (Citation: TrendMicro CPL Malware Dec 2013)

For ease of use, Control Panel items typically include graphical menus available to users after being registered and loaded into the Control Panel. (Citation: Microsoft Implementing CPL)

Adversaries can use Control Panel items as execution payloads to execute arbitrary commands. Malicious Control Panel items can be delivered via [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) campaigns (Citation: TrendMicro CPL Malware Jan 2014) (Citation: TrendMicro CPL Malware Dec 2013) or executed as part of multi-stage malware. (Citation: Palo Alto Reaver Nov 2017) Control Panel items, specifically CPL files, may also bypass application and/or file extension whitelisting.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application whitelisting', 'Process whitelisting']
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1196

## Potential Commands

```
control.exe PathToAtomicsFolder\T1196\bin\calc.cpl

\\Windows\\.+\\control.exe
Shell32.dll,Control_RunDLLAsUser|.cpl
```

## Commands Dataset

```
[{'command': 'control.exe PathToAtomicsFolder\\T1196\\bin\\calc.cpl\n',
  'name': None,
  'source': 'atomics/T1196/T1196.yaml'},
 {'command': '\\\\Windows\\\\.+\\\\control.exe',
  'name': None,
  'source': 'SysmonHunter - Control Panel Items'},
 {'command': 'Shell32.dll,Control_RunDLLAsUser|.cpl',
  'name': None,
  'source': 'SysmonHunter - Control Panel Items'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Kyaw Min Thein',
                  'date': '2019/08/27',
                  'description': 'Detects the use of a control panel item '
                                 '(.cpl) outside of the System32 folder',
                  'detection': {'condition': 'selection and not filter',
                                'filter': {'CommandLine': ['*\\System32\\\\*',
                                                           '*%System%*']},
                                'selection': {'CommandLine': '*.cpl'}},
                  'falsepositives': ['Unknown'],
                  'id': '0ba863e6-def5-4e50-9cea-4dd8c7dc46a4',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'reference': ['https://attack.mitre.org/techniques/T1196/'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.t1196',
                           'attack.defense_evasion'],
                  'title': 'Control Panel Items'}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['Windows event logs']},
 {'data_source': ['API monitoring']},
 {'data_source': ['Binary file metadata']},
 {'data_source': ['DLL monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['Windows event logs']},
 {'data_source': ['LOG-MD - B9', 'Binary file metadata']},
 {'data_source': ['Sysmon ID 7', 'DLL monitoring']},
 {'data_source': ['API monitoring']}]
```

## Potential Queries

```json
[{'name': 'Control Panel Items Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_command_line contains '
           '"control \\\\/name"or process_commandline contains "rundll32 '
           'shell32.dll,Control_RunDLL")'},
 {'name': 'Control Panel Items Registry',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           '(registry_key_path contains '
           '"\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\ControlPanel\\\\NameSpace"or '
           'registry_key_path contains '
           '"\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Controls '
           'Folder\\\\*\\\\Shellex\\\\PropertySheetHandlers\\\\"or '
           'registry_key_path contains '
           '"\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Control '
           'Panel\\\\")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Control Panel Items': {'atomic_tests': [{'auto_generated_guid': '037e9d8a-9e46-4255-8b33-2ae3b545ca6f',
                                                                   'dependencies': [{'description': 'Cpl '
                                                                                                    'file '
                                                                                                    'must '
                                                                                                    'exist '
                                                                                                    'on '
                                                                                                    'disk '
                                                                                                    'at '
                                                                                                    'specified '
                                                                                                    'location '
                                                                                                    '(#{cpl_file_path})\n',
                                                                                     'get_prereq_command': 'New-Item '
                                                                                                           '-Type '
                                                                                                           'Directory '
                                                                                                           '(split-path '
                                                                                                           '#{cpl_file_path}) '
                                                                                                           '-ErrorAction '
                                                                                                           'ignore '
                                                                                                           '| '
                                                                                                           'Out-Null\n'
                                                                                                           'Invoke-WebRequest '
                                                                                                           '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1196/bin/calc.cpl" '
                                                                                                           '-OutFile '
                                                                                                           '"#{cpl_file_path}"\n',
                                                                                     'prereq_command': 'if '
                                                                                                       '(Test-Path '
                                                                                                       '#{cpl_file_path}) '
                                                                                                       '{exit '
                                                                                                       '0} '
                                                                                                       'else '
                                                                                                       '{exit '
                                                                                                       '1}\n'}],
                                                                   'dependency_executor_name': 'powershell',
                                                                   'description': 'This '
                                                                                  'test '
                                                                                  'simulates '
                                                                                  'an '
                                                                                  'adversary '
                                                                                  'leveraging '
                                                                                  'control.exe\n'
                                                                                  'Upon '
                                                                                  'execution '
                                                                                  'calc.exe '
                                                                                  'will '
                                                                                  'be '
                                                                                  'launched\n',
                                                                   'executor': {'command': 'control.exe '
                                                                                           '#{cpl_file_path}\n',
                                                                                'elevation_required': False,
                                                                                'name': 'command_prompt'},
                                                                   'input_arguments': {'cpl_file_path': {'default': 'PathToAtomicsFolder\\T1196\\bin\\calc.cpl',
                                                                                                         'description': 'path '
                                                                                                                        'to '
                                                                                                                        'cpl '
                                                                                                                        'file',
                                                                                                         'type': 'path'}},
                                                                   'name': 'Control '
                                                                           'Panel '
                                                                           'Items',
                                                                   'supported_platforms': ['windows']}],
                                                 'attack_technique': 'T1196',
                                                 'display_name': 'Control '
                                                                 'Panel '
                                                                 'Items'}},
 {'SysmonHunter - T1196': {'description': None,
                           'level': 'medium',
                           'name': 'Control Panel Items',
                           'phase': 'Execution',
                           'query': [{'process': {'image': {'flag': 'regex',
                                                            'pattern': '\\\\Windows\\\\.+\\\\control.exe'}},
                                      'type': 'process'},
                                     {'process': {'cmdline': {'op': 'and',
                                                              'pattern': 'Shell32.dll,Control_RunDLLAsUser|.cpl'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Execution](../tactics/Execution.md)
    

# Mitigations

None

# Actors

None
