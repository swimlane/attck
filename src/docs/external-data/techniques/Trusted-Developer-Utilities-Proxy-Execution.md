
# Trusted Developer Utilities Proxy Execution

## Description

### MITRE Description

> Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads. There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering.(Citation: engima0x3 DNX Bypass)(Citation: engima0x3 RCSI Bypass)(Citation: Exploit Monday WinDbg)(Citation: LOLBAS Tracker) These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application control']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1127

## Potential Commands

```
powershell/lateral_movement/invoke_executemsbuild
powershell/code_execution/invoke_ntsd
```

## Commands Dataset

```
[{'command': 'powershell/lateral_movement/invoke_executemsbuild',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/lateral_movement/invoke_executemsbuild',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/code_execution/invoke_ntsd',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/code_execution/invoke_ntsd',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Nik Seetharaman',
                  'description': 'Detects invocation of Microsoft Workflow '
                                 'Compiler, which may permit the execution of '
                                 'arbitrary unsigned code.',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': '*\\Microsoft.Workflow.Compiler.exe'}},
                  'falsepositives': ['Legitimate MWC use (unlikely in modern '
                                     'enterprise environments)'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '419dbf2b-8a9b-4bea-bf99-7544b050ec8d',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1127'],
                  'title': 'Microsoft Workflow Compiler'}},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']}]
```

## Potential Queries

```json
[{'name': 'Trusted Developer Utilities',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_path contains '
           '"MSBuild.exe"or process_path contains "msxsl.exe")'}]
```

## Raw Dataset

```json
[{'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1127',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/lateral_movement/invoke_executemsbuild":  '
                                                                                 '["T1127"],',
                                            'Empire Module': 'powershell/lateral_movement/invoke_executemsbuild',
                                            'Technique': 'Trusted Developer '
                                                         'Utilities'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1127',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/code_execution/invoke_ntsd":  '
                                                                                 '["T1127"],',
                                            'Empire Module': 'powershell/code_execution/invoke_ntsd',
                                            'Technique': 'Trusted Developer '
                                                         'Utilities'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)

* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    

# Actors

None
