
# Control Panel

## Description

### MITRE Description

> Adversaries may abuse control.exe to proxy execution of malicious payloads. The Windows Control Panel process binary (control.exe) handles execution of Control Panel items, which are utilities that allow users to view and adjust computer settings. Control Panel items are registered executable (.exe) or Control Panel (.cpl) files, the latter are actually renamed dynamic-link library (.dll) files that export a <code>CPlApplet</code> function. (Citation: Microsoft Implementing CPL) (Citation: TrendMicro CPL Malware Jan 2014) Control Panel items can be executed directly from the command line, programmatically via an application programming interface (API) call, or by simply double-clicking the file. (Citation: Microsoft Implementing CPL) (Citation: TrendMicro CPL Malware Jan 2014) (Citation: TrendMicro CPL Malware Dec 2013)

For ease of use, Control Panel items typically include graphical menus available to users after being registered and loaded into the Control Panel. (Citation: Microsoft Implementing CPL)

Malicious Control Panel items can be delivered via [Phishing](https://attack.mitre.org/techniques/T1566) campaigns (Citation: TrendMicro CPL Malware Jan 2014) (Citation: TrendMicro CPL Malware Dec 2013) or executed as part of multi-stage malware. (Citation: Palo Alto Reaver Nov 2017) Control Panel items, specifically CPL files, may also bypass application and/or file extension allow lists.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application control']
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1218/002

## Potential Commands

```
control.exe PathToAtomicsFolder\T1218.002\bin\calc.cpl
```

## Commands Dataset

```
[{'command': 'control.exe PathToAtomicsFolder\\T1218.002\\bin\\calc.cpl\n',
  'name': None,
  'source': 'atomics/T1218.002/T1218.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Signed Binary Proxy Execution: Control Panel': {'atomic_tests': [{'auto_generated_guid': '037e9d8a-9e46-4255-8b33-2ae3b545ca6f',
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
                                                                                                                                    '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.002/bin/calc.cpl" '
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
                                                                                                         'name': 'command_prompt'},
                                                                                            'input_arguments': {'cpl_file_path': {'default': 'PathToAtomicsFolder\\T1218.002\\bin\\calc.cpl',
                                                                                                                                  'description': 'path '
                                                                                                                                                 'to '
                                                                                                                                                 'cpl '
                                                                                                                                                 'file',
                                                                                                                                  'type': 'path'}},
                                                                                            'name': 'Control '
                                                                                                    'Panel '
                                                                                                    'Items',
                                                                                            'supported_platforms': ['windows']}],
                                                                          'attack_technique': 'T1218.002',
                                                                          'display_name': 'Signed '
                                                                                          'Binary '
                                                                                          'Proxy '
                                                                                          'Execution: '
                                                                                          'Control '
                                                                                          'Panel'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)

* [Execution Prevention](../mitigations/Execution-Prevention.md)
    

# Actors

None
