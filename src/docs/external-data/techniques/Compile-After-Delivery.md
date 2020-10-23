
# Compile After Delivery

## Description

### MITRE Description

> Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These payloads will need to be compiled before execution; typically via native utilities such as csc.exe or GCC/MinGW.(Citation: ClearSky MuddyWater Nov 2018)

Source code payloads may also be encrypted, encoded, and/or embedded within other files, such as those delivered as a [Phishing](https://attack.mitre.org/techniques/T1566). Payloads may also be delivered in formats unrecognizable and inherently benign to the native OS (ex: EXEs on macOS/Linux) before later being (re)compiled into a proper executable binary with a bundled compiler and execution framework.(Citation: TrendMicro WindowsAppMac)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Signature-based detection', 'Host intrusion prevention systems', 'Anti-virus', 'Binary Analysis', 'Static File Analysis']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1027/004

## Potential Commands

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Windows\Temp\T1027.004.exe #{input_file}
Invoke-Expression PathToAtomicsFolder\T1027.004\bin\T1027.004_DynamicCompile.exe
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:#{output_file} PathToAtomicsFolder\T1027.004\src\calc.cs
```

## Commands Dataset

```
[{'command': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe '
             '/out:C:\\Windows\\Temp\\T1027.004.exe #{input_file}\n',
  'name': None,
  'source': 'atomics/T1027.004/T1027.004.yaml'},
 {'command': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe '
             '/out:#{output_file} '
             'PathToAtomicsFolder\\T1027.004\\src\\calc.cs\n',
  'name': None,
  'source': 'atomics/T1027.004/T1027.004.yaml'},
 {'command': 'Invoke-Expression '
             'PathToAtomicsFolder\\T1027.004\\bin\\T1027.004_DynamicCompile.exe\n',
  'name': None,
  'source': 'atomics/T1027.004/T1027.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Obfuscated Files or Information: Compile After Delivery': {'atomic_tests': [{'auto_generated_guid': 'ffcdbd6a-b0e8-487d-927a-09127fe9a206',
                                                                                                       'dependencies': [{'description': 'C# '
                                                                                                                                        'file '
                                                                                                                                        'must '
                                                                                                                                        'exist '
                                                                                                                                        'on '
                                                                                                                                        'disk '
                                                                                                                                        'at '
                                                                                                                                        'specified '
                                                                                                                                        'location '
                                                                                                                                        '(#{input_file})\n',
                                                                                                                         'get_prereq_command': 'New-Item '
                                                                                                                                               '-Type '
                                                                                                                                               'Directory '
                                                                                                                                               '(split-path '
                                                                                                                                               '#{input_file}) '
                                                                                                                                               '-ErrorAction '
                                                                                                                                               'ignore '
                                                                                                                                               '| '
                                                                                                                                               'Out-Null\n'
                                                                                                                                               'Invoke-WebRequest '
                                                                                                                                               '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1027.004/src/calc.cs" '
                                                                                                                                               '-OutFile '
                                                                                                                                               '"#{input_file}"\n',
                                                                                                                         'prereq_command': 'if '
                                                                                                                                           '(Test-Path '
                                                                                                                                           '#{input_file}) '
                                                                                                                                           '{exit '
                                                                                                                                           '0} '
                                                                                                                                           'else '
                                                                                                                                           '{exit '
                                                                                                                                           '1}\n'}],
                                                                                                       'dependency_executor_name': 'powershell',
                                                                                                       'description': 'Compile '
                                                                                                                      'C# '
                                                                                                                      'code '
                                                                                                                      'using '
                                                                                                                      'csc.exe '
                                                                                                                      'binary '
                                                                                                                      'used '
                                                                                                                      'by '
                                                                                                                      '.NET\n'
                                                                                                                      'Upon '
                                                                                                                      'execution '
                                                                                                                      'an '
                                                                                                                      'exe '
                                                                                                                      'named '
                                                                                                                      'T1027.004.exe '
                                                                                                                      'will '
                                                                                                                      'be '
                                                                                                                      'placed '
                                                                                                                      'in '
                                                                                                                      'the '
                                                                                                                      'temp '
                                                                                                                      'folder\n',
                                                                                                       'executor': {'cleanup_command': 'del '
                                                                                                                                       '#{output_file} '
                                                                                                                                       '>nul '
                                                                                                                                       '2>&1\n',
                                                                                                                    'command': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe '
                                                                                                                               '/out:#{output_file} '
                                                                                                                               '#{input_file}\n',
                                                                                                                    'name': 'command_prompt'},
                                                                                                       'input_arguments': {'input_file': {'default': 'PathToAtomicsFolder\\T1027.004\\src\\calc.cs',
                                                                                                                                          'description': 'C# '
                                                                                                                                                         'code '
                                                                                                                                                         'that '
                                                                                                                                                         'launches '
                                                                                                                                                         'calc.exe '
                                                                                                                                                         'from '
                                                                                                                                                         'a '
                                                                                                                                                         'hidden '
                                                                                                                                                         'cmd.exe '
                                                                                                                                                         'Window',
                                                                                                                                          'type': 'Path'},
                                                                                                                           'output_file': {'default': 'C:\\Windows\\Temp\\T1027.004.exe',
                                                                                                                                           'description': 'Output '
                                                                                                                                                          'compiled '
                                                                                                                                                          'binary',
                                                                                                                                           'type': 'Path'}},
                                                                                                       'name': 'Compile '
                                                                                                               'After '
                                                                                                               'Delivery '
                                                                                                               'using '
                                                                                                               'csc.exe',
                                                                                                       'supported_platforms': ['windows']},
                                                                                                      {'auto_generated_guid': '453614d8-3ba6-4147-acc0-7ec4b3e1faef',
                                                                                                       'dependencies': [{'description': 'exe '
                                                                                                                                        'file '
                                                                                                                                        'must '
                                                                                                                                        'exist '
                                                                                                                                        'on '
                                                                                                                                        'disk '
                                                                                                                                        'at '
                                                                                                                                        'specified '
                                                                                                                                        'location '
                                                                                                                                        '(#{input_file})\n',
                                                                                                                         'get_prereq_command': 'Invoke-WebRequest '
                                                                                                                                               'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1027.004/bin/T1027.004_DynamicCompile.exe '
                                                                                                                                               '-OutFile '
                                                                                                                                               '#{input_file}\n',
                                                                                                                         'prereq_command': 'if '
                                                                                                                                           '(Test-Path '
                                                                                                                                           '#{input_file}) '
                                                                                                                                           '{exit '
                                                                                                                                           '0} '
                                                                                                                                           'else '
                                                                                                                                           '{exit '
                                                                                                                                           '1}\n'}],
                                                                                                       'dependency_executor_name': 'powershell',
                                                                                                       'description': 'When '
                                                                                                                      'C# '
                                                                                                                      'is '
                                                                                                                      'compiled '
                                                                                                                      'dynamically, '
                                                                                                                      'a '
                                                                                                                      '.cmdline '
                                                                                                                      'file '
                                                                                                                      'will '
                                                                                                                      'be '
                                                                                                                      'created '
                                                                                                                      'as '
                                                                                                                      'a '
                                                                                                                      'part '
                                                                                                                      'of '
                                                                                                                      'the '
                                                                                                                      'process. \n'
                                                                                                                      'Certain '
                                                                                                                      'processes '
                                                                                                                      'are '
                                                                                                                      'not '
                                                                                                                      'typically '
                                                                                                                      'observed '
                                                                                                                      'compiling '
                                                                                                                      'C# '
                                                                                                                      'code, '
                                                                                                                      'but '
                                                                                                                      'can '
                                                                                                                      'do '
                                                                                                                      'so '
                                                                                                                      'without '
                                                                                                                      'touching '
                                                                                                                      'disk. '
                                                                                                                      'This '
                                                                                                                      'can '
                                                                                                                      'be '
                                                                                                                      'used '
                                                                                                                      'to '
                                                                                                                      'unpack '
                                                                                                                      'a '
                                                                                                                      'payload '
                                                                                                                      'for '
                                                                                                                      'execution.\n'
                                                                                                                      'The '
                                                                                                                      'exe '
                                                                                                                      'file '
                                                                                                                      'that '
                                                                                                                      'will '
                                                                                                                      'be '
                                                                                                                      'executed '
                                                                                                                      'is '
                                                                                                                      'named '
                                                                                                                      'as '
                                                                                                                      'T1027.004_DynamicCompile.exe '
                                                                                                                      'is '
                                                                                                                      'containted '
                                                                                                                      'in '
                                                                                                                      'the '
                                                                                                                      "'bin' "
                                                                                                                      'folder '
                                                                                                                      'of '
                                                                                                                      'this '
                                                                                                                      'atomic, '
                                                                                                                      'and '
                                                                                                                      'the '
                                                                                                                      'source '
                                                                                                                      'code '
                                                                                                                      'to '
                                                                                                                      'the '
                                                                                                                      'file '
                                                                                                                      'is '
                                                                                                                      'in '
                                                                                                                      'the '
                                                                                                                      "'src' "
                                                                                                                      'folder.\n'
                                                                                                                      'Upon '
                                                                                                                      'execution, '
                                                                                                                      'the '
                                                                                                                      'exe '
                                                                                                                      'will '
                                                                                                                      'print '
                                                                                                                      "'T1027.004 "
                                                                                                                      'Dynamic '
                                                                                                                      "Compile'.\n",
                                                                                                       'executor': {'command': 'Invoke-Expression '
                                                                                                                               '#{input_file}\n',
                                                                                                                    'name': 'powershell'},
                                                                                                       'input_arguments': {'input_file': {'default': 'PathToAtomicsFolder\\T1027.004\\bin\\T1027.004_DynamicCompile.exe',
                                                                                                                                          'description': 'exe '
                                                                                                                                                         'program '
                                                                                                                                                         'containing '
                                                                                                                                                         'dynamically '
                                                                                                                                                         'compiled '
                                                                                                                                                         'C# '
                                                                                                                                                         'code',
                                                                                                                                          'type': 'Path'}},
                                                                                                       'name': 'Dynamic '
                                                                                                               'C# '
                                                                                                               'Compile',
                                                                                                       'supported_platforms': ['windows']}],
                                                                                     'attack_technique': 'T1027.004',
                                                                                     'display_name': 'Obfuscated '
                                                                                                     'Files '
                                                                                                     'or '
                                                                                                     'Information: '
                                                                                                     'Compile '
                                                                                                     'After '
                                                                                                     'Delivery'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [MuddyWater](../actors/MuddyWater.md)

* [Rocke](../actors/Rocke.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
