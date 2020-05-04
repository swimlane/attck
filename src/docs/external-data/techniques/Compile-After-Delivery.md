
# Compile After Delivery

## Description

### MITRE Description

> Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Similar to [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027), text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These payloads will need to be compiled before execution; typically via native utilities such as csc.exe or GCC/MinGW.(Citation: ClearSky MuddyWater Nov 2018)

Source code payloads may also be encrypted, encoded, and/or embedded within other files, such as those delivered as a [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193). Payloads may also be delivered in formats unrecognizable and inherently benign to the native OS (ex: EXEs on macOS/Linux) before later being (re)compiled into a proper executable binary with a bundled compiler and execution framework.(Citation: TrendMicro WindowsAppMac)


## Additional Attributes

* Bypass: ['Static File Analysis', 'Binary Analysis', 'Anti-virus', 'Host intrusion prevention systems', 'Signature-based detection']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1500

## Potential Commands

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:#{output_file} PathToAtomicsFolder\T1500\src\calc.cs

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Windows\Temp\T1500.exe #{input_file}

```

## Commands Dataset

```
[{'command': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe '
             '/out:#{output_file} PathToAtomicsFolder\\T1500\\src\\calc.cs\n',
  'name': None,
  'source': 'atomics/T1500/T1500.yaml'},
 {'command': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe '
             '/out:C:\\Windows\\Temp\\T1500.exe #{input_file}\n',
  'name': None,
  'source': 'atomics/T1500/T1500.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Compile After Delivery': {'atomic_tests': [{'dependencies': [{'description': 'C# '
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
                                                                                                              '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1500/src/calc.cs" '
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
                                                                                     'T1500.exe '
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
                                                                                   'elevation_required': False,
                                                                                   'name': 'command_prompt'},
                                                                      'input_arguments': {'input_file': {'default': 'PathToAtomicsFolder\\T1500\\src\\calc.cs',
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
                                                                                          'output_file': {'default': 'C:\\Windows\\Temp\\T1500.exe',
                                                                                                          'description': 'Output '
                                                                                                                         'compiled '
                                                                                                                         'binary',
                                                                                                          'type': 'Path'}},
                                                                      'name': 'Compile '
                                                                              'After '
                                                                              'Delivery '
                                                                              'using '
                                                                              'csc.exe',
                                                                      'supported_platforms': ['windows']}],
                                                    'attack_technique': 'T1500',
                                                    'display_name': 'Compile '
                                                                    'After '
                                                                    'Delivery'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [MuddyWater](../actors/MuddyWater.md)

