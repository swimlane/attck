
# MSBuild

## Description

### MITRE Description

> Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility. MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It handles XML formatted project files that define requirements for loading and building various platforms and configurations.(Citation: MSDN MSBuild)

Adversaries can abuse MSBuild to proxy execution of malicious code. The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# code to be inserted into an XML project file.(Citation: MSDN MSBuild) MSBuild will compile and execute the inline task. MSBuild.exe is a signed Microsoft binary, so when it is used this way it can execute arbitrary code and bypass application control defenses that are configured to allow MSBuild.exe execution.(Citation: LOLBAS Msbuild)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1127/001

## Potential Commands

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe PathToAtomicsFolder\T1127.001\src\T1127.001.csproj
```

## Commands Dataset

```
[{'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe '
             'PathToAtomicsFolder\\T1127.001\\src\\T1127.001.csproj\n',
  'name': None,
  'source': 'atomics/T1127.001/T1127.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Trusted Developer Utilities Proxy Execution: MSBuild': {'atomic_tests': [{'auto_generated_guid': '58742c0f-cb01-44cd-a60b-fb26e8871c93',
                                                                                                    'dependencies': [{'description': 'Project '
                                                                                                                                     'file '
                                                                                                                                     'must '
                                                                                                                                     'exist '
                                                                                                                                     'on '
                                                                                                                                     'disk '
                                                                                                                                     'at '
                                                                                                                                     'specified '
                                                                                                                                     'location '
                                                                                                                                     '(#{filename})\n',
                                                                                                                      'get_prereq_command': 'New-Item '
                                                                                                                                            '-Type '
                                                                                                                                            'Directory '
                                                                                                                                            '(split-path '
                                                                                                                                            '#{filename}) '
                                                                                                                                            '-ErrorAction '
                                                                                                                                            'ignore '
                                                                                                                                            '| '
                                                                                                                                            'Out-Null\n'
                                                                                                                                            'Invoke-WebRequest '
                                                                                                                                            '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1127.001/src/T1127.001.csproj" '
                                                                                                                                            '-OutFile '
                                                                                                                                            '"#{filename}"\n',
                                                                                                                      'prereq_command': 'if '
                                                                                                                                        '(Test-Path '
                                                                                                                                        '#{filename}) '
                                                                                                                                        '{exit '
                                                                                                                                        '0} '
                                                                                                                                        'else '
                                                                                                                                        '{exit '
                                                                                                                                        '1}\n'}],
                                                                                                    'dependency_executor_name': 'powershell',
                                                                                                    'description': 'Executes '
                                                                                                                   'the '
                                                                                                                   'code '
                                                                                                                   'in '
                                                                                                                   'a '
                                                                                                                   'project '
                                                                                                                   'file '
                                                                                                                   'using. '
                                                                                                                   'C# '
                                                                                                                   'Example\n',
                                                                                                    'executor': {'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe '
                                                                                                                            '#{filename}\n',
                                                                                                                 'name': 'command_prompt'},
                                                                                                    'input_arguments': {'filename': {'default': 'PathToAtomicsFolder\\T1127.001\\src\\T1127.001.csproj',
                                                                                                                                     'description': 'Location '
                                                                                                                                                    'of '
                                                                                                                                                    'the '
                                                                                                                                                    'project '
                                                                                                                                                    'file',
                                                                                                                                     'type': 'Path'}},
                                                                                                    'name': 'MSBuild '
                                                                                                            'Bypass '
                                                                                                            'Using '
                                                                                                            'Inline '
                                                                                                            'Tasks',
                                                                                                    'supported_platforms': ['windows']}],
                                                                                  'attack_technique': 'T1127.001',
                                                                                  'display_name': 'Trusted '
                                                                                                  'Developer '
                                                                                                  'Utilities '
                                                                                                  'Proxy '
                                                                                                  'Execution: '
                                                                                                  'MSBuild'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)


# Actors


* [Frankenstein](../actors/Frankenstein.md)

