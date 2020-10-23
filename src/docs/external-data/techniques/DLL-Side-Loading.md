
# DLL Side-Loading

## Description

### MITRE Description

> Adversaries may execute their own malicious payloads by hijacking the library manifest used to load DLLs. Adversaries may take advantage of vague references in the library manifest of a program by replacing a legitimate library with a malicious one, causing the operating system to load their malicious library when it is called for by the victim program.

Programs may specify DLLs that are loaded at runtime. Programs that improperly or vaguely specify a required DLL may be open to a vulnerability in which an unintended DLL is loaded. Side-loading vulnerabilities specifically occur when Windows Side-by-Side (WinSxS) manifests (Citation: About Side by Side Assemblies) are not explicit enough about characteristics of the DLL to be loaded. Adversaries may take advantage of a legitimate program that is vulnerable by replacing the legitimate DLL with a malicious one.  (Citation: FireEye DLL Side-Loading)

Adversaries likely use this technique as a means of masking actions they perform under a legitimate, trusted system or software process.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti-virus', 'Application control']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1574/002

## Potential Commands

```
PathToAtomicsFolder\T1574.002\bin\GUP.exe
#{gup_executable}
```

## Commands Dataset

```
[{'command': '#{gup_executable}\n',
  'name': None,
  'source': 'atomics/T1574.002/T1574.002.yaml'},
 {'command': 'PathToAtomicsFolder\\T1574.002\\bin\\GUP.exe\n',
  'name': None,
  'source': 'atomics/T1574.002/T1574.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Hijack Execution Flow: DLL Side-Loading': {'atomic_tests': [{'auto_generated_guid': '65526037-7079-44a9-bda1-2cb624838040',
                                                                                       'dependencies': [{'description': 'Gup.exe '
                                                                                                                        'binary '
                                                                                                                        'must '
                                                                                                                        'exist '
                                                                                                                        'on '
                                                                                                                        'disk '
                                                                                                                        'at '
                                                                                                                        'specified '
                                                                                                                        'location '
                                                                                                                        '(#{gup_executable})\n',
                                                                                                         'get_prereq_command': 'New-Item '
                                                                                                                               '-Type '
                                                                                                                               'Directory '
                                                                                                                               '(split-path '
                                                                                                                               '#{gup_executable}) '
                                                                                                                               '-ErrorAction '
                                                                                                                               'ignore '
                                                                                                                               '| '
                                                                                                                               'Out-Null\n'
                                                                                                                               'Invoke-WebRequest '
                                                                                                                               '"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.002/bin/GUP.exe" '
                                                                                                                               '-OutFile '
                                                                                                                               '"#{gup_executable}"\n',
                                                                                                         'prereq_command': 'if '
                                                                                                                           '(Test-Path '
                                                                                                                           '#{gup_executable}) '
                                                                                                                           '{exit '
                                                                                                                           '0} '
                                                                                                                           'else '
                                                                                                                           '{exit '
                                                                                                                           '1}\n'}],
                                                                                       'dependency_executor_name': 'powershell',
                                                                                       'description': 'GUP '
                                                                                                      'is '
                                                                                                      'an '
                                                                                                      'open '
                                                                                                      'source '
                                                                                                      'signed '
                                                                                                      'binary '
                                                                                                      'used '
                                                                                                      'by '
                                                                                                      'Notepad++ '
                                                                                                      'for '
                                                                                                      'software '
                                                                                                      'updates, '
                                                                                                      'and '
                                                                                                      'is '
                                                                                                      'vulnerable '
                                                                                                      'to '
                                                                                                      'DLL '
                                                                                                      'Side-Loading, '
                                                                                                      'thus '
                                                                                                      'enabling '
                                                                                                      'the '
                                                                                                      'libcurl '
                                                                                                      'dll '
                                                                                                      'to '
                                                                                                      'be '
                                                                                                      'loaded.\n'
                                                                                                      'Upon '
                                                                                                      'execution, '
                                                                                                      'calc.exe '
                                                                                                      'will '
                                                                                                      'be '
                                                                                                      'opened.\n',
                                                                                       'executor': {'cleanup_command': 'taskkill '
                                                                                                                       '/F '
                                                                                                                       '/IM '
                                                                                                                       '#{process_name} '
                                                                                                                       '>nul '
                                                                                                                       '2>&1\n',
                                                                                                    'command': '#{gup_executable}\n',
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'gup_executable': {'default': 'PathToAtomicsFolder\\T1574.002\\bin\\GUP.exe',
                                                                                                                              'description': 'GUP '
                                                                                                                                             'is '
                                                                                                                                             'an '
                                                                                                                                             'open '
                                                                                                                                             'source '
                                                                                                                                             'signed '
                                                                                                                                             'binary '
                                                                                                                                             'used '
                                                                                                                                             'by '
                                                                                                                                             'Notepad++ '
                                                                                                                                             'for '
                                                                                                                                             'software '
                                                                                                                                             'updates',
                                                                                                                              'type': 'path'},
                                                                                                           'process_name': {'default': 'calculator.exe',
                                                                                                                            'description': 'Name '
                                                                                                                                           'of '
                                                                                                                                           'the '
                                                                                                                                           'created '
                                                                                                                                           'process',
                                                                                                                            'type': 'string'}},
                                                                                       'name': 'DLL '
                                                                                               'Side-Loading '
                                                                                               'using '
                                                                                               'the '
                                                                                               'Notepad++ '
                                                                                               'GUP.exe '
                                                                                               'binary',
                                                                                       'supported_platforms': ['windows']}],
                                                                     'attack_technique': 'T1574.002',
                                                                     'display_name': 'Hijack '
                                                                                     'Execution '
                                                                                     'Flow: '
                                                                                     'DLL '
                                                                                     'Side-Loading'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Update Software](../mitigations/Update-Software.md)

* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    
* [Audit](../mitigations/Audit.md)
    

# Actors


* [Patchwork](../actors/Patchwork.md)

* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT19](../actors/APT19.md)
    
* [menuPass](../actors/menuPass.md)
    
* [APT3](../actors/APT3.md)
    
* [APT32](../actors/APT32.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
* [Naikon](../actors/Naikon.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
