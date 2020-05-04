
# DLL Side-Loading

## Description

### MITRE Description

> Programs may specify DLLs that are loaded at runtime. Programs that improperly or vaguely specify a required DLL may be open to a vulnerability in which an unintended DLL is loaded. Side-loading vulnerabilities specifically occur when Windows Side-by-Side (WinSxS) manifests (Citation: MSDN Manifests) are not explicit enough about characteristics of the DLL to be loaded. Adversaries may take advantage of a legitimate program that is vulnerable to side-loading to load a malicious DLL. (Citation: Stewart 2014)

Adversaries likely use this technique as a means of masking actions they perform under a legitimate, trusted system or software process.

## Additional Attributes

* Bypass: ['Process whitelisting', 'Anti-virus']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1073

## Potential Commands

```
#{gup_executable}

PathToAtomicsFolder\T1073\bin\GUP.exe

```

## Commands Dataset

```
[{'command': '#{gup_executable}\n',
  'name': None,
  'source': 'atomics/T1073/T1073.yaml'},
 {'command': 'PathToAtomicsFolder\\T1073\\bin\\GUP.exe\n',
  'name': None,
  'source': 'atomics/T1073/T1073.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - DLL Side-Loading': {'atomic_tests': [{'dependencies': [{'description': 'Gup.exe '
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
                                                                                                        '"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1073/bin/GUP.exe" '
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
                                                                             'elevation_required': False,
                                                                             'name': 'command_prompt'},
                                                                'input_arguments': {'gup_executable': {'default': 'PathToAtomicsFolder\\T1073\\bin\\GUP.exe',
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
                                              'attack_technique': 'T1073',
                                              'display_name': 'DLL '
                                                              'Side-Loading'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

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
    
