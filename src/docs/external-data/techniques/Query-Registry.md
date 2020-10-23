
# Query Registry

## Description

### MITRE Description

> Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.

The Registry contains a significant amount of information about the operating system, configuration, software, and security.(Citation: Wikipedia Windows Registry) Information can easily be queried using the [Reg](https://attack.mitre.org/software/S0075) utility, though other means to access the Registry exist. Some of the information may help adversaries to further their operation within a network. Adversaries may use the information from [Query Registry](https://attack.mitre.org/techniques/T1012) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1012

## Potential Commands

```
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections 
shell reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
reg queryval -k "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" -v fDenyTSConnections
post/windows/gather/enum_termserv
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
reg query HKLM\system\currentcontrolset\services /s | findstr ImagePath 2>nul | findstr /Ri ".*\.sys$"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run

{'windows': {'psh': {'command': 'Get-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\n'}}}
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
cmd.exe reg (query|add)
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
cmd.exe reg (query|add)
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
cmd.exe reg (query|add)
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
cmd.exe reg (query|add)
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
cmd.exe reg (query|add)
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
cmd.exe reg (query|add)
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
cmd.exe reg (query|add)
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
powershell/situational_awareness/network/powerview/get_cached_rdpconnection
powershell/situational_awareness/network/powerview/get_cached_rdpconnection
```

## Commands Dataset

```
[{'command': 'reg query '
             '"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
             'Server" /v fDenyTSConnections ',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell reg query '
             '"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
             'Server" /v fDenyTSConnections',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'reg queryval -k '
             '"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
             'Server" -v fDenyTSConnections\n'
             'post/windows/gather/enum_termserv',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Windows"\n'
             'reg query '
             'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\n'
             'reg query '
             'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\n'
             'reg query '
             'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\n'
             'reg query '
             'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\n'
             'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Winlogon\\Notify"\n'
             'reg query "HKLM\\Software\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Winlogon\\Userinit"\n'
             'reg query "HKCU\\Software\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Winlogon\\\\Shell"\n'
             'reg query "HKLM\\Software\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Winlogon\\\\Shell"\n'
             'reg query '
             'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad\n'
             'reg query '
             'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n'
             'reg query '
             'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\n'
             'reg query '
             'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n'
             'reg query '
             'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n'
             'reg query '
             'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n'
             'reg query '
             'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\n'
             'reg query '
             'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\n'
             'reg query HKLM\\system\\currentcontrolset\\services /s | findstr '
             'ImagePath 2>nul | findstr /Ri ".*\\.sys$"\n'
             'reg query '
             'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n',
  'name': None,
  'source': 'atomics/T1012/T1012.yaml'},
 {'command': {'windows': {'psh': {'command': 'Get-ItemProperty -Path '
                                             'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\n'}}},
  'name': 'Query Registry using PowerShell Get-ItemProperty',
  'source': 'data/abilities/discovery/2488245e-bcbd-405d-920e-2de27db882b3.yml'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Winlogon\\Notify',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Winlogon\\Userinit',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKCU\\Software\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Winlogon\\\\Shell',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Winlogon\\\\Shell',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell/situational_awareness/network/powerview/get_cached_rdpconnection',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_cached_rdpconnection',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['Windows Registry']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['LOG-MD Reg Compare', 'Windows Registry']}]
```

## Potential Queries

```json
[{'name': 'Query Registry Network',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 3 and process_path contains "reg.exe" and '
           'process_command_line contains "reg query"'},
 {'name': 'Query Registry Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and process_path contains "reg.exe" and '
           'process_command_line contains "reg query"'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'reg '
                                                                              'query '
                                                                              '"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
                                                                              'Server" '
                                                                              '/v '
                                                                              'fDenyTSConnections ',
                                                  'Category': 'T1012',
                                                  'Cobalt Strike': 'shell reg '
                                                                   'query '
                                                                   '"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
                                                                   'Server" /v '
                                                                   'fDenyTSConnections',
                                                  'Description': 'Check for '
                                                                 'the current '
                                                                 'registry '
                                                                 'value for '
                                                                 'terminal '
                                                                 'services, if '
                                                                 "it's 0, then "
                                                                 'terminal '
                                                                 'services are '
                                                                 'enabled. If '
                                                                 "it's 1, then "
                                                                 "they're "
                                                                 'disabled',
                                                  'Metasploit': 'reg queryval '
                                                                '-k '
                                                                '"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
                                                                'Server" -v '
                                                                'fDenyTSConnections\n'
                                                                'post/windows/gather/enum_termserv'}},
 {'Atomic Red Team Test - Query Registry': {'atomic_tests': [{'auto_generated_guid': '8f7578c4-9863-4d83-875c-a565573bbdf0',
                                                              'description': 'Query '
                                                                             'Windows '
                                                                             'Registry.\n'
                                                                             'Upon '
                                                                             'successful '
                                                                             'execution, '
                                                                             'cmd.exe '
                                                                             'will '
                                                                             'perform '
                                                                             'multiple '
                                                                             'reg '
                                                                             'queries. '
                                                                             'Some '
                                                                             'will '
                                                                             'succeed '
                                                                             'and '
                                                                             'others '
                                                                             'will '
                                                                             'fail '
                                                                             '(dependent '
                                                                             'upon '
                                                                             'OS).\n'
                                                                             'References:\n'
                                                                             'https://blog.cylance.com/windows-registry-persistence-part-2-the-run-keys-and-search-order\n'
                                                                             'https://blog.cylance.com/windows-registry-persistence-part-1-introduction-attack-phases-and-windows-services\n'
                                                                             'http://www.handgrep.se/repository/cheatsheets/postexploitation/WindowsPost-Exploitation.pdf\n'
                                                                             'https://www.offensive-security.com/wp-content/uploads/2015/04/wp.Registry_Quick_Find_Chart.en_us.pdf\n',
                                                              'executor': {'command': 'reg '
                                                                                      'query '
                                                                                      '"HKLM\\SOFTWARE\\Microsoft\\Windows '
                                                                                      'NT\\CurrentVersion\\Windows"\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      '"HKLM\\SOFTWARE\\Microsoft\\Windows '
                                                                                      'NT\\CurrentVersion\\Winlogon\\Notify"\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      '"HKLM\\Software\\Microsoft\\Windows '
                                                                                      'NT\\CurrentVersion\\Winlogon\\Userinit"\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      '"HKCU\\Software\\Microsoft\\Windows '
                                                                                      'NT\\CurrentVersion\\Winlogon\\\\Shell"\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      '"HKLM\\Software\\Microsoft\\Windows '
                                                                                      'NT\\CurrentVersion\\Winlogon\\\\Shell"\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKLM\\system\\currentcontrolset\\services '
                                                                                      '/s '
                                                                                      '| '
                                                                                      'findstr '
                                                                                      'ImagePath '
                                                                                      '2>nul '
                                                                                      '| '
                                                                                      'findstr '
                                                                                      '/Ri '
                                                                                      '".*\\.sys$"\n'
                                                                                      'reg '
                                                                                      'query '
                                                                                      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n',
                                                                           'elevation_required': True,
                                                                           'name': 'command_prompt'},
                                                              'name': 'Query '
                                                                      'Registry',
                                                              'supported_platforms': ['windows']}],
                                            'attack_technique': 'T1012',
                                            'display_name': 'Query Registry'}},
 {'Mitre Stockpile - Query Registry using PowerShell Get-ItemProperty': {'description': 'Query '
                                                                                        'Registry '
                                                                                        'using '
                                                                                        'PowerShell '
                                                                                        'Get-ItemProperty',
                                                                         'id': '2488245e-bcbd-405d-920e-2de27db882b3',
                                                                         'name': 'Query '
                                                                                 'Registry',
                                                                         'platforms': {'windows': {'psh': {'command': 'Get-ItemProperty '
                                                                                                                      '-Path '
                                                                                                                      'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\n'}}},
                                                                         'tactic': 'discovery',
                                                                         'technique': {'attack_id': 'T1012',
                                                                                       'name': 'Query '
                                                                                               'Registry'}}},
 {'Threat Hunting Tables': {'chain_id': '100148',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\Windows',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100149',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100150',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100151',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100152',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100153',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\Winlogon\\Notify',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100154',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\Winlogon\\Userinit',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100155',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKCU\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\Winlogon\\\\Shell',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100156',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\Winlogon\\\\Shell',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100157',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100158',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100159',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100160',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100161',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100162',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100163',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100164',
                            'commandline_string': 'reg (query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1012',
                            'mitre_caption': 'query_registry',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1012',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_cached_rdpconnection":  '
                                                                                 '["T1012"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_cached_rdpconnection',
                                            'Technique': 'Query Registry'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [Query Registry Mitigation](../mitigations/Query-Registry-Mitigation.md)


# Actors


* [Turla](../actors/Turla.md)

* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [APT32](../actors/APT32.md)
    
