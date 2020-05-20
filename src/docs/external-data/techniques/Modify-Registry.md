
# Modify Registry

## Description

### MITRE Description

> Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in Persistence and Execution.

Access to specific areas of the Registry depends on account permissions, some requiring administrator-level access. The built-in Windows command-line utility [Reg](https://attack.mitre.org/software/S0075) may be used for local or remote Registry modification. (Citation: Microsoft Reg) Other tools may also be used, such as a remote access tool, which may contain functionality to interact with the Registry through the Windows API (see examples).

Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via [Reg](https://attack.mitre.org/software/S0075) or other utilities using the Win32 API. (Citation: Microsoft Reghide NOV 2006) Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to establish Persistence. (Citation: TrendMicro POWELIKS AUG 2014) (Citation: SpectorOps Hiding Reg Jul 2017)

The Registry of a remote system may be modified to aid in execution of files as part of Lateral Movement. It requires the remote Registry service to be running on the target system. (Citation: Microsoft Remote) Often [Valid Accounts](https://attack.mitre.org/techniques/T1078) are required, along with access to the remote system's [Windows Admin Shares](https://attack.mitre.org/techniques/T1077) for RPC communication.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Host forensic analysis']
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1112

## Potential Commands

```
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /t REG_DWORD /v HideFileExt /d 1 /f

reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run /t REG_EXPAND_SZ /v SecurityHealth /d calc.exe /f

reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

$key= "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\bad-domain.com\"
$name ="bad-subdomain"
new-item $key -Name $name -Force
new-itemproperty $key$name -Name https -Value 2 -Type DWORD;
new-itemproperty $key$name -Name http  -Value 2 -Type DWORD;
new-itemproperty $key$name -Name *     -Value 2 -Type DWORD;

New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name T1112 -Value "<script>"

powershell/persistence/misc/disable_machine_acct_change
powershell/persistence/misc/disable_machine_acct_change
```

## Commands Dataset

```
[{'command': 'reg add '
             'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced '
             '/t REG_DWORD /v HideFileExt /d 1 /f\n',
  'name': None,
  'source': 'atomics/T1112/T1112.yaml'},
 {'command': 'reg add '
             'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
             '/t REG_EXPAND_SZ /v SecurityHealth /d calc.exe /f\n',
  'name': None,
  'source': 'atomics/T1112/T1112.yaml'},
 {'command': 'reg add '
             'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest '
             '/v UseLogonCredential /t REG_DWORD /d 1 /f\n',
  'name': None,
  'source': 'atomics/T1112/T1112.yaml'},
 {'command': '$key= '
             '"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet '
             'Settings\\ZoneMap\\Domains\\bad-domain.com\\"\n'
             '$name ="bad-subdomain"\n'
             'new-item $key -Name $name -Force\n'
             'new-itemproperty $key$name -Name https -Value 2 -Type DWORD;\n'
             'new-itemproperty $key$name -Name http  -Value 2 -Type DWORD;\n'
             'new-itemproperty $key$name -Name *     -Value 2 -Type DWORD;\n',
  'name': None,
  'source': 'atomics/T1112/T1112.yaml'},
 {'command': 'New-ItemProperty '
             '"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
             'Settings" -Name T1112 -Value "<script>"\n',
  'name': None,
  'source': 'atomics/T1112/T1112.yaml'},
 {'command': 'powershell/persistence/misc/disable_machine_acct_change',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/misc/disable_machine_acct_change',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'action': 'global',
                  'author': 'Florian Roth, Markus Neis',
                  'date': '2018/03/23',
                  'description': 'Detects Chafer activity attributed to OilRig '
                                 'as reported in Nyotron report in March 2018',
                  'detection': {'condition': '1 of them'},
                  'falsepositives': ['Unknown'],
                  'id': '53ba33fd-3a50-4468-a5ef-c583635cfa92',
                  'level': 'critical',
                  'modified': '2019/03/01',
                  'references': ['https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/'],
                  'tags': ['attack.persistence',
                           'attack.g0049',
                           'attack.t1053',
                           'attack.s0111',
                           'attack.defense_evasion',
                           'attack.t1112'],
                  'title': 'Chafer Activity'}},
 {'data_source': {'detection': {'selection_service': {'EventID': 7045,
                                                      'ServiceName': ['SC '
                                                                      'Scheduled '
                                                                      'Scan',
                                                                      'UpdatMachine']}},
                  'logsource': {'product': 'windows', 'service': 'system'}}},
 {'data_source': {'detection': {'selection_service': {'EventID': 4698,
                                                      'TaskName': ['SC '
                                                                   'Scheduled '
                                                                   'Scan',
                                                                   'UpdatMachine']}},
                  'logsource': {'product': 'windows', 'service': 'security'}}},
 {'data_source': {'detection': {'selection_reg1': {'EventID': 13,
                                                   'EventType': 'SetValue',
                                                   'TargetObject': ['*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UMe',
                                                                    '*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UT']},
                                'selection_reg2': {'Details': 'DWORD '
                                                              '(0x00000001)',
                                                   'EventID': 13,
                                                   'EventType': 'SetValue',
                                                   'TargetObject': '*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential'}},
                  'logsource': {'product': 'windows', 'service': 'sysmon'}}},
 {'data_source': {'detection': {'selection_process1': {'CommandLine': ['*\\Service.exe '
                                                                       'i',
                                                                       '*\\Service.exe '
                                                                       'u',
                                                                       '*\\microsoft\\Taskbar\\autoit3.exe',
                                                                       'C:\\wsc.exe*']},
                                'selection_process2': {'Image': '*\\Windows\\Temp\\DB\\\\*.exe'},
                                'selection_process3': {'CommandLine': '*\\nslookup.exe '
                                                                      '-q=TXT*',
                                                       'ParentImage': '*\\Autoit*'}},
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'}}},
 {'data_source': {'author': 'megan201296',
                  'date': '2019/04/14',
                  'description': 'Detects registry keys created in OceanLotus '
                                 '(also known as APT32) attacks',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 13,
                                              'TargetObject': ['*\\SOFTWARE\\Classes\\CLSID\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\\Model',
                                                               '*\\SOFTWARE\\App\\AppXbf13d4ea2945444d8b13e2121cb6b663\\Application',
                                                               '*\\SOFTWARE\\App\\AppXbf13d4ea2945444d8b13e2121cb6b663\\DefaultIcon',
                                                               '*\\SOFTWARE\\App\\AppX70162486c7554f7f80f481985d67586d\\Application',
                                                               '*\\SOFTWARE\\App\\AppX70162486c7554f7f80f481985d67586d\\DefaultIcon',
                                                               '*\\SOFTWARE\\App\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\Application',
                                                               '*\\SOFTWARE\\App\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\DefaultIcon']}},
                  'falsepositives': ['Unknown'],
                  'id': '4ac5fc44-a601-4c06-955b-309df8c4e9d4',
                  'level': 'critical',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://www.welivesecurity.com/2019/03/20/fake-or-fake-keeping-up-with-oceanlotus-decoys/'],
                  'status': 'experimental',
                  'tags': ['attack.t1112'],
                  'title': 'OceanLotus Registry Activity'}},
 {'data_source': {'author': 'Dimitrios Slamaris',
                  'date': '2017/05/15',
                  'description': 'Detects the installation of a Callout DLL '
                                 'via CalloutDlls and CalloutEnabled parameter '
                                 'in Registry, which can be used to execute '
                                 'code in context of the DHCP server (restart '
                                 'required)',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 13,
                                              'TargetObject': ['*\\Services\\DHCPServer\\Parameters\\CalloutDlls',
                                                               '*\\Services\\DHCPServer\\Parameters\\CalloutEnabled']}},
                  'falsepositives': ['unknown'],
                  'id': '9d3436ef-9476-4c43-acca-90ce06bdf33a',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html',
                                 'https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx',
                                 'https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.t1073',
                           'attack.t1112'],
                  'title': 'DHCP Callout DLL installation'}},
 {'data_source': {'author': 'SBousseaden',
                  'date': '2019/10/28',
                  'description': 'IKEEXT and SessionEnv service, as they call '
                                 'LoadLibrary on files that do not exist '
                                 'within C:\\Windows\\System32\\ by default. '
                                 'An attacker can place their malicious logic '
                                 'within the PROCESS_ATTACH block of their '
                                 'library and restart the aforementioned '
                                 'services "svchost.exe -k netsvcs" to gain '
                                 'code execution on a remote machine.',
                  'detection': {'condition': 'selection and not filter',
                                'filter': {'EventID': 7,
                                           'Image': ['*\\svchost.exe'],
                                           'ImageLoaded': ['C:\\Windows\\WinSxS\\*']},
                                'selection': {'EventID': 7,
                                              'Image': ['*\\svchost.exe'],
                                              'ImageLoaded': ['*\\tsmsisrv.dll',
                                                              '*\\tsvipsrv.dll',
                                                              '*\\wlbsctrl.dll']}},
                  'falsepositives': ['Pentest'],
                  'id': '602a1f13-c640-4d73-b053-be9a2fa58b77',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992'],
                  'status': 'experimental',
                  'tags': ['attack.persistence',
                           'attack.defense_evasion',
                           'attack.t1073',
                           'attack.t1038',
                           'attack.t1112'],
                  'title': 'Svchost DLL Search Order Hijack'}},
 {'data_source': {'author': 'megan201296',
                  'date': '2019/02/13',
                  'description': 'Detects new registry key created by Ursnif '
                                 'malware.',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 13,
                                              'TargetObject': '*\\Software\\AppDataLow\\Software\\Microsoft\\\\*'}},
                  'falsepositives': ['Unknown'],
                  'id': '21f17060-b282-4249-ade0-589ea3591558',
                  'level': 'critical',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://blog.yoroi.company/research/ursnif-long-live-the-steganography/',
                                 'https://blog.trendmicro.com/trendlabs-security-intelligence/phishing-campaign-uses-hijacked-emails-to-deliver-ursnif-by-replying-to-ongoing-threads/'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1112'],
                  'title': 'Ursnif'}},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['LMD', 'Reg Compare']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['LOG-MD', 'Reg Compare']}]
```

## Potential Queries

```json
[{'name': 'Modify Registry',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where process_path contains "reg.exe"and file_directory '
           'contains "reg.exe\\" query"'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Modify Registry': {'atomic_tests': [{'auto_generated_guid': '1324796b-d0f6-455a-b4ae-21ffee6aa6b9',
                                                               'description': 'Modify '
                                                                              'the '
                                                                              'registry '
                                                                              'of '
                                                                              'the '
                                                                              'currently '
                                                                              'logged '
                                                                              'in '
                                                                              'user '
                                                                              'using '
                                                                              'reg.exe '
                                                                              'via '
                                                                              'cmd '
                                                                              'console. '
                                                                              'Upon '
                                                                              'execution, '
                                                                              'the '
                                                                              'message '
                                                                              '"The '
                                                                              'operation '
                                                                              'completed '
                                                                              'successfully."\n'
                                                                              'will '
                                                                              'be '
                                                                              'displayed. '
                                                                              'Additionally, '
                                                                              'open '
                                                                              'Registry '
                                                                              'Editor '
                                                                              'to '
                                                                              'view '
                                                                              'the '
                                                                              'new '
                                                                              'entry '
                                                                              'in '
                                                                              'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced.\n',
                                                               'executor': {'cleanup_command': 'reg '
                                                                                               'delete '
                                                                                               'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced '
                                                                                               '/v '
                                                                                               'HideFileExt '
                                                                                               '/f '
                                                                                               '>nul '
                                                                                               '2>&1\n',
                                                                            'command': 'reg '
                                                                                       'add '
                                                                                       'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced '
                                                                                       '/t '
                                                                                       'REG_DWORD '
                                                                                       '/v '
                                                                                       'HideFileExt '
                                                                                       '/d '
                                                                                       '1 '
                                                                                       '/f\n',
                                                                            'elevation_required': True,
                                                                            'name': 'command_prompt'},
                                                               'name': 'Modify '
                                                                       'Registry '
                                                                       'of '
                                                                       'Current '
                                                                       'User '
                                                                       'Profile '
                                                                       '- cmd',
                                                               'supported_platforms': ['windows']},
                                                              {'auto_generated_guid': '282f929a-6bc5-42b8-bd93-960c3ba35afe',
                                                               'description': 'Modify '
                                                                              'the '
                                                                              'Local '
                                                                              'Machine '
                                                                              'registry '
                                                                              'RUN '
                                                                              'key '
                                                                              'to '
                                                                              'change '
                                                                              'Windows '
                                                                              'Defender '
                                                                              'executable '
                                                                              'that '
                                                                              'should '
                                                                              'be '
                                                                              'ran '
                                                                              'on '
                                                                              'startup.  '
                                                                              'This '
                                                                              'should '
                                                                              'only '
                                                                              'be '
                                                                              'possible '
                                                                              'when\n'
                                                                              'CMD '
                                                                              'is '
                                                                              'ran '
                                                                              'as '
                                                                              'Administrative '
                                                                              'rights. '
                                                                              'Upon '
                                                                              'execution, '
                                                                              'the '
                                                                              'message '
                                                                              '"The '
                                                                              'operation '
                                                                              'completed '
                                                                              'successfully."\n'
                                                                              'will '
                                                                              'be '
                                                                              'displayed. '
                                                                              'Additionally, '
                                                                              'open '
                                                                              'Registry '
                                                                              'Editor '
                                                                              'to '
                                                                              'view '
                                                                              'the '
                                                                              'modified '
                                                                              'entry '
                                                                              'in '
                                                                              'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.\n',
                                                               'executor': {'cleanup_command': 'reg '
                                                                                               'delete '
                                                                                               'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                                                                                               '/v '
                                                                                               'SecurityHealth '
                                                                                               '/f '
                                                                                               '>nul '
                                                                                               '2>&1\n',
                                                                            'command': 'reg '
                                                                                       'add '
                                                                                       'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                                                                                       '/t '
                                                                                       'REG_EXPAND_SZ '
                                                                                       '/v '
                                                                                       'SecurityHealth '
                                                                                       '/d '
                                                                                       '#{new_executable} '
                                                                                       '/f\n',
                                                                            'elevation_required': True,
                                                                            'name': 'command_prompt'},
                                                               'input_arguments': {'new_executable': {'default': 'calc.exe',
                                                                                                      'description': 'New '
                                                                                                                     'executable '
                                                                                                                     'to '
                                                                                                                     'run '
                                                                                                                     'on '
                                                                                                                     'startup '
                                                                                                                     'instead '
                                                                                                                     'of '
                                                                                                                     'Windows '
                                                                                                                     'Defender',
                                                                                                      'type': 'string'}},
                                                               'name': 'Modify '
                                                                       'Registry '
                                                                       'of '
                                                                       'Local '
                                                                       'Machine '
                                                                       '- cmd',
                                                               'supported_platforms': ['windows']},
                                                              {'auto_generated_guid': 'c0413fb5-33e2-40b7-9b6f-60b29f4a7a18',
                                                               'description': 'Sets '
                                                                              'registry '
                                                                              'key '
                                                                              'that '
                                                                              'will '
                                                                              'tell '
                                                                              'windows '
                                                                              'to '
                                                                              'store '
                                                                              'plaintext '
                                                                              'passwords '
                                                                              '(making '
                                                                              'the '
                                                                              'system '
                                                                              'vulnerable '
                                                                              'to '
                                                                              'clear '
                                                                              'text '
                                                                              '/ '
                                                                              'cleartext '
                                                                              'password '
                                                                              'dumping).\n'
                                                                              'Upon '
                                                                              'execution, '
                                                                              'the '
                                                                              'message '
                                                                              '"The '
                                                                              'operation '
                                                                              'completed '
                                                                              'successfully." '
                                                                              'will '
                                                                              'be '
                                                                              'displayed.\n'
                                                                              'Additionally, '
                                                                              'open '
                                                                              'Registry '
                                                                              'Editor '
                                                                              'to '
                                                                              'view '
                                                                              'the '
                                                                              'modified '
                                                                              'entry '
                                                                              'in '
                                                                              'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest.\n',
                                                               'executor': {'cleanup_command': 'reg '
                                                                                               'add '
                                                                                               'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest '
                                                                                               '/v '
                                                                                               'UseLogonCredential '
                                                                                               '/t '
                                                                                               'REG_DWORD '
                                                                                               '/d '
                                                                                               '0 '
                                                                                               '/f '
                                                                                               '>nul '
                                                                                               '2>&1\n',
                                                                            'command': 'reg '
                                                                                       'add '
                                                                                       'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest '
                                                                                       '/v '
                                                                                       'UseLogonCredential '
                                                                                       '/t '
                                                                                       'REG_DWORD '
                                                                                       '/d '
                                                                                       '1 '
                                                                                       '/f\n',
                                                                            'elevation_required': True,
                                                                            'name': 'command_prompt'},
                                                               'name': 'Modify '
                                                                       'registry '
                                                                       'to '
                                                                       'store '
                                                                       'logon '
                                                                       'credentials',
                                                               'supported_platforms': ['windows']},
                                                              {'auto_generated_guid': 'cf447677-5a4e-4937-a82c-e47d254afd57',
                                                               'description': 'Attackers '
                                                                              'may '
                                                                              'add '
                                                                              'a '
                                                                              'domain '
                                                                              'to '
                                                                              'the '
                                                                              'trusted '
                                                                              'site '
                                                                              'zone '
                                                                              'to '
                                                                              'bypass '
                                                                              'defenses. '
                                                                              'Doing '
                                                                              'this '
                                                                              'enables '
                                                                              'attacks '
                                                                              'such '
                                                                              'as '
                                                                              'c2 '
                                                                              'over '
                                                                              'office365.\n'
                                                                              'Upon '
                                                                              'execution, '
                                                                              'details '
                                                                              'of '
                                                                              'the '
                                                                              'new '
                                                                              'registry '
                                                                              'entries '
                                                                              'will '
                                                                              'be '
                                                                              'displayed.\n'
                                                                              'Additionally, '
                                                                              'open '
                                                                              'Registry '
                                                                              'Editor '
                                                                              'to '
                                                                              'view '
                                                                              'the '
                                                                              'modified '
                                                                              'entry '
                                                                              'in '
                                                                              'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet '
                                                                              'Settings\\ZoneMap\\.\n'
                                                                              '\n'
                                                                              'https://www.blackhat.com/docs/us-17/wednesday/us-17-Dods-Infecting-The-Enterprise-Abusing-Office365-Powershell-For-Covert-C2.pdf\n',
                                                               'executor': {'cleanup_command': '$key '
                                                                                               '= '
                                                                                               '"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet '
                                                                                               'Settings\\ZoneMap\\Domains\\#{bad_domain}\\"\n'
                                                                                               'Remove-item  '
                                                                                               '$key '
                                                                                               '-Recurse '
                                                                                               '-ErrorAction '
                                                                                               'Ignore\n',
                                                                            'command': '$key= '
                                                                                       '"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet '
                                                                                       'Settings\\ZoneMap\\Domains\\#{bad_domain}\\"\n'
                                                                                       '$name '
                                                                                       '="bad-subdomain"\n'
                                                                                       'new-item '
                                                                                       '$key '
                                                                                       '-Name '
                                                                                       '$name '
                                                                                       '-Force\n'
                                                                                       'new-itemproperty '
                                                                                       '$key$name '
                                                                                       '-Name '
                                                                                       'https '
                                                                                       '-Value '
                                                                                       '2 '
                                                                                       '-Type '
                                                                                       'DWORD;\n'
                                                                                       'new-itemproperty '
                                                                                       '$key$name '
                                                                                       '-Name '
                                                                                       'http  '
                                                                                       '-Value '
                                                                                       '2 '
                                                                                       '-Type '
                                                                                       'DWORD;\n'
                                                                                       'new-itemproperty '
                                                                                       '$key$name '
                                                                                       '-Name '
                                                                                       '*     '
                                                                                       '-Value '
                                                                                       '2 '
                                                                                       '-Type '
                                                                                       'DWORD;\n',
                                                                            'elevation_required': False,
                                                                            'name': 'powershell'},
                                                               'input_arguments': {'bad_domain': {'default': 'bad-domain.com',
                                                                                                  'description': 'Domain '
                                                                                                                 'to '
                                                                                                                 'add '
                                                                                                                 'to '
                                                                                                                 'trusted '
                                                                                                                 'site '
                                                                                                                 'zone',
                                                                                                  'type': 'String'}},
                                                               'name': 'Add '
                                                                       'domain '
                                                                       'to '
                                                                       'Trusted '
                                                                       'sites '
                                                                       'Zone',
                                                               'supported_platforms': ['windows']},
                                                              {'auto_generated_guid': '15f44ea9-4571-4837-be9e-802431a7bfae',
                                                               'description': 'Upon '
                                                                              'execution, '
                                                                              'a '
                                                                              'javascript '
                                                                              'block '
                                                                              'will '
                                                                              'be '
                                                                              'placed '
                                                                              'in '
                                                                              'the '
                                                                              'registry '
                                                                              'for '
                                                                              'persistence.\n'
                                                                              'Additionally, '
                                                                              'open '
                                                                              'Registry '
                                                                              'Editor '
                                                                              'to '
                                                                              'view '
                                                                              'the '
                                                                              'modified '
                                                                              'entry '
                                                                              'in '
                                                                              'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
                                                                              'Settings.\n',
                                                               'executor': {'cleanup_command': 'Remove-ItemProperty '
                                                                                               '"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
                                                                                               'Settings" '
                                                                                               '-Name '
                                                                                               'T1112 '
                                                                                               '-ErrorAction '
                                                                                               'Ignore\n',
                                                                            'command': 'New-ItemProperty '
                                                                                       '"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
                                                                                       'Settings" '
                                                                                       '-Name '
                                                                                       'T1112 '
                                                                                       '-Value '
                                                                                       '"<script>"\n',
                                                                            'elevation_required': False,
                                                                            'name': 'powershell'},
                                                               'name': 'Javascript '
                                                                       'in '
                                                                       'registry',
                                                               'supported_platforms': ['windows']}],
                                             'attack_technique': 'T1112',
                                             'display_name': 'Modify '
                                                             'Registry'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1112',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/misc/disable_machine_acct_change":  '
                                                                                 '["T1112"],',
                                            'Empire Module': 'powershell/persistence/misc/disable_machine_acct_change',
                                            'Technique': 'Modify Registry'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [APT19](../actors/APT19.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT38](../actors/APT38.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [APT32](../actors/APT32.md)
    
* [Turla](../actors/Turla.md)
    
* [APT41](../actors/APT41.md)
    
