
# New Service

## Description

### MITRE Description

> When operating systems boot up, they can start programs or applications called services that perform background system functions. (Citation: TechNet Services) A service's configuration information, including the file path to the service's executable, is stored in the Windows Registry. 

Adversaries may install a new service that can be configured to execute at startup by using utilities to interact with services or by directly modifying the Registry. The service name may be disguised by using a name from a related operating system or benign software with [Masquerading](https://attack.mitre.org/techniques/T1036). Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges from administrator to SYSTEM. Adversaries may also directly start services through [Service Execution](https://attack.mitre.org/techniques/T1035).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: ['SYSTEM']
* Network: None
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1050

## Potential Commands

```
sc.exe create #{service_name} binPath= PathToAtomicsFolder\T1050\bin\AtomicService.exe
sc.exe start #{service_name}

sc.exe create AtomicTestService binPath= #{binary_path}
sc.exe start AtomicTestService

New-Service -Name "#{service_name}" -BinaryPathName "PathToAtomicsFolder\T1050\bin\AtomicService.exe"
Start-Service -Name "#{service_name}"

New-Service -Name "AtomicTestService" -BinaryPathName "#{binary_path}"
Start-Service -Name "AtomicTestService"

*.exe (query|add)
\AppData\*
HKCU\software\Microsoft\Windows\CurrentVersion\Run\*
*.exe (query|add)
$Recycle.bin\*
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*
*.exe (query|add)
Temp\*
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*
*.exe (query|add)
Users\Public\*
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*
*.exe (query|add)
Users\Default\*
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*
*.exe (query|add)
HKEY_USERS\*\Classes\exefile\shell\runas\command\isolatedCommand
powershell/privesc/powerup/service_exe_restore
powershell/privesc/powerup/service_exe_restore
powershell/privesc/powerup/service_exe_stager
powershell/privesc/powerup/service_exe_stager
powershell/privesc/powerup/service_exe_useradd
powershell/privesc/powerup/service_exe_useradd
powershell/privesc/powerup/service_stager
powershell/privesc/powerup/service_stager
```

## Commands Dataset

```
[{'command': 'sc.exe create #{service_name} binPath= '
             'PathToAtomicsFolder\\T1050\\bin\\AtomicService.exe\n'
             'sc.exe start #{service_name}\n',
  'name': None,
  'source': 'atomics/T1050/T1050.yaml'},
 {'command': 'sc.exe create AtomicTestService binPath= #{binary_path}\n'
             'sc.exe start AtomicTestService\n',
  'name': None,
  'source': 'atomics/T1050/T1050.yaml'},
 {'command': 'New-Service -Name "#{service_name}" -BinaryPathName '
             '"PathToAtomicsFolder\\T1050\\bin\\AtomicService.exe"\n'
             'Start-Service -Name "#{service_name}"\n',
  'name': None,
  'source': 'atomics/T1050/T1050.yaml'},
 {'command': 'New-Service -Name "AtomicTestService" -BinaryPathName '
             '"#{binary_path}"\n'
             'Start-Service -Name "AtomicTestService"\n',
  'name': None,
  'source': 'atomics/T1050/T1050.yaml'},
 {'command': '*.exe (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': '\\AppData\\*',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'HKCU\\software\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': '$Recycle.bin\\*',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'Temp\\*', 'name': 'file_path', 'source': 'Threat Hunting Tables'},
 {'command': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'Users\\Public\\*',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'Users\\Default\\*',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe (query|add)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKEY_USERS\\*\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell/privesc/powerup/service_exe_restore',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/powerup/service_exe_restore',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/powerup/service_exe_stager',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/powerup/service_exe_stager',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/powerup/service_exe_useradd',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/powerup/service_exe_useradd',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/powerup/service_stager',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/powerup/service_stager',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'action': 'global',
                  'description': 'This method detects malicious services '
                                 'mentioned in APT29 report by FireEye. The '
                                 'legitimate path for the Google update '
                                 'service is C:\\Program Files '
                                 '(x86)\\Google\\Update\\GoogleUpdate.exe so '
                                 'the service names and executable locations '
                                 'used by APT29 are specific enough to be '
                                 'detected in log files.',
                  'detection': {'condition': 'service_install | near process',
                                'service_install': {'EventID': 7045,
                                                    'ServiceName': 'Google '
                                                                   'Update'},
                                'timeframe': '5m'},
                  'falsepositives': ['Unknown'],
                  'id': 'c069f460-2b87-4010-8dcf-e45bab362624',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'system'},
                  'references': ['https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html'],
                  'tags': ['attack.persistence',
                           'attack.g0016',
                           'attack.t1050'],
                  'title': 'APT29 Google Update Service Install'}},
 {'data_source': {'detection': {'process': {'Image': ['C:\\Program '
                                                      'Files(x86)\\Google\\GoogleService.exe',
                                                      'C:\\Program '
                                                      'Files(x86)\\Google\\GoogleUpdate.exe']}},
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'}}},
 {'data_source': {'description': 'This method detects a service install of '
                                 'malicious services mentioned in Carbon Paper '
                                 '- Turla report by ESET',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 7045,
                                              'ServiceName': ['srservice',
                                                              'ipvpn',
                                                              'hkmsvc']}},
                  'falsepositives': ['Unknown'],
                  'id': '1df8b3da-b0ac-4d8a-b7c7-6cb7c24160e4',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'system'},
                  'references': ['https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/'],
                  'tags': ['attack.persistence',
                           'attack.g0010',
                           'attack.t1050'],
                  'title': 'Turla Service Install'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'This method detects a service install of the '
                                 'malicious Microsoft Network Realtime '
                                 'Inspection Service service described in '
                                 'StoneDrill report by Kaspersky',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 7045,
                                              'ServiceFileName': '* '
                                                                 'LocalService',
                                              'ServiceName': 'NtsSrv'}},
                  'falsepositives': ['Unlikely'],
                  'id': '9e987c6c-4c1e-40d8-bd85-dd26fba8fdd6',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'system'},
                  'references': ['https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/'],
                  'tags': ['attack.persistence',
                           'attack.g0064',
                           'attack.t1050'],
                  'title': 'StoneDrill Service Install'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2018/11/23',
                  'description': 'This method detects malicious services '
                                 'mentioned in Turla PNG dropper report by NCC '
                                 'Group in November 2018',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 7045,
                                              'ServiceName': 'WerFaultSvc'}},
                  'falsepositives': ['unlikely'],
                  'id': '1228f8e2-7e79-4dea-b0ad-c91f1d5016c1',
                  'level': 'critical',
                  'logsource': {'product': 'windows', 'service': 'system'},
                  'references': ['https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/november/turla-png-dropper-is-back/'],
                  'tags': ['attack.persistence',
                           'attack.g0010',
                           'attack.t1050'],
                  'title': 'Turla PNG Dropper Service'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects a driver load from a temporary '
                                 'directory',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 6,
                                              'ImageLoaded': '*\\Temp\\\\*'}},
                  'falsepositives': ['there is a relevant set of false '
                                     'positives depending on applications in '
                                     'the environment'],
                  'id': '2c4523d5-d481-4ed0-8ec3-7fbf0cb41a75',
                  'level': 'medium',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'tags': ['attack.persistence', 'attack.t1050'],
                  'title': 'Suspicious Driver Load from Temp'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects known malicious service installs '
                                 'that only appear in cases of lateral '
                                 'movement, credential dumping and other '
                                 'suspicious activity',
                  'detection': {'condition': 'selection and 1 of malsvc_*',
                                'malsvc_others': {'ServiceName': ['pwdump*',
                                                                  'gsecdump*',
                                                                  'cachedump*']},
                                'malsvc_paexec': {'ServiceFileName': '*\\PAExec*'},
                                'malsvc_persistence': {'ServiceFileName': '* '
                                                                          'net '
                                                                          'user '
                                                                          '*'},
                                'malsvc_pwdumpx': {'ServiceFileName': '*\\DumpSvc.exe'},
                                'malsvc_wannacry': {'ServiceName': 'mssecsvc2.0'},
                                'malsvc_wce': {'ServiceName': ['WCESERVICE',
                                                               'WCE SERVICE']},
                                'malsvc_winexe': {'ServiceFileName': 'winexesvc.exe*'},
                                'selection': {'EventID': 7045}},
                  'falsepositives': ['Penetration testing'],
                  'id': '5a105d34-05fc-401e-8553-272b45c1522d',
                  'level': 'critical',
                  'logsource': {'product': 'windows', 'service': 'system'},
                  'tags': ['attack.persistence',
                           'attack.privilege_escalation',
                           'attack.t1050',
                           'car.2013-09-005'],
                  'title': 'Malicious Service Installations'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects rare service installs that only '
                                 'appear a few times per time frame and could '
                                 'reveal password dumpers, backdoor installs '
                                 'or other types of malicious services',
                  'detection': {'condition': 'selection | count() by '
                                             'ServiceFileName < 5',
                                'selection': {'EventID': 7045},
                                'timeframe': '7d'},
                  'falsepositives': ['Software installation',
                                     'Software updates'],
                  'id': '66bfef30-22a5-4fcd-ad44-8d81e60922ae',
                  'level': 'low',
                  'logsource': {'product': 'windows', 'service': 'system'},
                  'status': 'experimental',
                  'tags': ['attack.persistence',
                           'attack.privilege_escalation',
                           'attack.t1050',
                           'car.2013-09-005'],
                  'title': 'Rare Service Installs'}},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']}]
```

## Potential Queries

```json
[{'name': 'New Service Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains "sc.exe"or '
           'process_path contains "powershell.exe"or process_path contains '
           '"cmd.exe")and (process_command_line contains '
           '"*New-Service*BinaryPathName*"or process_command_line contains '
           '"*sc*create*binpath*"or process_command_line contains '
           '"*Get-WmiObject*Win32_Service*create*")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Service Installation': {'atomic_tests': [{'auto_generated_guid': '981e2942-e433-44e9-afc1-8c957a1496b6',
                                                                    'dependencies': [{'description': 'Service '
                                                                                                     'binary '
                                                                                                     'must '
                                                                                                     'exist '
                                                                                                     'on '
                                                                                                     'disk '
                                                                                                     'at '
                                                                                                     'specified '
                                                                                                     'location '
                                                                                                     '(#{binary_path})\n',
                                                                                      'get_prereq_command': 'New-Item '
                                                                                                            '-Type '
                                                                                                            'Directory '
                                                                                                            '(split-path '
                                                                                                            '#{binary_path}) '
                                                                                                            '-ErrorAction '
                                                                                                            'ignore '
                                                                                                            '| '
                                                                                                            'Out-Null\n'
                                                                                                            'Invoke-WebRequest '
                                                                                                            '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1050/bin/AtomicService.exe" '
                                                                                                            '-OutFile '
                                                                                                            '"#{binary_path}"\n',
                                                                                      'prereq_command': 'if '
                                                                                                        '(Test-Path '
                                                                                                        '#{binary_path}) '
                                                                                                        '{exit '
                                                                                                        '0} '
                                                                                                        'else '
                                                                                                        '{exit '
                                                                                                        '1}\n'}],
                                                                    'dependency_executor_name': 'powershell',
                                                                    'description': 'Download '
                                                                                   'an '
                                                                                   'executable '
                                                                                   'from '
                                                                                   'github '
                                                                                   'and '
                                                                                   'start '
                                                                                   'it '
                                                                                   'as '
                                                                                   'a '
                                                                                   'service.\n'
                                                                                   '\n'
                                                                                   'Upon '
                                                                                   'successful '
                                                                                   'execution, '
                                                                                   'powershell '
                                                                                   'will '
                                                                                   'download '
                                                                                   '`AtomicService.exe` '
                                                                                   'from '
                                                                                   'github. '
                                                                                   'cmd.exe '
                                                                                   'will '
                                                                                   'spawn '
                                                                                   'sc.exe '
                                                                                   'which '
                                                                                   'will '
                                                                                   'create '
                                                                                   'and '
                                                                                   'start '
                                                                                   'the '
                                                                                   'service. '
                                                                                   'Results '
                                                                                   'will '
                                                                                   'output '
                                                                                   'via '
                                                                                   'stdout.\n',
                                                                    'executor': {'cleanup_command': 'sc.exe '
                                                                                                    'stop '
                                                                                                    '#{service_name} '
                                                                                                    '>nul '
                                                                                                    '2>&1\n'
                                                                                                    'sc.exe '
                                                                                                    'delete '
                                                                                                    '#{service_name} '
                                                                                                    '>nul '
                                                                                                    '2>&1\n',
                                                                                 'command': 'sc.exe '
                                                                                            'create '
                                                                                            '#{service_name} '
                                                                                            'binPath= '
                                                                                            '#{binary_path}\n'
                                                                                            'sc.exe '
                                                                                            'start '
                                                                                            '#{service_name}\n',
                                                                                 'elevation_required': True,
                                                                                 'name': 'command_prompt'},
                                                                    'input_arguments': {'binary_path': {'default': 'PathToAtomicsFolder\\T1050\\bin\\AtomicService.exe',
                                                                                                        'description': 'Name '
                                                                                                                       'of '
                                                                                                                       'the '
                                                                                                                       'service '
                                                                                                                       'binary, '
                                                                                                                       'include '
                                                                                                                       'path.',
                                                                                                        'type': 'Path'},
                                                                                        'service_name': {'default': 'AtomicTestService',
                                                                                                         'description': 'Name '
                                                                                                                        'of '
                                                                                                                        'the '
                                                                                                                        'Service',
                                                                                                         'type': 'String'}},
                                                                    'name': 'Service '
                                                                            'Installation '
                                                                            'CMD',
                                                                    'supported_platforms': ['windows']},
                                                                   {'auto_generated_guid': '491a4af6-a521-4b74-b23b-f7b3f1ee9e77',
                                                                    'dependencies': [{'description': 'Service '
                                                                                                     'binary '
                                                                                                     'must '
                                                                                                     'exist '
                                                                                                     'on '
                                                                                                     'disk '
                                                                                                     'at '
                                                                                                     'specified '
                                                                                                     'location '
                                                                                                     '(#{binary_path})\n',
                                                                                      'get_prereq_command': 'New-Item '
                                                                                                            '-Type '
                                                                                                            'Directory '
                                                                                                            '(split-path '
                                                                                                            '#{binary_path}) '
                                                                                                            '-ErrorAction '
                                                                                                            'ignore '
                                                                                                            '| '
                                                                                                            'Out-Null\n'
                                                                                                            'Invoke-WebRequest '
                                                                                                            '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1050/bin/AtomicService.exe" '
                                                                                                            '-OutFile '
                                                                                                            '"#{binary_path}"\n',
                                                                                      'prereq_command': 'if '
                                                                                                        '(Test-Path '
                                                                                                        '#{binary_path}) '
                                                                                                        '{exit '
                                                                                                        '0} '
                                                                                                        'else '
                                                                                                        '{exit '
                                                                                                        '1}\n'}],
                                                                    'dependency_executor_name': 'powershell',
                                                                    'description': 'Installs '
                                                                                   'A '
                                                                                   'Local '
                                                                                   'Service '
                                                                                   'via '
                                                                                   'PowerShell.\n'
                                                                                   '\n'
                                                                                   'Upon '
                                                                                   'successful '
                                                                                   'execution, '
                                                                                   'powershell '
                                                                                   'will '
                                                                                   'download '
                                                                                   '`AtomicService.exe` '
                                                                                   'from '
                                                                                   'github. '
                                                                                   'Powershell '
                                                                                   'will '
                                                                                   'then '
                                                                                   'use '
                                                                                   '`New-Service` '
                                                                                   'and '
                                                                                   '`Start-Service` '
                                                                                   'to '
                                                                                   'start '
                                                                                   'service. '
                                                                                   'Results '
                                                                                   'will '
                                                                                   'be '
                                                                                   'displayed.\n',
                                                                    'executor': {'cleanup_command': 'Stop-Service '
                                                                                                    '-Name '
                                                                                                    '"#{service_name}" '
                                                                                                    '2>&1 '
                                                                                                    '| '
                                                                                                    'Out-Null\n'
                                                                                                    'try '
                                                                                                    '{(Get-WmiObject '
                                                                                                    'Win32_Service '
                                                                                                    '-filter '
                                                                                                    '"name=\'#{service_name}\'").Delete()}\n'
                                                                                                    'catch '
                                                                                                    '{}\n',
                                                                                 'command': 'New-Service '
                                                                                            '-Name '
                                                                                            '"#{service_name}" '
                                                                                            '-BinaryPathName '
                                                                                            '"#{binary_path}"\n'
                                                                                            'Start-Service '
                                                                                            '-Name '
                                                                                            '"#{service_name}"\n',
                                                                                 'elevation_required': True,
                                                                                 'name': 'powershell'},
                                                                    'input_arguments': {'binary_path': {'default': 'PathToAtomicsFolder\\T1050\\bin\\AtomicService.exe',
                                                                                                        'description': 'Name '
                                                                                                                       'of '
                                                                                                                       'the '
                                                                                                                       'service '
                                                                                                                       'binary, '
                                                                                                                       'include '
                                                                                                                       'path.',
                                                                                                        'type': 'Path'},
                                                                                        'service_name': {'default': 'AtomicTestService',
                                                                                                         'description': 'Name '
                                                                                                                        'of '
                                                                                                                        'the '
                                                                                                                        'Service',
                                                                                                         'type': 'String'}},
                                                                    'name': 'Service '
                                                                            'Installation '
                                                                            'PowerShell',
                                                                    'supported_platforms': ['windows']}],
                                                  'attack_technique': 'T1050',
                                                  'display_name': 'Service '
                                                                  'Installation'}},
 {'Threat Hunting Tables': {'chain_id': '100109',
                            'commandline_string': '(query|add)',
                            'file_path': '\\AppData\\*',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1050',
                            'mitre_caption': 'new_service',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': 'HKCU\\software\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100110',
                            'commandline_string': '(query|add)',
                            'file_path': '$Recycle.bin\\*',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1050',
                            'mitre_caption': 'new_service',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100111',
                            'commandline_string': '(query|add)',
                            'file_path': 'Temp\\*',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1050',
                            'mitre_caption': 'new_service',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100112',
                            'commandline_string': '(query|add)',
                            'file_path': 'Users\\Public\\*',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1050',
                            'mitre_caption': 'new_service',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100113',
                            'commandline_string': '(query|add)',
                            'file_path': 'Users\\Default\\*',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1050',
                            'mitre_caption': 'new_service',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100114',
                            'commandline_string': '(query|add)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': 'https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe',
                            'loaded_dll': '',
                            'mitre_attack': 'T1050',
                            'mitre_caption': 'new_service',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': 'HKEY_USERS\\*\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1050',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/powerup/service_exe_restore":  '
                                                                                 '["T1050"],',
                                            'Empire Module': 'powershell/privesc/powerup/service_exe_restore',
                                            'Technique': 'New Service'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1050',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/powerup/service_exe_stager":  '
                                                                                 '["T1050"],',
                                            'Empire Module': 'powershell/privesc/powerup/service_exe_stager',
                                            'Technique': 'New Service'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1050',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/powerup/service_exe_useradd":  '
                                                                                 '["T1050"],',
                                            'Empire Module': 'powershell/privesc/powerup/service_exe_useradd',
                                            'Technique': 'New Service'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1050',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/powerup/service_stager":  '
                                                                                 '["T1050"],',
                                            'Empire Module': 'powershell/privesc/powerup/service_stager',
                                            'Technique': 'New Service'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors


* [Carbanak](../actors/Carbanak.md)

* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [APT3](../actors/APT3.md)
    
* [FIN7](../actors/FIN7.md)
    
* [APT32](../actors/APT32.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
