
# New Service

## Description

### MITRE Description

> When operating systems boot up, they can start programs or applications called services that perform background system functions. (Citation: TechNet Services) A service's configuration information, including the file path to the service's executable, is stored in the Windows Registry. 

Adversaries may install a new service that can be configured to execute at startup by using utilities to interact with services or by directly modifying the Registry. The service name may be disguised by using a name from a related operating system or benign software with [Masquerading](https://attack.mitre.org/techniques/T1036). Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges from administrator to SYSTEM. Adversaries may also directly start services through [Service Execution](https://attack.mitre.org/techniques/T1035).

## Additional Attributes

* Bypass: None
* Effective Permissions: ['SYSTEM']
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: intentionally left blank
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
[{'Atomic Red Team Test - Service Installation': {'atomic_tests': [{'dependencies': [{'description': 'Service '
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
                                                                   {'dependencies': [{'description': 'Service '
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
    
