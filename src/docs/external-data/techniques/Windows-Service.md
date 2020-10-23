
# Windows Service

## Description

### MITRE Description

> Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.(Citation: TechNet Services) Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry. Service configurations can be modified using utilities such as sc.exe and [Reg](https://attack.mitre.org/software/S0075). 

Adversaries may install a new service or modify an existing service by using system utilities to interact with services, by directly modifying the Registry, or by using custom tools to interact with the Windows API. Adversaries may configure services to execute at startup in order to persist on a system.

An adversary may also incorporate [Masquerading](https://attack.mitre.org/techniques/T1036) by using a service name from a related operating system or benign software, or by modifying existing services to make detection analysis more challenging. Modifying existing services may interrupt their functionality or may enable services that are disabled or otherwise not commonly used. 

Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges from administrator to SYSTEM. Adversaries may also directly start services through [Service Execution](https://attack.mitre.org/techniques/T1569/002). 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: ['Administrator', 'SYSTEM']
* Network: None
* Permissions: None
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1543/003

## Potential Commands

```
sc config Fax binPath= "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -noexit -c \"write-host 'T1543.003 Test'\""
sc start Fax
New-Service -Name "AtomicTestService_PowerShell" -BinaryPathName "#{binary_path}"
Start-Service -Name "AtomicTestService_PowerShell"
New-Service -Name "#{service_name}" -BinaryPathName "PathToAtomicsFolder\T1543.003\bin\AtomicService.exe"
Start-Service -Name "#{service_name}"
sc.exe create #{service_name} binPath= PathToAtomicsFolder\T1543.003\bin\AtomicService.exe
sc.exe start #{service_name}
sc.exe create AtomicTestService_CMD binPath= #{binary_path}
sc.exe start AtomicTestService_CMD
```

## Commands Dataset

```
[{'command': 'sc config Fax binPath= '
             '"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe '
             '-noexit -c \\"write-host \'T1543.003 Test\'\\""\n'
             'sc start Fax\n',
  'name': None,
  'source': 'atomics/T1543.003/T1543.003.yaml'},
 {'command': 'sc.exe create #{service_name} binPath= '
             'PathToAtomicsFolder\\T1543.003\\bin\\AtomicService.exe\n'
             'sc.exe start #{service_name}\n',
  'name': None,
  'source': 'atomics/T1543.003/T1543.003.yaml'},
 {'command': 'sc.exe create AtomicTestService_CMD binPath= #{binary_path}\n'
             'sc.exe start AtomicTestService_CMD\n',
  'name': None,
  'source': 'atomics/T1543.003/T1543.003.yaml'},
 {'command': 'New-Service -Name "#{service_name}" -BinaryPathName '
             '"PathToAtomicsFolder\\T1543.003\\bin\\AtomicService.exe"\n'
             'Start-Service -Name "#{service_name}"\n',
  'name': None,
  'source': 'atomics/T1543.003/T1543.003.yaml'},
 {'command': 'New-Service -Name "AtomicTestService_PowerShell" -BinaryPathName '
             '"#{binary_path}"\n'
             'Start-Service -Name "AtomicTestService_PowerShell"\n',
  'name': None,
  'source': 'atomics/T1543.003/T1543.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Create or Modify System Process: Windows Service': {'atomic_tests': [{'auto_generated_guid': 'ed366cde-7d12-49df-a833-671904770b9f',
                                                                                                'description': 'This '
                                                                                                               'test '
                                                                                                               'will '
                                                                                                               'temporarily '
                                                                                                               'modify '
                                                                                                               'the '
                                                                                                               'service '
                                                                                                               'Fax '
                                                                                                               'by '
                                                                                                               'changing '
                                                                                                               'the '
                                                                                                               'binPath '
                                                                                                               'to '
                                                                                                               'PowerShell\n'
                                                                                                               'and '
                                                                                                               'will '
                                                                                                               'then '
                                                                                                               'revert '
                                                                                                               'the '
                                                                                                               'binPath '
                                                                                                               'change, '
                                                                                                               'restoring '
                                                                                                               'Fax '
                                                                                                               'to '
                                                                                                               'its '
                                                                                                               'original '
                                                                                                               'state.\n'
                                                                                                               'Upon '
                                                                                                               'successful '
                                                                                                               'execution, '
                                                                                                               'cmd '
                                                                                                               'will '
                                                                                                               'modify '
                                                                                                               'the '
                                                                                                               'binpath '
                                                                                                               'for '
                                                                                                               '`Fax` '
                                                                                                               'to '
                                                                                                               'spawn '
                                                                                                               'powershell. '
                                                                                                               'Powershell '
                                                                                                               'will '
                                                                                                               'then '
                                                                                                               'spawn.\n',
                                                                                                'executor': {'cleanup_command': 'sc '
                                                                                                                                'config '
                                                                                                                                'Fax '
                                                                                                                                'binPath= '
                                                                                                                                '"C:\\WINDOWS\\system32\\fxssvc.exe" '
                                                                                                                                '>nul '
                                                                                                                                '2>&1',
                                                                                                             'command': 'sc '
                                                                                                                        'config '
                                                                                                                        'Fax '
                                                                                                                        'binPath= '
                                                                                                                        '"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe '
                                                                                                                        '-noexit '
                                                                                                                        '-c '
                                                                                                                        '\\"write-host '
                                                                                                                        "'T1543.003 "
                                                                                                                        'Test\'\\""\n'
                                                                                                                        'sc '
                                                                                                                        'start '
                                                                                                                        'Fax\n',
                                                                                                             'elevation_required': True,
                                                                                                             'name': 'command_prompt'},
                                                                                                'name': 'Modify '
                                                                                                        'Fax '
                                                                                                        'service '
                                                                                                        'to '
                                                                                                        'run '
                                                                                                        'PowerShell',
                                                                                                'supported_platforms': ['windows']},
                                                                                               {'auto_generated_guid': '981e2942-e433-44e9-afc1-8c957a1496b6',
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
                                                                                                                                        '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1543.003/bin/AtomicService.exe" '
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
                                                                                                'input_arguments': {'binary_path': {'default': 'PathToAtomicsFolder\\T1543.003\\bin\\AtomicService.exe',
                                                                                                                                    'description': 'Name '
                                                                                                                                                   'of '
                                                                                                                                                   'the '
                                                                                                                                                   'service '
                                                                                                                                                   'binary, '
                                                                                                                                                   'include '
                                                                                                                                                   'path.',
                                                                                                                                    'type': 'Path'},
                                                                                                                    'service_name': {'default': 'AtomicTestService_CMD',
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
                                                                                                                                        '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1543.003/bin/AtomicService.exe" '
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
                                                                                                'input_arguments': {'binary_path': {'default': 'PathToAtomicsFolder\\T1543.003\\bin\\AtomicService.exe',
                                                                                                                                    'description': 'Name '
                                                                                                                                                   'of '
                                                                                                                                                   'the '
                                                                                                                                                   'service '
                                                                                                                                                   'binary, '
                                                                                                                                                   'include '
                                                                                                                                                   'path.',
                                                                                                                                    'type': 'Path'},
                                                                                                                    'service_name': {'default': 'AtomicTestService_PowerShell',
                                                                                                                                     'description': 'Name '
                                                                                                                                                    'of '
                                                                                                                                                    'the '
                                                                                                                                                    'Service',
                                                                                                                                     'type': 'String'}},
                                                                                                'name': 'Service '
                                                                                                        'Installation '
                                                                                                        'PowerShell',
                                                                                                'supported_platforms': ['windows']}],
                                                                              'attack_technique': 'T1543.003',
                                                                              'display_name': 'Create '
                                                                                              'or '
                                                                                              'Modify '
                                                                                              'System '
                                                                                              'Process: '
                                                                                              'Windows '
                                                                                              'Service'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Audit](../mitigations/Audit.md)

* [User Account Management](../mitigations/User-Account-Management.md)
    

# Actors


* [Carbanak](../actors/Carbanak.md)

* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [APT3](../actors/APT3.md)
    
* [FIN7](../actors/FIN7.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT19](../actors/APT19.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [APT41](../actors/APT41.md)
    
* [APT32](../actors/APT32.md)
    
* [Wizard Spider](../actors/Wizard-Spider.md)
    
* [DarkVishnya](../actors/DarkVishnya.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
