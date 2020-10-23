
# Windows Remote Management

## Description

### MITRE Description

> Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.

WinRM is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services).(Citation: Microsoft WinRM) It may be called with the `winrm` command or by any number of programs such as PowerShell.(Citation: Jacobsen 2014)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1021/006

## Potential Commands

```
evil-winrm -i #{destination_address} -u Domain\Administrator -p #{password}
Enable-PSRemoting -Force
invoke-command -ComputerName localhost -scriptblock {#{remote_command}}
evil-winrm -i Target -u #{user_name} -p #{password}
evil-winrm -i #{destination_address} -u #{user_name} -p P@ssw0rd1
invoke-command -ComputerName #{host_name} -scriptblock {ipconfig}
```

## Commands Dataset

```
[{'command': 'Enable-PSRemoting -Force\n',
  'name': None,
  'source': 'atomics/T1021.006/T1021.006.yaml'},
 {'command': 'invoke-command -ComputerName localhost -scriptblock '
             '{#{remote_command}}\n',
  'name': None,
  'source': 'atomics/T1021.006/T1021.006.yaml'},
 {'command': 'invoke-command -ComputerName #{host_name} -scriptblock '
             '{ipconfig}\n',
  'name': None,
  'source': 'atomics/T1021.006/T1021.006.yaml'},
 {'command': 'evil-winrm -i #{destination_address} -u Domain\\Administrator -p '
             '#{password}',
  'name': None,
  'source': 'atomics/T1021.006/T1021.006.yaml'},
 {'command': 'evil-winrm -i Target -u #{user_name} -p #{password}',
  'name': None,
  'source': 'atomics/T1021.006/T1021.006.yaml'},
 {'command': 'evil-winrm -i #{destination_address} -u #{user_name} -p '
             'P@ssw0rd1',
  'name': None,
  'source': 'atomics/T1021.006/T1021.006.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Remote Services: Windows Remote Management': {'atomic_tests': [{'auto_generated_guid': '9059e8de-3d7d-4954-a322-46161880b9cf',
                                                                                          'description': 'Powershell '
                                                                                                         'Enable '
                                                                                                         'WinRM\n'
                                                                                                         '\n'
                                                                                                         'Upon '
                                                                                                         'successful '
                                                                                                         'execution, '
                                                                                                         'powershell '
                                                                                                         'will '
                                                                                                         '"Enable-PSRemoting" '
                                                                                                         'allowing '
                                                                                                         'for '
                                                                                                         'remote '
                                                                                                         'PS '
                                                                                                         'access.\n',
                                                                                          'executor': {'command': 'Enable-PSRemoting '
                                                                                                                  '-Force\n',
                                                                                                       'elevation_required': True,
                                                                                                       'name': 'powershell'},
                                                                                          'name': 'Enable '
                                                                                                  'Windows '
                                                                                                  'Remote '
                                                                                                  'Management',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': '5295bd61-bd7e-4744-9d52-85962a4cf2d6',
                                                                                          'description': 'Execute '
                                                                                                         'Invoke-command '
                                                                                                         'on '
                                                                                                         'remote '
                                                                                                         'host.\n'
                                                                                                         '\n'
                                                                                                         'Upon '
                                                                                                         'successful '
                                                                                                         'execution, '
                                                                                                         'powershell '
                                                                                                         'will '
                                                                                                         'execute '
                                                                                                         'ipconfig '
                                                                                                         'on '
                                                                                                         'localhost '
                                                                                                         'using '
                                                                                                         '`invoke-command`.\n',
                                                                                          'executor': {'command': 'invoke-command '
                                                                                                                  '-ComputerName '
                                                                                                                  '#{host_name} '
                                                                                                                  '-scriptblock '
                                                                                                                  '{#{remote_command}}\n',
                                                                                                       'name': 'powershell'},
                                                                                          'input_arguments': {'host_name': {'default': 'localhost',
                                                                                                                            'description': 'Remote '
                                                                                                                                           'Windows '
                                                                                                                                           'Host '
                                                                                                                                           'Name',
                                                                                                                            'type': 'String'},
                                                                                                              'remote_command': {'default': 'ipconfig',
                                                                                                                                 'description': 'Command '
                                                                                                                                                'to '
                                                                                                                                                'execute '
                                                                                                                                                'on '
                                                                                                                                                'remote '
                                                                                                                                                'Host',
                                                                                                                                 'type': 'String'}},
                                                                                          'name': 'Invoke-Command',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': 'efe86d95-44c4-4509-ae42-7bfd9d1f5b3d',
                                                                                          'dependencies': [{'description': 'Computer '
                                                                                                                           'must '
                                                                                                                           'have '
                                                                                                                           'Ruby '
                                                                                                                           'Installed',
                                                                                                            'get_prereq_command': 'Invoke-WebRequest  '
                                                                                                                                  '-OutFile '
                                                                                                                                  '$env:Temp\\rubyinstaller-2.7.1-1-x64.exe '
                                                                                                                                  'https://github.com/oneclick/rubyinstaller2/releases/download/RubyInstaller-2.7.1-1/rubyinstaller-2.7.1-1-x64.exe\n'
                                                                                                                                  '$file1= '
                                                                                                                                  '$env:Temp '
                                                                                                                                  '+ '
                                                                                                                                  '"\\rubyinstaller-2.7.1-1-x64.exe"\n'
                                                                                                                                  'Start-Process '
                                                                                                                                  '$file1 '
                                                                                                                                  '/S;',
                                                                                                            'prereq_command': 'if '
                                                                                                                              '(ruby '
                                                                                                                              '-v) '
                                                                                                                              '{exit '
                                                                                                                              '0} '
                                                                                                                              'else '
                                                                                                                              '{exit '
                                                                                                                              '1}'},
                                                                                                           {'description': 'Computer '
                                                                                                                           'must '
                                                                                                                           'have '
                                                                                                                           'Evil-WinRM '
                                                                                                                           'installed',
                                                                                                            'get_prereq_command': 'gem '
                                                                                                                                  'install '
                                                                                                                                  'evil-winrm',
                                                                                                            'prereq_command': 'if '
                                                                                                                              '(evil-winrm '
                                                                                                                              '-h) '
                                                                                                                              '{exit '
                                                                                                                              '0} '
                                                                                                                              'else '
                                                                                                                              '{exit '
                                                                                                                              '1}'}],
                                                                                          'dependency_executor_name': 'powershell',
                                                                                          'description': 'An '
                                                                                                         'adversary '
                                                                                                         'may '
                                                                                                         'attempt '
                                                                                                         'to '
                                                                                                         'use '
                                                                                                         'Evil-WinRM '
                                                                                                         'with '
                                                                                                         'a '
                                                                                                         'valid '
                                                                                                         'account '
                                                                                                         'to '
                                                                                                         'interact '
                                                                                                         'with '
                                                                                                         'remote '
                                                                                                         'systems '
                                                                                                         'that '
                                                                                                         'have '
                                                                                                         'WinRM '
                                                                                                         'enabled',
                                                                                          'executor': {'command': 'evil-winrm '
                                                                                                                  '-i '
                                                                                                                  '#{destination_address} '
                                                                                                                  '-u '
                                                                                                                  '#{user_name} '
                                                                                                                  '-p '
                                                                                                                  '#{password}',
                                                                                                       'elevation_required': True,
                                                                                                       'name': 'powershell'},
                                                                                          'input_arguments': {'destination_address': {'default': 'Target',
                                                                                                                                      'description': 'Remote '
                                                                                                                                                     'Host '
                                                                                                                                                     'IP '
                                                                                                                                                     'or '
                                                                                                                                                     'Hostname',
                                                                                                                                      'type': 'string'},
                                                                                                              'password': {'default': 'P@ssw0rd1',
                                                                                                                           'description': 'Password',
                                                                                                                           'type': 'string'},
                                                                                                              'user_name': {'default': 'Domain\\Administrator',
                                                                                                                            'description': 'Username',
                                                                                                                            'type': 'string'}},
                                                                                          'name': 'WinRM '
                                                                                                  'Access '
                                                                                                  'with '
                                                                                                  'Evil-WinRM',
                                                                                          'supported_platforms': ['windows']}],
                                                                        'attack_technique': 'T1021.006',
                                                                        'display_name': 'Remote '
                                                                                        'Services: '
                                                                                        'Windows '
                                                                                        'Remote '
                                                                                        'Management'}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations


* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)

* [Network Segmentation](../mitigations/Network-Segmentation.md)
    
* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    

# Actors


* [Threat Group-3390](../actors/Threat-Group-3390.md)

