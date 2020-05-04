
# Scheduled Task

## Description

### MITRE Description

> Utilities such as [at](https://attack.mitre.org/software/S0110) and [schtasks](https://attack.mitre.org/software/S0111), along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. A task can also be scheduled on a remote system, provided the proper authentication is met to use RPC and file and printer sharing is turned on. Scheduling a task on a remote system typically required being a member of the Administrators group on the remote system. (Citation: TechNet Task Scheduler Security)

An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence, to conduct remote Execution as part of Lateral Movement, to gain SYSTEM privileges, or to run a process under the context of a specified account.

## Additional Attributes

* Bypass: None
* Effective Permissions: ['SYSTEM', 'Administrator', 'User']
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM', 'User']
* Platforms: ['Windows']
* Remote: True
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1053

## Potential Commands

```
schtasks [/s HOSTNAME]
shell schtasks
Creating a scheduled task:
schtasks [/S HOSTNAME] /create /tn "acachesrv" /tr C:\file\path\here.exe /sc ONLOGON /ru "System" [/rp password]
Requirements for running scheduled tasks:
net start schedule
sc config schedule start= auto
Creating a scheduled task:
shell schtasks [/S HOSTNAME] /create /tn "acachesrv" /tr C:\file\path\here.exe /sc ONLOGON /ru "System" [/rp password]
Requirements for running scheduled tasks:
shell net start schedule
shell sc config schedule start= auto
at 13:20 /interactive cmd

SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST #{time}

None
SCHTASKS /Create /S #{target} /RU #{user_name} /RP #{password} /TN "Atomic task" /TR "C:\windows\system32\cmd.exe" /SC daily /ST #{time}

None
SCHTASKS /Create /S localhost /RU #{user_name} /RP #{password} /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}

SCHTASKS /Create /S #{target} /RU DOMAIN\user /RP #{password} /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}

SCHTASKS /Create /S #{target} /RU #{user_name} /RP At0micStrong /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}

$Action = New-ScheduledTaskAction -Execute "calc.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$Set = New-ScheduledTaskSettingsSet
$object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
Register-ScheduledTask AtomicTask -InputObject $object

schtask.exe /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10
schtask.exe /create /tn "mysc" /tr C:\windows\system32\cmd.exe /sc ONLOGON /ru "System"
at.exe ##:## /interactive cmd
at.exe \\[computername|IP] ##:## c:\temp\evil.bat
net.exe use \\[computername|IP] /user:DOMAIN\username password
net.exe time \\[computername|IP]
schtasks.exe /create * appdata
\\Windows\\.+\\at.exe
\\Windows\\.+\\schtasks.exe/Create
powershell/lateral_movement/new_gpo_immediate_task
powershell/lateral_movement/new_gpo_immediate_task
powershell/persistence/elevated/schtasks
powershell/persistence/elevated/schtasks
powershell/persistence/userland/schtasks
powershell/persistence/userland/schtasks
```

## Commands Dataset

```
[{'command': 'schtasks [/s HOSTNAME]',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell schtasks',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Creating a scheduled task:\n'
             'schtasks [/S HOSTNAME] /create /tn "acachesrv" /tr '
             'C:\\file\\path\\here.exe /sc ONLOGON /ru "System" [/rp '
             'password]\n'
             'Requirements for running scheduled tasks:\n'
             'net start schedule\n'
             'sc config schedule start= auto',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Creating a scheduled task:\n'
             'shell schtasks [/S HOSTNAME] /create /tn "acachesrv" /tr '
             'C:\\file\\path\\here.exe /sc ONLOGON /ru "System" [/rp '
             'password]\n'
             'Requirements for running scheduled tasks:\n'
             'shell net start schedule\n'
             'shell sc config schedule start= auto',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'at 13:20 /interactive cmd\n',
  'name': None,
  'source': 'atomics/T1053/T1053.yaml'},
 {'command': 'SCHTASKS /Create /SC ONCE /TN spawn /TR '
             'C:\\windows\\system32\\cmd.exe /ST #{time}\n',
  'name': None,
  'source': 'atomics/T1053/T1053.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1053/T1053.yaml'},
 {'command': 'SCHTASKS /Create /S #{target} /RU #{user_name} /RP #{password} '
             '/TN "Atomic task" /TR "C:\\windows\\system32\\cmd.exe" /SC daily '
             '/ST #{time}\n',
  'name': None,
  'source': 'atomics/T1053/T1053.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1053/T1053.yaml'},
 {'command': 'SCHTASKS /Create /S localhost /RU #{user_name} /RP #{password} '
             '/TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}\n',
  'name': None,
  'source': 'atomics/T1053/T1053.yaml'},
 {'command': 'SCHTASKS /Create /S #{target} /RU DOMAIN\\user /RP #{password} '
             '/TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}\n',
  'name': None,
  'source': 'atomics/T1053/T1053.yaml'},
 {'command': 'SCHTASKS /Create /S #{target} /RU #{user_name} /RP At0micStrong '
             '/TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}\n',
  'name': None,
  'source': 'atomics/T1053/T1053.yaml'},
 {'command': '$Action = New-ScheduledTaskAction -Execute "calc.exe"\n'
             '$Trigger = New-ScheduledTaskTrigger -AtLogon\n'
             '$User = New-ScheduledTaskPrincipal -GroupId '
             '"BUILTIN\\Administrators" -RunLevel Highest\n'
             '$Set = New-ScheduledTaskSettingsSet\n'
             '$object = New-ScheduledTask -Action $Action -Principal $User '
             '-Trigger $Trigger -Settings $Set\n'
             'Register-ScheduledTask AtomicTask -InputObject $object\n',
  'name': None,
  'source': 'atomics/T1053/T1053.yaml'},
 {'command': 'schtask.exe /Create /SC ONCE /TN spawn /TR '
             'C:\\windows\\system32\\cmd.exe /ST 20:10',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'schtask.exe /create /tn "mysc" /tr '
             'C:\\windows\\system32\\cmd.exe /sc ONLOGON /ru "System"',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'at.exe ##:## /interactive cmd',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'at.exe \\\\[computername|IP] ##:## c:\\temp\\evil.bat',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'net.exe use \\\\[computername|IP] /user:DOMAIN\\username '
             'password',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'net.exe time \\\\[computername|IP]',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'schtasks.exe /create * appdata',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': '\\\\Windows\\\\.+\\\\at.exe',
  'name': None,
  'source': 'SysmonHunter - Scheduled Task'},
 {'command': '\\\\Windows\\\\.+\\\\schtasks.exe/Create',
  'name': None,
  'source': 'SysmonHunter - Scheduled Task'},
 {'command': 'powershell/lateral_movement/new_gpo_immediate_task',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/lateral_movement/new_gpo_immediate_task',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/elevated/schtasks',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/elevated/schtasks',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/userland/schtasks',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/userland/schtasks',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Scheduled Task FileAccess',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 11 and process_command_line contains '
           '"C:\\\\WINDOWS\\\\system32\\\\svchost.exe"or file_name contains '
           '"C:\\\\Windows\\\\System32\\\\Tasks\\\\"or file_name contains '
           '"C:\\\\Windows\\\\Tasks\\\\"'},
 {'name': 'Scheduled Task Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains '
           '"taskeng.exe"or process_path contains "schtasks.exe"or '
           '(process_path contains "svchost.exe"and '
           'process_parent_command_line != '
           '"C:\\\\Windows\\\\System32\\\\services.exe"))'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'schtasks '
                                                                              '[/s '
                                                                              'HOSTNAME]',
                                                  'Category': 'T1053',
                                                  'Cobalt Strike': 'shell '
                                                                   'schtasks',
                                                  'Description': 'Displays all '
                                                                 'of the '
                                                                 'currently '
                                                                 'scheduled '
                                                                 'tasks to be '
                                                                 'run on a '
                                                                 'computer',
                                                  'Metasploit': ''}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'Creating '
                                                                              'a '
                                                                              'scheduled '
                                                                              'task:\n'
                                                                              'schtasks '
                                                                              '[/S '
                                                                              'HOSTNAME] '
                                                                              '/create '
                                                                              '/tn '
                                                                              '"acachesrv" '
                                                                              '/tr '
                                                                              'C:\\file\\path\\here.exe '
                                                                              '/sc '
                                                                              'ONLOGON '
                                                                              '/ru '
                                                                              '"System" '
                                                                              '[/rp '
                                                                              'password]\n'
                                                                              'Requirements '
                                                                              'for '
                                                                              'running '
                                                                              'scheduled '
                                                                              'tasks:\n'
                                                                              'net '
                                                                              'start '
                                                                              'schedule\n'
                                                                              'sc '
                                                                              'config '
                                                                              'schedule '
                                                                              'start= '
                                                                              'auto',
                                                  'Category': 'T1053',
                                                  'Cobalt Strike': 'Creating a '
                                                                   'scheduled '
                                                                   'task:\n'
                                                                   'shell '
                                                                   'schtasks '
                                                                   '[/S '
                                                                   'HOSTNAME] '
                                                                   '/create '
                                                                   '/tn '
                                                                   '"acachesrv" '
                                                                   '/tr '
                                                                   'C:\\file\\path\\here.exe '
                                                                   '/sc '
                                                                   'ONLOGON '
                                                                   '/ru '
                                                                   '"System" '
                                                                   '[/rp '
                                                                   'password]\n'
                                                                   'Requirements '
                                                                   'for '
                                                                   'running '
                                                                   'scheduled '
                                                                   'tasks:\n'
                                                                   'shell net '
                                                                   'start '
                                                                   'schedule\n'
                                                                   'shell sc '
                                                                   'config '
                                                                   'schedule '
                                                                   'start= '
                                                                   'auto',
                                                  'Description': 'Add '
                                                                 'scheduled '
                                                                 'task (/s is '
                                                                 'name/ip of '
                                                                 'remote '
                                                                 'system to do '
                                                                 'this on; /tn '
                                                                 'is the name '
                                                                 'of the task; '
                                                                 '/sc is when '
                                                                 'to run; /ru '
                                                                 'is user to '
                                                                 'runas; /rp '
                                                                 'is password '
                                                                 'for that '
                                                                 'user)\n'
                                                                 'may need to '
                                                                 'make sure '
                                                                 'that the '
                                                                 'schedule '
                                                                 'service is '
                                                                 'started and '
                                                                 'configured '
                                                                 'to run on '
                                                                 'boot so that '
                                                                 'your '
                                                                 'persistence '
                                                                 'sticks.\n'
                                                                 'Delete a '
                                                                 'scheduled '
                                                                 'task by '
                                                                 'name:\n'
                                                                 'schtasks [/s '
                                                                 'HOSTNAME] '
                                                                 '/delete /tn '
                                                                 '"name"',
                                                  'Metasploit': ''}},
 {'Atomic Red Team Test - Scheduled Task': {'atomic_tests': [{'description': 'Executes '
                                                                             'cmd.exe\n'
                                                                             'Note: '
                                                                             'deprecated '
                                                                             'in '
                                                                             'Windows '
                                                                             '8+\n'
                                                                             '\n'
                                                                             'Upon '
                                                                             'successful '
                                                                             'execution, '
                                                                             'cmd.exe '
                                                                             'will '
                                                                             'spawn '
                                                                             'at.exe '
                                                                             'and '
                                                                             'create '
                                                                             'a '
                                                                             'scheduled '
                                                                             'task '
                                                                             'that '
                                                                             'will '
                                                                             'spawn '
                                                                             'cmd '
                                                                             'at '
                                                                             'a '
                                                                             'specific '
                                                                             'time.\n',
                                                              'executor': {'command': 'at '
                                                                                      '13:20 '
                                                                                      '/interactive '
                                                                                      'cmd\n',
                                                                           'elevation_required': False,
                                                                           'name': 'command_prompt'},
                                                              'name': 'At.exe '
                                                                      'Scheduled '
                                                                      'task',
                                                              'supported_platforms': ['windows']},
                                                             {'description': 'Upon '
                                                                             'successful '
                                                                             'execution, '
                                                                             'cmd.exe '
                                                                             'will '
                                                                             'create '
                                                                             'a '
                                                                             'scheduled '
                                                                             'task '
                                                                             'to '
                                                                             'spawn '
                                                                             'cmd.exe '
                                                                             'at '
                                                                             '20:10. \n',
                                                              'executor': {'cleanup_command': 'SCHTASKS '
                                                                                              '/Delete '
                                                                                              '/TN '
                                                                                              'spawn '
                                                                                              '/F '
                                                                                              '>nul '
                                                                                              '2>&1\n',
                                                                           'command': 'SCHTASKS '
                                                                                      '/Create '
                                                                                      '/SC '
                                                                                      'ONCE '
                                                                                      '/TN '
                                                                                      'spawn '
                                                                                      '/TR '
                                                                                      '#{task_command} '
                                                                                      '/ST '
                                                                                      '#{time}\n',
                                                                           'elevation_required': True,
                                                                           'name': 'command_prompt'},
                                                              'input_arguments': {'task_command': {'default': 'C:\\windows\\system32\\cmd.exe',
                                                                                                   'description': 'What '
                                                                                                                  'you '
                                                                                                                  'want '
                                                                                                                  'to '
                                                                                                                  'execute',
                                                                                                   'type': 'String'},
                                                                                  'time': {'default': 1210,
                                                                                           'description': 'What '
                                                                                                          'time '
                                                                                                          '24 '
                                                                                                          'Hour',
                                                                                           'type': 'String'}},
                                                              'name': 'Scheduled '
                                                                      'task '
                                                                      'Local',
                                                              'supported_platforms': ['windows']},
                                                             {'description': 'Create '
                                                                             'a '
                                                                             'task '
                                                                             'on '
                                                                             'a '
                                                                             'remote '
                                                                             'system.\n'
                                                                             '\n'
                                                                             'Upon '
                                                                             'successful '
                                                                             'execution, '
                                                                             'cmd.exe '
                                                                             'will '
                                                                             'create '
                                                                             'a '
                                                                             'scheduled '
                                                                             'task '
                                                                             'to '
                                                                             'spawn '
                                                                             'cmd.exe '
                                                                             'at '
                                                                             '20:10 '
                                                                             'on '
                                                                             'a '
                                                                             'remote '
                                                                             'endpoint. \n',
                                                              'executor': {'cleanup_command': 'SCHTASKS '
                                                                                              '/Delete '
                                                                                              '/TN '
                                                                                              '"Atomic '
                                                                                              'task" '
                                                                                              '/F '
                                                                                              '>nul '
                                                                                              '2>&1\n',
                                                                           'command': 'SCHTASKS '
                                                                                      '/Create '
                                                                                      '/S '
                                                                                      '#{target} '
                                                                                      '/RU '
                                                                                      '#{user_name} '
                                                                                      '/RP '
                                                                                      '#{password} '
                                                                                      '/TN '
                                                                                      '"Atomic '
                                                                                      'task" '
                                                                                      '/TR '
                                                                                      '"#{task_command}" '
                                                                                      '/SC '
                                                                                      'daily '
                                                                                      '/ST '
                                                                                      '#{time}\n',
                                                                           'elevation_required': True,
                                                                           'name': 'command_prompt'},
                                                              'input_arguments': {'password': {'default': 'At0micStrong',
                                                                                               'description': 'Password',
                                                                                               'type': 'String'},
                                                                                  'target': {'default': 'localhost',
                                                                                             'description': 'Target',
                                                                                             'type': 'String'},
                                                                                  'task_command': {'default': 'C:\\windows\\system32\\cmd.exe',
                                                                                                   'description': 'What '
                                                                                                                  'you '
                                                                                                                  'want '
                                                                                                                  'to '
                                                                                                                  'execute',
                                                                                                   'type': 'String'},
                                                                                  'time': {'default': 1210,
                                                                                           'description': 'What '
                                                                                                          'time '
                                                                                                          '24 '
                                                                                                          'Hour',
                                                                                           'type': 'String'},
                                                                                  'user_name': {'default': 'DOMAIN\\user',
                                                                                                'description': 'Username '
                                                                                                               'DOMAIN\\User',
                                                                                                'type': 'String'}},
                                                              'name': 'Scheduled '
                                                                      'task '
                                                                      'Remote',
                                                              'supported_platforms': ['windows']},
                                                             {'description': 'Create '
                                                                             'an '
                                                                             'atomic '
                                                                             'scheduled '
                                                                             'task '
                                                                             'that '
                                                                             'leverages '
                                                                             'native '
                                                                             'powershell '
                                                                             'cmdlets.\n'
                                                                             '\n'
                                                                             'Upon '
                                                                             'successful '
                                                                             'execution, '
                                                                             'powershell.exe '
                                                                             'will '
                                                                             'create '
                                                                             'a '
                                                                             'scheduled '
                                                                             'task '
                                                                             'to '
                                                                             'spawn '
                                                                             'cmd.exe '
                                                                             'at '
                                                                             '20:10. \n',
                                                              'executor': {'cleanup_command': 'Unregister-ScheduledTask '
                                                                                              '-TaskName '
                                                                                              '"AtomicTask" '
                                                                                              '-confirm:$false '
                                                                                              '>$null '
                                                                                              '2>&1\n',
                                                                           'command': '$Action '
                                                                                      '= '
                                                                                      'New-ScheduledTaskAction '
                                                                                      '-Execute '
                                                                                      '"calc.exe"\n'
                                                                                      '$Trigger '
                                                                                      '= '
                                                                                      'New-ScheduledTaskTrigger '
                                                                                      '-AtLogon\n'
                                                                                      '$User '
                                                                                      '= '
                                                                                      'New-ScheduledTaskPrincipal '
                                                                                      '-GroupId '
                                                                                      '"BUILTIN\\Administrators" '
                                                                                      '-RunLevel '
                                                                                      'Highest\n'
                                                                                      '$Set '
                                                                                      '= '
                                                                                      'New-ScheduledTaskSettingsSet\n'
                                                                                      '$object '
                                                                                      '= '
                                                                                      'New-ScheduledTask '
                                                                                      '-Action '
                                                                                      '$Action '
                                                                                      '-Principal '
                                                                                      '$User '
                                                                                      '-Trigger '
                                                                                      '$Trigger '
                                                                                      '-Settings '
                                                                                      '$Set\n'
                                                                                      'Register-ScheduledTask '
                                                                                      'AtomicTask '
                                                                                      '-InputObject '
                                                                                      '$object\n',
                                                                           'elevation_required': False,
                                                                           'name': 'powershell'},
                                                              'name': 'Powershell '
                                                                      'Cmdlet '
                                                                      'Scheduled '
                                                                      'Task',
                                                              'supported_platforms': ['windows']}],
                                            'attack_technique': 'T1053',
                                            'display_name': 'Scheduled Task'}},
 {'Threat Hunting Tables': {'chain_id': '100184',
                            'commandline_string': '/Create /SC ONCE /TN spawn '
                                                  '/TR '
                                                  'C:\\windows\\system32\\cmd.exe '
                                                  '/ST 20:10',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1053',
                            'mitre_caption': 'scheduled_task',
                            'os': 'windows',
                            'parent_process': 'schtask.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100185',
                            'commandline_string': '/create /tn "mysc" /tr '
                                                  'C:\\windows\\system32\\cmd.exe '
                                                  '/sc ONLOGON /ru "System"',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1053',
                            'mitre_caption': 'scheduled_task',
                            'os': 'windows',
                            'parent_process': 'schtask.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100186',
                            'commandline_string': '##:## /interactive cmd',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1053',
                            'mitre_caption': 'scheduled_task',
                            'os': 'windows',
                            'parent_process': 'at.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100187',
                            'commandline_string': '\\\\[computername|IP] ##:## '
                                                  'c:\\temp\\evil.bat',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1053',
                            'mitre_caption': 'scheduled_task',
                            'os': 'windows',
                            'parent_process': 'at.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100188',
                            'commandline_string': 'use \\\\[computername|IP] '
                                                  '/user:DOMAIN\\username '
                                                  'password',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1053',
                            'mitre_caption': 'scheduled_task',
                            'os': 'windows',
                            'parent_process': 'net.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100189',
                            'commandline_string': 'time \\\\[computername|IP]',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1053',
                            'mitre_caption': 'scheduled_task',
                            'os': 'windows',
                            'parent_process': 'net.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100206',
                            'commandline_string': '/create * appdata',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': 'fe66f4fec21229bd008d7974f071fae1a1a2ef7a1365cee27675f197719a8e27',
                            'loaded_dll': '',
                            'mitre_attack': 'T1053',
                            'mitre_caption': '',
                            'os': 'windows',
                            'parent_process': 'schtasks.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'SysmonHunter - T1053': {'description': None,
                           'level': 'high',
                           'name': 'Scheduled Task',
                           'phase': 'Execution',
                           'query': [{'process': {'image': {'flag': 'regex',
                                                            'pattern': '\\\\Windows\\\\.+\\\\at.exe'}},
                                      'type': 'process'},
                                     {'process': {'cmdline': {'pattern': '/Create'},
                                                  'image': {'flag': 'regex',
                                                            'pattern': '\\\\Windows\\\\.+\\\\schtasks.exe'}},
                                      'type': 'process'}]}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1053',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/lateral_movement/new_gpo_immediate_task":  '
                                                                                 '["T1053"],',
                                            'Empire Module': 'powershell/lateral_movement/new_gpo_immediate_task',
                                            'Technique': 'Scheduled Task'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1053',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/elevated/schtasks":  '
                                                                                 '["T1053"],',
                                            'Empire Module': 'powershell/persistence/elevated/schtasks',
                                            'Technique': 'Scheduled Task'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1053',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/userland/schtasks":  '
                                                                                 '["T1053"],',
                                            'Empire Module': 'powershell/persistence/userland/schtasks',
                                            'Technique': 'Scheduled Task'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors


* [FIN6](../actors/FIN6.md)

* [APT3](../actors/APT3.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Rancor](../actors/Rancor.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [FIN10](../actors/FIN10.md)
    
* [APT32](../actors/APT32.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [FIN7](../actors/FIN7.md)
    
* [APT18](../actors/APT18.md)
    
* [APT29](../actors/APT29.md)
    
* [APT39](../actors/APT39.md)
    
* [APT33](../actors/APT33.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [Silence](../actors/Silence.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [Machete](../actors/Machete.md)
    
* [APT41](../actors/APT41.md)
    
