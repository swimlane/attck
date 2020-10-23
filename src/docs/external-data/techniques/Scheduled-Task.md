
# Scheduled Task

## Description

### MITRE Description

> Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The <code>schtasks</code> can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library to create a scheduled task.

The deprecated [at](https://attack.mitre.org/software/S0110) utility could also be abused by adversaries (ex: [At (Windows)](https://attack.mitre.org/techniques/T1053/002)), though <code>at.exe</code> can not access tasks created with <code>schtasks</code> or the Control Panel.

An adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence. The Windows Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and or to run a process under the context of a specified account (such as SYSTEM).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: True
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1053/005

## Potential Commands

```
SCHTASKS /Create /S #{target} /RU #{user_name} /RP #{password} /TN "Atomic task" /TR "C:\windows\system32\cmd.exe" /SC daily /ST #{time}
SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST #{time}
SCHTASKS /Create /S localhost /RU #{user_name} /RP #{password} /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}
SCHTASKS /Create /S #{target} /RU #{user_name} /RP At0micStrong /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}
$Action = New-ScheduledTaskAction -Execute "calc.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$Set = New-ScheduledTaskSettingsSet
$object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
Register-ScheduledTask AtomicTask -InputObject $object
schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"
SCHTASKS /Create /S #{target} /RU DOMAIN\user /RP #{password} /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}
```

## Commands Dataset

```
[{'command': 'schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr '
             '"cmd.exe /c calc.exe"\n'
             'schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru '
             'system /tr "cmd.exe /c calc.exe"\n',
  'name': None,
  'source': 'atomics/T1053.005/T1053.005.yaml'},
 {'command': 'SCHTASKS /Create /SC ONCE /TN spawn /TR '
             'C:\\windows\\system32\\cmd.exe /ST #{time}\n',
  'name': None,
  'source': 'atomics/T1053.005/T1053.005.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1053.005/T1053.005.yaml'},
 {'command': 'SCHTASKS /Create /S #{target} /RU #{user_name} /RP #{password} '
             '/TN "Atomic task" /TR "C:\\windows\\system32\\cmd.exe" /SC daily '
             '/ST #{time}\n',
  'name': None,
  'source': 'atomics/T1053.005/T1053.005.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1053.005/T1053.005.yaml'},
 {'command': 'SCHTASKS /Create /S localhost /RU #{user_name} /RP #{password} '
             '/TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}\n',
  'name': None,
  'source': 'atomics/T1053.005/T1053.005.yaml'},
 {'command': 'SCHTASKS /Create /S #{target} /RU DOMAIN\\user /RP #{password} '
             '/TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}\n',
  'name': None,
  'source': 'atomics/T1053.005/T1053.005.yaml'},
 {'command': 'SCHTASKS /Create /S #{target} /RU #{user_name} /RP At0micStrong '
             '/TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}\n',
  'name': None,
  'source': 'atomics/T1053.005/T1053.005.yaml'},
 {'command': '$Action = New-ScheduledTaskAction -Execute "calc.exe"\n'
             '$Trigger = New-ScheduledTaskTrigger -AtLogon\n'
             '$User = New-ScheduledTaskPrincipal -GroupId '
             '"BUILTIN\\Administrators" -RunLevel Highest\n'
             '$Set = New-ScheduledTaskSettingsSet\n'
             '$object = New-ScheduledTask -Action $Action -Principal $User '
             '-Trigger $Trigger -Settings $Set\n'
             'Register-ScheduledTask AtomicTask -InputObject $object\n',
  'name': None,
  'source': 'atomics/T1053.005/T1053.005.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Scheduled Task/Job: Scheduled Task': {'atomic_tests': [{'auto_generated_guid': 'fec27f65-db86-4c2d-b66c-61945aee87c2',
                                                                                  'description': 'Run '
                                                                                                 'an '
                                                                                                 'exe '
                                                                                                 'on '
                                                                                                 'user '
                                                                                                 'logon '
                                                                                                 'or '
                                                                                                 'system '
                                                                                                 'startup.  '
                                                                                                 'Upon '
                                                                                                 'execution, '
                                                                                                 'success '
                                                                                                 'messages '
                                                                                                 'will '
                                                                                                 'be '
                                                                                                 'displayed '
                                                                                                 'for '
                                                                                                 'the '
                                                                                                 'two '
                                                                                                 'scheduled '
                                                                                                 'tasks. '
                                                                                                 'To '
                                                                                                 'view\n'
                                                                                                 'the '
                                                                                                 'tasks, '
                                                                                                 'open '
                                                                                                 'the '
                                                                                                 'Task '
                                                                                                 'Scheduler '
                                                                                                 'and '
                                                                                                 'look '
                                                                                                 'in '
                                                                                                 'the '
                                                                                                 'Active '
                                                                                                 'Tasks '
                                                                                                 'pane.\n',
                                                                                  'executor': {'cleanup_command': 'schtasks '
                                                                                                                  '/delete '
                                                                                                                  '/tn '
                                                                                                                  '"T1053_005_OnLogon" '
                                                                                                                  '/f '
                                                                                                                  '>nul '
                                                                                                                  '2>&1\n'
                                                                                                                  'schtasks '
                                                                                                                  '/delete '
                                                                                                                  '/tn '
                                                                                                                  '"T1053_005_OnStartup" '
                                                                                                                  '/f '
                                                                                                                  '>nul '
                                                                                                                  '2>&1\n',
                                                                                               'command': 'schtasks '
                                                                                                          '/create '
                                                                                                          '/tn '
                                                                                                          '"T1053_005_OnLogon" '
                                                                                                          '/sc '
                                                                                                          'onlogon '
                                                                                                          '/tr '
                                                                                                          '"cmd.exe '
                                                                                                          '/c '
                                                                                                          'calc.exe"\n'
                                                                                                          'schtasks '
                                                                                                          '/create '
                                                                                                          '/tn '
                                                                                                          '"T1053_005_OnStartup" '
                                                                                                          '/sc '
                                                                                                          'onstart '
                                                                                                          '/ru '
                                                                                                          'system '
                                                                                                          '/tr '
                                                                                                          '"cmd.exe '
                                                                                                          '/c '
                                                                                                          'calc.exe"\n',
                                                                                               'elevation_required': True,
                                                                                               'name': 'command_prompt'},
                                                                                  'name': 'Scheduled '
                                                                                          'Task '
                                                                                          'Startup '
                                                                                          'Script',
                                                                                  'supported_platforms': ['windows']},
                                                                                 {'auto_generated_guid': '42f53695-ad4a-4546-abb6-7d837f644a71',
                                                                                  'description': 'Upon '
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
                                                                                                 '20:10.\n',
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
                                                                                               'elevation_required': False,
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
                                                                                 {'auto_generated_guid': '2e5eac3e-327b-4a88-a0c0-c4057039a8dd',
                                                                                  'description': 'Create '
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
                                                                                                 'endpoint.\n',
                                                                                  'executor': {'cleanup_command': 'SCHTASKS '
                                                                                                                  '/Delete '
                                                                                                                  '/S '
                                                                                                                  '#{target} '
                                                                                                                  '/RU '
                                                                                                                  '#{user_name} '
                                                                                                                  '/RP '
                                                                                                                  '#{password} '
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
                                                                                                                   'description': 'Password '
                                                                                                                                  'to '
                                                                                                                                  'authenticate '
                                                                                                                                  'with',
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
                                                                                                                                   'to '
                                                                                                                                   'authenticate '
                                                                                                                                   'with, '
                                                                                                                                   'format: '
                                                                                                                                   'DOMAIN\\User',
                                                                                                                    'type': 'String'}},
                                                                                  'name': 'Scheduled '
                                                                                          'task '
                                                                                          'Remote',
                                                                                  'supported_platforms': ['windows']},
                                                                                 {'auto_generated_guid': 'af9fd58f-c4ac-4bf2-a9ba-224b71ff25fd',
                                                                                  'description': 'Create '
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
                                                                                                 '20:10.\n',
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
                                                                'attack_technique': 'T1053.005',
                                                                'display_name': 'Scheduled '
                                                                                'Task/Job: '
                                                                                'Scheduled '
                                                                                'Task'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    
* [Audit](../mitigations/Audit.md)
    

# Actors


* [FIN6](../actors/FIN6.md)

* [APT3](../actors/APT3.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Rancor](../actors/Rancor.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [FIN10](../actors/FIN10.md)
    
* [APT32](../actors/APT32.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [FIN7](../actors/FIN7.md)
    
* [APT29](../actors/APT29.md)
    
* [APT39](../actors/APT39.md)
    
* [APT33](../actors/APT33.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [Silence](../actors/Silence.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [Machete](../actors/Machete.md)
    
* [APT41](../actors/APT41.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [APT-C-36](../actors/APT-C-36.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
* [Wizard Spider](../actors/Wizard-Spider.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
