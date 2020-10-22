
# Scheduled Task/Job

## Description

### MITRE Description

> Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically requires being a member of an admin or otherwise privileged group on the remote system.(Citation: TechNet Task Scheduler Security)

Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: ['SYSTEM', 'Administrator', 'User']
* Network: None
* Permissions: ['Administrator', 'SYSTEM', 'User']
* Platforms: ['Windows', 'Linux', 'macOS']
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
[{'data_source': {'action': 'global',
                  'author': 'Florian Roth',
                  'description': 'Detects the deactivation of the Scheduled '
                                 'defragmentation task as seen by Slingshot '
                                 'APT group',
                  'detection': {'condition': '1 of them'},
                  'falsepositives': ['Unknown'],
                  'id': '958d81aa-8566-4cea-a565-59ccd4df27b0',
                  'level': 'medium',
                  'references': ['https://securelist.com/apt-slingshot/84312/'],
                  'tags': ['attack.persistence',
                           'attack.t1053',
                           'attack.s0111'],
                  'title': 'Defrag Deactivation'}},
 {'data_source': {'detection': {'selection1': {'CommandLine': ['*schtasks* '
                                                               '/delete '
                                                               '*Defrag\\ScheduledDefrag*']}},
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'}}},
 {'data_source': {'detection': {'selection2': {'EventID': 4701,
                                               'TaskName': '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag'}},
                  'logsource': {'definition': 'Requirements: Audit Policy : '
                                              'Audit Other Object Access '
                                              'Events > Success',
                                'product': 'windows',
                                'service': 'security'}}},
 {'data_source': {'author': 'Samir Bousseaden',
                  'description': 'Detect lateral movement using GPO scheduled '
                                 'task, ususally used to deploy ransomware at '
                                 'scale',
                  'detection': {'condition': 'selection',
                                'selection': {'Accesses': '*WriteData*',
                                              'EventID': 5145,
                                              'RelativeTargetName': '*ScheduledTasks.xml',
                                              'ShareName': '\\\\*\\SYSVOL'}},
                  'falsepositives': ['if the source IP is not localhost then '
                                     "it's super suspicious, better to monitor "
                                     'both local and remote changes to GPO '
                                     'scheduledtasks'],
                  'id': 'a8f29a7b-b137-4446-80a0-b804272f3da2',
                  'level': 'high',
                  'logsource': {'description': 'The advanced audit policy '
                                               'setting "Object Access > Audit '
                                               'Detailed File Share" must be '
                                               'configured for Success/Failure',
                                'product': 'windows',
                                'service': 'security'},
                  'references': ['https://twitter.com/menasec1/status/1106899890377052160'],
                  'tags': ['attack.persistence',
                           'attack.lateral_movement',
                           'attack.t1053'],
                  'title': 'Persistence and Execution at scale via GPO '
                           'scheduled task'}},
 {'data_source': {'author': 'Samir Bousseaden',
                  'description': 'Detects remote task creation via at.exe or '
                                 'API interacting with ATSVC namedpipe',
                  'detection': {'condition': 'selection',
                                'selection': {'Accesses': '*WriteData*',
                                              'EventID': 5145,
                                              'RelativeTargetName': 'atsvc',
                                              'ShareName': '\\\\*\\IPC$'}},
                  'falsepositives': ['pentesting'],
                  'id': 'f6de6525-4509-495a-8a82-1f8b0ed73a00',
                  'level': 'medium',
                  'logsource': {'description': 'The advanced audit policy '
                                               'setting "Object Access > Audit '
                                               'Detailed File Share" must be '
                                               'configured for Success/Failure',
                                'product': 'windows',
                                'service': 'security'},
                  'references': ['https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html'],
                  'tags': ['attack.lateral_movement',
                           'attack.persistence',
                           'attack.t1053',
                           'car.2013-05-004',
                           'car.2015-04-001'],
                  'title': 'Remote Task Creation via ATSVC named pipe'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'This rule detects rare scheduled task '
                                 'creations. Typically software gets installed '
                                 'on multiple systems and not only on a few. '
                                 'The aggregation and count function selects '
                                 'tasks with rare names.',
                  'detection': {'condition': 'selection | count() by TaskName '
                                             '< 5',
                                'selection': {'EventID': 106},
                                'timeframe': '7d'},
                  'falsepositives': ['Software installation'],
                  'id': 'b20f6158-9438-41be-83da-a5a16ac90c2b',
                  'level': 'low',
                  'logsource': {'product': 'windows',
                                'service': 'taskscheduler'},
                  'status': 'experimental',
                  'tags': ['attack.persistence',
                           'attack.t1053',
                           'attack.s0111'],
                  'title': 'Rare Scheduled Task Creations'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects rare scheduled tasks creations that '
                                 'only appear a few times per time frame and '
                                 'could reveal password dumpers, backdoor '
                                 'installs or other types of malicious code',
                  'detection': {'condition': 'selection | count() by TaskName '
                                             '< 5',
                                'selection': {'EventID': 4698},
                                'timeframe': '7d'},
                  'falsepositives': ['Software installation',
                                     'Software updates'],
                  'id': 'b0d77106-7bb0-41fe-bd94-d1752164d066',
                  'level': 'low',
                  'logsource': {'definition': 'The Advanced Audit Policy '
                                              'setting Object Access > Audit '
                                              'Other Object Access Events has '
                                              'to be configured to allow this '
                                              'detection (not in the baseline '
                                              'recommendations by Microsoft). '
                                              'We also recommend extracting '
                                              'the Command field from the '
                                              'embedded XML in the event data.',
                                'product': 'windows',
                                'service': 'security'},
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.privilege_escalation',
                           'attack.persistence',
                           'attack.t1053',
                           'car.2013-08-001'],
                  'title': 'Rare Schtasks Creations'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects the creation of scheduled tasks in '
                                 'user session',
                  'detection': {'condition': 'selection and not filter',
                                'filter': {'User': 'NT AUTHORITY\\SYSTEM'},
                                'selection': {'CommandLine': '* /create *',
                                              'Image': '*\\schtasks.exe'}},
                  'falsepositives': ['Administrative activity',
                                     'Software installation'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '92626ddd-662c-49e3-ac59-f6535f12d189',
                  'level': 'low',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.persistence',
                           'attack.privilege_escalation',
                           'attack.t1053',
                           'attack.s0111',
                           'car.2013-08-001'],
                  'title': 'Scheduled Task Creation'}},
 {'data_source': {'author': 'Olaf Hartong',
                  'date': '2019/05/22',
                  'description': 'Detects Task Scheduler .job import arbitrary '
                                 'DACL write\\par',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': '*/change*/TN*/RU*/RP*',
                                              'Image': 'schtasks.exe'}},
                  'falsepositives': ['Unknown'],
                  'id': '931b6802-d6a6-4267-9ffa-526f57f22aaf',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe'],
                  'status': 'experimental',
                  'tags': ['attack.privilege_escalation',
                           'attack.execution',
                           'attack.t1053',
                           'car.2013-08-001'],
                  'title': 'Windows 10 scheduled task SandboxEscaper 0-day'}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Windows event logs']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['106', 'Task Registered']}]
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


* [Scheduled Task Mitigation](../mitigations/Scheduled-Task-Mitigation.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    
* [Audit](../mitigations/Audit.md)
    
* [User Account Management](../mitigations/User-Account-Management.md)
    

# Actors

None
