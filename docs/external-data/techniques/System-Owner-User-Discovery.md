
# System Owner/User Discovery

## Description

### MITRE Description

> ### Windows

Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using [Credential Dumping](https://attack.mitre.org/techniques/T1003). The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from [System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

### Mac

On Mac, the currently logged in user can be identified with <code>users</code>,<code>w</code>, and <code>who</code>.

### Linux

On Linux, the currently logged in user can be identified with <code>w</code> and <code>who</code>.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
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
qwinsta.exe" /server:localhost
qwinsta.exe
for /F "tokens=1,2" %i in ('qwinsta /server:localhost ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt
@FOR /F %n in (computers.txt) DO @FOR /F "tokens=1,2" %i in ('qwinsta /server:%n ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt

users
w
who

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
             'qwinsta.exe" /server:localhost\n'
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

```

## Potential Queries

```json
[{'name': 'System Owner User Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains '
           '"whoami.exe"or process_command_line contains "whoami"or '
           'file_directory contains "useraccount get /ALL"or process_path '
           'contains "qwinsta.exe"or process_path contains "quser.exe"or '
           'process_path contains "systeminfo.exe")'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: system owner / user found\n'
           'description: windows server 2016 / Ubuntu19.04\n'
           'references: https://attack.mitre.org/techniques/T1033/\n'
           'tags: T1033\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ windows \\ "
           "system32 \\ whoami.exe' # process information> new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ windows "
           "\\ system32 \\ cmd.exe' # Process Information> Creator Process "
           'Name\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: whoami # '
           'Process information> process command line\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4703 # a user's "
           'privileges to be adjusted.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ProcessName: 'C: \\ Windows \\ "
           "System32 \\ whoami.exe' # process information> process name\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EnabledPrivileges: '
           "'SeDebugPrivilege' permission enabled #\n"
           '\xa0\xa0\xa0\xa0selection3:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4689 # exited process\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ProcessName: 'C: \\ Windows \\ "
           "System32 \\ whoami.exe' # process information> process name\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Exitstatus: 0x0 # Process '
           'information> exit status\n'
           '\xa0\xa0\xa0\xa0timeframe: last 1m # can be adjusted according to '
           'actual situation\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: low\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: linux\n'
           '\xa0\xa0\xa0\xa0service: history\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0keywords:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0- w\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0- who\n'
           '\xa0\xa0\xa0\xa0condition: keywords\n'
           'level: low'}]
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
 {'Atomic Red Team Test - System Owner/User Discovery': {'atomic_tests': [{'description': 'Identify '
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
                                                                                                   'qwinsta.exe" '
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
                                                                                        'elevation_required': False,
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
                                                                          {'description': 'Identify '
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
                                                                                        'elevation_required': False,
                                                                                        'name': 'sh'},
                                                                           'name': 'System '
                                                                                   'Owner/User '
                                                                                   'Discovery',
                                                                           'supported_platforms': ['linux',
                                                                                                   'macos']}],
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

None

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
    
