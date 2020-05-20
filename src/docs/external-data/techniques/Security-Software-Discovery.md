
# Security Software Discovery

## Description

### MITRE Description

> Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on the system. This may include things such as local firewall rules and anti-virus. Adversaries may use the information from [Security Software Discovery](https://attack.mitre.org/techniques/T1063) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.


### Windows

Example commands that can be used to obtain security software information are [netsh](https://attack.mitre.org/software/S0108), <code>reg query</code> with [Reg](https://attack.mitre.org/software/S0075), <code>dir</code> with [cmd](https://attack.mitre.org/software/S0106), and [Tasklist](https://attack.mitre.org/software/S0057), but other indicators of discovery behavior may be more specific to the type of software or security system the adversary is looking for.

### Mac

It's becoming more common to see macOS malware perform checks for LittleSnitch and KnockKnock software.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1063

## Potential Commands

```
netsh.exe advfirewall  show allprofiles
tasklist.exe
tasklist.exe | findstr /i virus
tasklist.exe | findstr /i cb
tasklist.exe | findstr /i defender
tasklist.exe | findstr /i cylance

get-process | ?{$_.Description -like "*virus*"}
get-process | ?{$_.Description -like "*carbonblack*"}
get-process | ?{$_.Description -like "*defender*"}
get-process | ?{$_.Description -like "*cylance*"}

ps -ef | grep Little\ Snitch | grep -v grep
ps aux | grep CbOsxSensorService

fltmc.exe | findstr.exe 385201

wmic.exe /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
{'darwin': {'sh': {'command': 'find /Applications/ -maxdepth 2 -iname *.app | grep -io "[a-z ]*\\.app" | grep -Ei -- "symantec|norton|bitdefender|kapersky|eset|avast|avira|malwarebytes|sophos|(trend micro)"\n', 'parsers': {'plugins.stockpile.app.parsers.antivirus': [{'source': 'host.installed.av'}]}}}, 'windows': {'psh': {'command': 'wmic /NAMESPACE:\\\\root\\SecurityCenter2 PATH AntiVirusProduct GET /value\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.installed.av'}]}}}}
{'windows': {'psh': {'command': '$NameSpace = Get-WmiObject -Namespace "root" -Class "__Namespace" | Select Name | Out-String -Stream | Select-String "SecurityCenter";\n$SecurityCenter = $NameSpace | Select-Object -First 1;\nGet-WmiObject -Namespace "root\\$SecurityCenter" -Class AntiVirusProduct | Select DisplayName, InstanceGuid, PathToSignedProductExe, PathToSignedReportingExe, ProductState, Timestamp | Format-List;\n'}}}
powershell/situational_awareness/host/antivirusproduct
powershell/situational_awareness/host/antivirusproduct
Dos
Microsoft Windows [Version 10.0.14393]
(C) 2016 Microsoft Corporation. all rights reserved.

C: \ Users \ Administrator> netsh advfirewall firewall show rule name = all

Rule Name: Network Discovery (UPnP-In)
-------------------------------------------------- --------------------
Enabled: Yes
Direction: Inbound
Profile: Dedicated
Grouping: Network Discovery
Local IP: Any
Remote IP: Any
Protocol: TCP
Local Port: 2869
Remote Port: Any
Edge traversal: No
Action: Allow
```

## Commands Dataset

```
[{'command': 'netsh.exe advfirewall  show allprofiles\n'
             'tasklist.exe\n'
             'tasklist.exe | findstr /i virus\n'
             'tasklist.exe | findstr /i cb\n'
             'tasklist.exe | findstr /i defender\n'
             'tasklist.exe | findstr /i cylance\n',
  'name': None,
  'source': 'atomics/T1063/T1063.yaml'},
 {'command': 'get-process | ?{$_.Description -like "*virus*"}\n'
             'get-process | ?{$_.Description -like "*carbonblack*"}\n'
             'get-process | ?{$_.Description -like "*defender*"}\n'
             'get-process | ?{$_.Description -like "*cylance*"}\n',
  'name': None,
  'source': 'atomics/T1063/T1063.yaml'},
 {'command': 'ps -ef | grep Little\\ Snitch | grep -v grep\n'
             'ps aux | grep CbOsxSensorService\n',
  'name': None,
  'source': 'atomics/T1063/T1063.yaml'},
 {'command': 'fltmc.exe | findstr.exe 385201\n',
  'name': None,
  'source': 'atomics/T1063/T1063.yaml'},
 {'command': 'wmic.exe /Namespace:\\\\root\\SecurityCenter2 Path '
             'AntiVirusProduct Get displayName /Format:List',
  'name': None,
  'source': 'atomics/T1063/T1063.yaml'},
 {'command': {'darwin': {'sh': {'command': 'find /Applications/ -maxdepth 2 '
                                           '-iname *.app | grep -io "[a-z '
                                           ']*\\.app" | grep -Ei -- '
                                           '"symantec|norton|bitdefender|kapersky|eset|avast|avira|malwarebytes|sophos|(trend '
                                           'micro)"\n',
                                'parsers': {'plugins.stockpile.app.parsers.antivirus': [{'source': 'host.installed.av'}]}}},
              'windows': {'psh': {'command': 'wmic '
                                             '/NAMESPACE:\\\\root\\SecurityCenter2 '
                                             'PATH AntiVirusProduct GET '
                                             '/value\n',
                                  'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.installed.av'}]}}}},
  'name': 'Identify AV',
  'source': 'data/abilities/discovery/2dece965-37a0-4f70-a391-0f30e3331aba.yml'},
 {'command': {'windows': {'psh': {'command': '$NameSpace = Get-WmiObject '
                                             '-Namespace "root" -Class '
                                             '"__Namespace" | Select Name | '
                                             'Out-String -Stream | '
                                             'Select-String "SecurityCenter";\n'
                                             '$SecurityCenter = $NameSpace | '
                                             'Select-Object -First 1;\n'
                                             'Get-WmiObject -Namespace '
                                             '"root\\$SecurityCenter" -Class '
                                             'AntiVirusProduct | Select '
                                             'DisplayName, InstanceGuid, '
                                             'PathToSignedProductExe, '
                                             'PathToSignedReportingExe, '
                                             'ProductState, Timestamp | '
                                             'Format-List;\n'}}},
  'name': 'Identify Firewalls',
  'source': 'data/abilities/discovery/8c06ebf8-bacf-486b-bd77-21ba8c5a5777.yml'},
 {'command': 'powershell/situational_awareness/host/antivirusproduct',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/host/antivirusproduct',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'Dos\n'
             'Microsoft Windows [Version 10.0.14393]\n'
             '(C) 2016 Microsoft Corporation. all rights reserved.\n'
             '\n'
             'C: \\ Users \\ Administrator> netsh advfirewall firewall show '
             'rule name = all\n'
             '\n'
             'Rule Name: Network Discovery (UPnP-In)\n'
             '-------------------------------------------------- '
             '--------------------\n'
             'Enabled: Yes\n'
             'Direction: Inbound\n'
             'Profile: Dedicated\n'
             'Grouping: Network Discovery\n'
             'Local IP: Any\n'
             'Remote IP: Any\n'
             'Protocol: TCP\n'
             'Local Port: 2869\n'
             'Remote Port: Any\n'
             'Edge traversal: No\n'
             'Action: Allow',
  'name': 'Dos',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json
[{'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']}]
```

## Potential Queries

```json
[{'name': 'Security Software Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and(process_path contains "netsh.exe"or '
           'process_path contains "reg.exe"or process_path contains '
           '"tasklist.exe")and (process_command_line contains "*reg* query*"or '
           'process_command_line contains "*tasklist *"or process_command_line '
           'contains "*netsh*"or process_command_line contains '
           '"*fltmc*|*findstr*")'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows executed locally netsh advfirewall firewall show '
           'rule name = all\n'
           'description: windows server 2016\n'
           'references: No\n'
           'tags: T1063\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # Process Creation\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ netsh.exe' # process information> new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ windows "
           "\\ System32 \\ cmd.exe' # Process Information> Creator Process "
           'Name\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: netsh '
           'advfirewall firewall show rule name = all # Process Information> '
           'process command line\n'
           '\xa0\xa0\xa0\xa0condition: selection\n'
           'level: low'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Security Software Discovery': {'atomic_tests': [{'auto_generated_guid': 'f92a380f-ced9-491f-b338-95a991418ce2',
                                                                           'description': 'Methods '
                                                                                          'to '
                                                                                          'identify '
                                                                                          'Security '
                                                                                          'Software '
                                                                                          'on '
                                                                                          'an '
                                                                                          'endpoint\n'
                                                                                          '\n'
                                                                                          'when '
                                                                                          'sucessfully '
                                                                                          'executed, '
                                                                                          'the '
                                                                                          'test '
                                                                                          'is '
                                                                                          'going '
                                                                                          'to '
                                                                                          'display '
                                                                                          'running '
                                                                                          'processes, '
                                                                                          'firewall '
                                                                                          'configuration '
                                                                                          'on '
                                                                                          'network '
                                                                                          'profiles\n'
                                                                                          'and '
                                                                                          'specific '
                                                                                          'security '
                                                                                          'software.\n',
                                                                           'executor': {'command': 'netsh.exe '
                                                                                                   'advfirewall  '
                                                                                                   'show '
                                                                                                   'allprofiles\n'
                                                                                                   'tasklist.exe\n'
                                                                                                   'tasklist.exe '
                                                                                                   '| '
                                                                                                   'findstr '
                                                                                                   '/i '
                                                                                                   'virus\n'
                                                                                                   'tasklist.exe '
                                                                                                   '| '
                                                                                                   'findstr '
                                                                                                   '/i '
                                                                                                   'cb\n'
                                                                                                   'tasklist.exe '
                                                                                                   '| '
                                                                                                   'findstr '
                                                                                                   '/i '
                                                                                                   'defender\n'
                                                                                                   'tasklist.exe '
                                                                                                   '| '
                                                                                                   'findstr '
                                                                                                   '/i '
                                                                                                   'cylance\n',
                                                                                        'elevation_required': False,
                                                                                        'name': 'command_prompt'},
                                                                           'name': 'Security '
                                                                                   'Software '
                                                                                   'Discovery',
                                                                           'supported_platforms': ['windows']},
                                                                          {'auto_generated_guid': '7f566051-f033-49fb-89de-b6bacab730f0',
                                                                           'description': 'Methods '
                                                                                          'to '
                                                                                          'identify '
                                                                                          'Security '
                                                                                          'Software '
                                                                                          'on '
                                                                                          'an '
                                                                                          'endpoint\n'
                                                                                          '\n'
                                                                                          'when '
                                                                                          'sucessfully '
                                                                                          'executed, '
                                                                                          'powershell '
                                                                                          'is '
                                                                                          'going '
                                                                                          'to '
                                                                                          'processes '
                                                                                          'related '
                                                                                          'AV '
                                                                                          'products '
                                                                                          'if '
                                                                                          'they '
                                                                                          'are '
                                                                                          'running.\n',
                                                                           'executor': {'command': 'get-process '
                                                                                                   '| '
                                                                                                   '?{$_.Description '
                                                                                                   '-like '
                                                                                                   '"*virus*"}\n'
                                                                                                   'get-process '
                                                                                                   '| '
                                                                                                   '?{$_.Description '
                                                                                                   '-like '
                                                                                                   '"*carbonblack*"}\n'
                                                                                                   'get-process '
                                                                                                   '| '
                                                                                                   '?{$_.Description '
                                                                                                   '-like '
                                                                                                   '"*defender*"}\n'
                                                                                                   'get-process '
                                                                                                   '| '
                                                                                                   '?{$_.Description '
                                                                                                   '-like '
                                                                                                   '"*cylance*"}\n',
                                                                                        'elevation_required': False,
                                                                                        'name': 'powershell'},
                                                                           'name': 'Security '
                                                                                   'Software '
                                                                                   'Discovery '
                                                                                   '- '
                                                                                   'powershell',
                                                                           'supported_platforms': ['windows']},
                                                                          {'auto_generated_guid': 'ba62ce11-e820-485f-9c17-6f3c857cd840',
                                                                           'description': 'Methods '
                                                                                          'to '
                                                                                          'identify '
                                                                                          'Security '
                                                                                          'Software '
                                                                                          'on '
                                                                                          'an '
                                                                                          'endpoint\n'
                                                                                          'when '
                                                                                          'sucessfully '
                                                                                          'executed, '
                                                                                          'command '
                                                                                          'shell  '
                                                                                          'is '
                                                                                          'going '
                                                                                          'to '
                                                                                          'display '
                                                                                          'AV '
                                                                                          'software '
                                                                                          'it '
                                                                                          'is '
                                                                                          'running( '
                                                                                          'Little '
                                                                                          'snitch '
                                                                                          'or '
                                                                                          'carbon '
                                                                                          'black '
                                                                                          ').\n',
                                                                           'executor': {'command': 'ps '
                                                                                                   '-ef '
                                                                                                   '| '
                                                                                                   'grep '
                                                                                                   'Little\\ '
                                                                                                   'Snitch '
                                                                                                   '| '
                                                                                                   'grep '
                                                                                                   '-v '
                                                                                                   'grep\n'
                                                                                                   'ps '
                                                                                                   'aux '
                                                                                                   '| '
                                                                                                   'grep '
                                                                                                   'CbOsxSensorService\n',
                                                                                        'elevation_required': False,
                                                                                        'name': 'sh'},
                                                                           'name': 'Security '
                                                                                   'Software '
                                                                                   'Discovery '
                                                                                   '- '
                                                                                   'ps',
                                                                           'supported_platforms': ['linux',
                                                                                                   'macos']},
                                                                          {'auto_generated_guid': 'fe613cf3-8009-4446-9a0f-bc78a15b66c9',
                                                                           'description': 'Discovery '
                                                                                          'of '
                                                                                          'an '
                                                                                          'installed '
                                                                                          'Sysinternals '
                                                                                          'Sysmon '
                                                                                          'service '
                                                                                          'using '
                                                                                          'driver '
                                                                                          'altitude '
                                                                                          '(even '
                                                                                          'if '
                                                                                          'the '
                                                                                          'name '
                                                                                          'is '
                                                                                          'changed).\n'
                                                                                          '\n'
                                                                                          'when '
                                                                                          'sucessfully '
                                                                                          'executed, '
                                                                                          'the '
                                                                                          'test '
                                                                                          'is '
                                                                                          'going '
                                                                                          'to '
                                                                                          'display '
                                                                                          'sysmon '
                                                                                          'driver '
                                                                                          'instance '
                                                                                          'if '
                                                                                          'it '
                                                                                          'is '
                                                                                          'installed.\n',
                                                                           'executor': {'command': 'fltmc.exe '
                                                                                                   '| '
                                                                                                   'findstr.exe '
                                                                                                   '385201\n',
                                                                                        'elevation_required': True,
                                                                                        'name': 'command_prompt'},
                                                                           'name': 'Security '
                                                                                   'Software '
                                                                                   'Discovery '
                                                                                   '- '
                                                                                   'Sysmon '
                                                                                   'Service',
                                                                           'supported_platforms': ['windows']},
                                                                          {'auto_generated_guid': '1553252f-14ea-4d3b-8a08-d7a4211aa945',
                                                                           'description': 'Discovery '
                                                                                          'of '
                                                                                          'installed '
                                                                                          'antivirus '
                                                                                          'products '
                                                                                          'via '
                                                                                          'a '
                                                                                          'WMI '
                                                                                          'query.\n'
                                                                                          '\n'
                                                                                          'when '
                                                                                          'sucessfully '
                                                                                          'executed, '
                                                                                          'the '
                                                                                          'test '
                                                                                          'is '
                                                                                          'going '
                                                                                          'to '
                                                                                          'display '
                                                                                          'installed '
                                                                                          'AV '
                                                                                          'software.\n',
                                                                           'executor': {'command': 'wmic.exe '
                                                                                                   '/Namespace:\\\\root\\SecurityCenter2 '
                                                                                                   'Path '
                                                                                                   'AntiVirusProduct '
                                                                                                   'Get '
                                                                                                   'displayName '
                                                                                                   '/Format:List',
                                                                                        'elevation_required': True,
                                                                                        'name': 'command_prompt'},
                                                                           'name': 'Security '
                                                                                   'Software '
                                                                                   'Discovery '
                                                                                   '- '
                                                                                   'AV '
                                                                                   'Discovery '
                                                                                   'via '
                                                                                   'WMI',
                                                                           'supported_platforms': ['windows']}],
                                                         'attack_technique': 'T1063',
                                                         'display_name': 'Security '
                                                                         'Software '
                                                                         'Discovery'}},
 {'Mitre Stockpile - Identify AV': {'description': 'Identify AV',
                                    'id': '2dece965-37a0-4f70-a391-0f30e3331aba',
                                    'name': 'Discover antivirus programs',
                                    'platforms': {'darwin': {'sh': {'command': 'find '
                                                                               '/Applications/ '
                                                                               '-maxdepth '
                                                                               '2 '
                                                                               '-iname '
                                                                               '*.app '
                                                                               '| '
                                                                               'grep '
                                                                               '-io '
                                                                               '"[a-z '
                                                                               ']*\\.app" '
                                                                               '| '
                                                                               'grep '
                                                                               '-Ei '
                                                                               '-- '
                                                                               '"symantec|norton|bitdefender|kapersky|eset|avast|avira|malwarebytes|sophos|(trend '
                                                                               'micro)"\n',
                                                                    'parsers': {'plugins.stockpile.app.parsers.antivirus': [{'source': 'host.installed.av'}]}}},
                                                  'windows': {'psh': {'command': 'wmic '
                                                                                 '/NAMESPACE:\\\\root\\SecurityCenter2 '
                                                                                 'PATH '
                                                                                 'AntiVirusProduct '
                                                                                 'GET '
                                                                                 '/value\n',
                                                                      'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.installed.av'}]}}}},
                                    'tactic': 'discovery',
                                    'technique': {'attack_id': 'T1063',
                                                  'name': 'Security Software '
                                                          'Discovery'}}},
 {'Mitre Stockpile - Identify Firewalls': {'description': 'Identify Firewalls',
                                           'id': '8c06ebf8-bacf-486b-bd77-21ba8c5a5777',
                                           'name': 'Identify Firewalls',
                                           'platforms': {'windows': {'psh': {'command': '$NameSpace '
                                                                                        '= '
                                                                                        'Get-WmiObject '
                                                                                        '-Namespace '
                                                                                        '"root" '
                                                                                        '-Class '
                                                                                        '"__Namespace" '
                                                                                        '| '
                                                                                        'Select '
                                                                                        'Name '
                                                                                        '| '
                                                                                        'Out-String '
                                                                                        '-Stream '
                                                                                        '| '
                                                                                        'Select-String '
                                                                                        '"SecurityCenter";\n'
                                                                                        '$SecurityCenter '
                                                                                        '= '
                                                                                        '$NameSpace '
                                                                                        '| '
                                                                                        'Select-Object '
                                                                                        '-First '
                                                                                        '1;\n'
                                                                                        'Get-WmiObject '
                                                                                        '-Namespace '
                                                                                        '"root\\$SecurityCenter" '
                                                                                        '-Class '
                                                                                        'AntiVirusProduct '
                                                                                        '| '
                                                                                        'Select '
                                                                                        'DisplayName, '
                                                                                        'InstanceGuid, '
                                                                                        'PathToSignedProductExe, '
                                                                                        'PathToSignedReportingExe, '
                                                                                        'ProductState, '
                                                                                        'Timestamp '
                                                                                        '| '
                                                                                        'Format-List;\n'}}},
                                           'tactic': 'discovery',
                                           'technique': {'attack_id': 'T1063',
                                                         'name': 'Security '
                                                                 'Software '
                                                                 'Discovery'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1063',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/host/antivirusproduct":  '
                                                                                 '["T1063"],',
                                            'Empire Module': 'powershell/situational_awareness/host/antivirusproduct',
                                            'Technique': 'Security Software '
                                                         'Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations

None

# Actors


* [Patchwork](../actors/Patchwork.md)

* [MuddyWater](../actors/MuddyWater.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [Naikon](../actors/Naikon.md)
    
* [The White Company](../actors/The-White-Company.md)
    
