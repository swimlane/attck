
# Permission Groups Discovery

## Description

### MITRE Description

> Adversaries may attempt to find group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows', 'Office 365', 'Azure AD', 'AWS', 'GCP', 'Azure', 'SaaS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1069

## Potential Commands

```
shell net localgroup "Administrators"
net localgroup "Administrators"
post/windows/gather/local_admin_search_enum
net group ["Domain Admins"] /domain
net group ["Domain Admins"] /domain[:DOMAIN]
domain_list_gen.rb
post/windows/gather/enum_domain_group_users
powershell/situational_awareness/host/get_pathacl
powershell/situational_awareness/network/powerview/get_object_acl
powershell/situational_awareness/network/powerview/map_domain_trust
powershell/situational_awareness/host/get_uaclevel
```

## Commands Dataset

```
[{'command': 'net localgroup "Administrators"',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell net localgroup "Administrators"',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'post/windows/gather/local_admin_search_enum',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'net group ["Domain Admins"] /domain[:DOMAIN] ',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'net group ["Domain Admins"] /domain',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'domain_list_gen.rb\npost/windows/gather/enum_domain_group_users',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'powershell/situational_awareness/host/get_pathacl',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/host/get_pathacl',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_object_acl',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_object_acl',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/map_domain_trust',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/map_domain_trust',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/host/get_uaclevel',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/host/get_uaclevel',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth (rule), Jack Croock (method)',
                  'description': 'Detects activity as "net user administrator '
                                 '/domain" and "net group domain admins '
                                 '/domain"',
                  'detection': {'condition': 'selection',
                                'selection': [{'AccessMask': '0x2d',
                                               'EventID': 4661,
                                               'ObjectName': 'S-1-5-21-*-500',
                                               'ObjectType': 'SAM_USER'},
                                              {'AccessMask': '0x2d',
                                               'EventID': 4661,
                                               'ObjectName': 'S-1-5-21-*-512',
                                               'ObjectType': 'SAM_GROUP'}]},
                  'falsepositives': ['Administrator activity',
                                     'Penetration tests'],
                  'id': '968eef52-9cff-4454-8992-1e74b9cbad6c',
                  'level': 'high',
                  'logsource': {'definition': 'The volume of Event ID 4661 is '
                                              'high on Domain Controllers and '
                                              'therefore "Audit SAM" and '
                                              '"Audit Kernel Object" advanced '
                                              'audit policy settings are not '
                                              'configured in the '
                                              'recommendations for server '
                                              'systems',
                                'product': 'windows',
                                'service': 'security'},
                  'references': ['https://findingbad.blogspot.de/2017/01/hunting-what-does-it-look-like.html'],
                  'status': 'experimental',
                  'tags': ['attack.discovery',
                           'attack.t1087',
                           'attack.t1069',
                           'attack.s0039'],
                  'title': 'Reconnaissance Activity'}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['API monitoring']}]
```

## Potential Queries

```json
[{'name': 'Permission Groups Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where process_path contains "net"and (file_directory '
           'contains "user"or file_directory contains "group"or file_directory '
           'contains "localgroup")'},
 {'name': 'Permission Groups Discovery Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and process_path contains "net.exe"and '
           '(process_command_line contains "*net* user*"or '
           'process_command_line contains "*net* group*"or '
           'process_command_line contains "*net* localgroup*"or '
           'process_command_line contains "*get-localgroup*"or '
           'process_command_line contains '
           '"*get-ADPrinicipalGroupMembership*")'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: detection of a local user group enumeration behavior\n'
           'description: windows server 2016\n'
           'references:\n'
           'tags: T1069-001\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection:\n'
           '        EventID:\n'
           '          --4798 # of enumeration local group membership of users. '
           'Test command: net user\n'
           '          --4799 # enumeration has enabled local group membership '
           'security mechanisms. Test command: net localgroup administrators\n'
           "        Processname: 'C: \\ Windows \\ System32 \\ net1.exe' # "
           'Process information: Process Name\n'
           '    condition: selection\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: local attacker to collect information, and execute the '
           'whoami command net user command\n'
           'description: windows server 2012\n'
           'status: experimental\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection1:\n'
           "        EventID: 4688 #'ve created a new process\n"
           "        Newprocessname: '* \\ whoami.exe' # new process name\n"
           '        Processcommandline: whoami # process command line\n'
           '    selection2:\n'
           "        EventID: 4688 #'ve created a new process\n"
           "        Newprocessname: '* \\ net.exe' # new process name\n"
           '        Processcommandline: net user # process command line\n'
           '    selection3:\n'
           "        EventID: 4688 #'ve created a new process\n"
           "        Newprocessname: '* \\ net1.exe' # new process name\n"
           "        Processcommandline: '* \\ net1 user' # command-line "
           'process\n'
           '    condition: selection1 or (selection2 and selection3)\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: AD domain authority and the user group enumeration\n'
           'description: win7 test, windows service 2008 (the domain '
           'controller)\n'
           'references: http://www.polaris-lab.com/index.php/archives/42/\n'
           'tags: T1069-002\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection:\n'
           '        EventID: 4661 # has been requested to handle objects\n'
           '        Objecttype: # Object> Object Type\n'
           '             - SAM_USER\n'
           '             - SAM_GROUP\n'
           '        Objectname: # Object> object name\n'
           "             - 'S-1-5-21 - * - * - * - 502'\n"
           "             - 'S-1-5-21 - * - * - * - 512'\n"
           "             - 'S-1-5-21 - * - * - * - 500'\n"
           "             - 'S-1-5-21 - * - * - * - 505'\n"
           "             - 'S-1-5-21 - * - * - * - 519'\n"
           "             - 'S-1-5-21 - * - * - * - 520'\n"
           "             - 'S-1-5-21 - * - * - * - 544'\n"
           "             - 'S-1-5-21 - * - * - * - 551'\n"
           "             - 'S-1-5-21 - * - * - * - 555'\n"
           "        Processname: 'C: \\ Windows \\ System32 \\ lsass.exe' # "
           'process information> Process Name\n'
           '    condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'net '
                                                                              'localgroup '
                                                                              '"Administrators"',
                                                  'Category': 'T1069',
                                                  'Cobalt Strike': 'shell net '
                                                                   'localgroup '
                                                                   '"Administrators"',
                                                  'Description': 'Display the '
                                                                 'list of '
                                                                 'local '
                                                                 'administrator '
                                                                 'accounts on '
                                                                 'the '
                                                                 'workstation ',
                                                  'Metasploit': 'post/windows/gather/local_admin_search_enum'}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'net '
                                                                              'group '
                                                                              '["Domain '
                                                                              'Admins"] '
                                                                              '/domain[:DOMAIN] ',
                                                  'Category': 'T1069',
                                                  'Cobalt Strike': 'net group '
                                                                   '["Domain '
                                                                   'Admins"] '
                                                                   '/domain',
                                                  'Description': 'Display the '
                                                                 'list of '
                                                                 'domain '
                                                                 'administrator '
                                                                 'accounts',
                                                  'Metasploit': 'domain_list_gen.rb\n'
                                                                'post/windows/gather/enum_domain_group_users'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1069',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/host/get_pathacl":  '
                                                                                 '["T1069"],',
                                            'Empire Module': 'powershell/situational_awareness/host/get_pathacl',
                                            'Technique': 'Permission Groups '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1069',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_object_acl":  '
                                                                                 '["T1069"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_object_acl',
                                            'Technique': 'Permission Groups '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1069',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/map_domain_trust":  '
                                                                                 '["T1069"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/map_domain_trust',
                                            'Technique': 'Permission Groups '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1069',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/host/get_uaclevel":  '
                                                                                 '["T1069"],',
                                            'Empire Module': 'powershell/situational_awareness/host/get_uaclevel',
                                            'Technique': 'Permission Groups '
                                                         'Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [Permission Groups Discovery Mitigation](../mitigations/Permission-Groups-Discovery-Mitigation.md)


# Actors


* [APT3](../actors/APT3.md)

* [TA505](../actors/TA505.md)
    
