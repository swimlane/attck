
# Permission Groups Discovery

## Description

### MITRE Description

> Adversaries may attempt to find local system or domain-level groups and permissions settings. 

### Windows

Examples of commands that can list groups are <code>net group /domain</code> and <code>net localgroup</code> using the [Net](https://attack.mitre.org/software/S0039) utility.

### Mac

On Mac, this same thing can be accomplished with the <code>dscacheutil -q group</code> for the domain, or <code>dscl . -list /Groups</code> for local groups.

### Linux

On Linux, local groups can be enumerated with the <code>groups</code> command and domain groups via the <code>ldapsearch</code> command.

### Office 365 and Azure AD

With authenticated access there are several tools that can be used to find permissions groups. The <code>Get-MsolRole</code> PowerShell cmdlet can be used to obtain roles and permissions groups for Exchange and Office 365 accounts.(Citation: Microsoft msrole)(Citation: GitHub Raindance)

Azure CLI (AZ CLI) also provides an interface to obtain permissions groups with authenticated access to a domain. The command <code>az ad user get-member-groups</code> will list groups associated to a user account.(Citation: Microsoft AZ CLI)(Citation: Black Hills Red Teaming MS AD Azure, 2018)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows', 'Office 365', 'Azure AD']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1069

## Potential Commands

```
net localgroup "Administrators"
shell net localgroup "Administrators"
post/windows/gather/local_admin_search_enum
net group ["Domain Admins"] /domain[:DOMAIN] 
net group ["Domain Admins"] /domain
domain_list_gen.rb
post/windows/gather/enum_domain_group_users
dscacheutil -q group
dscl . -list /Groups
groups

net localgroup
net group /domain
net group "domain admins" /domain

get-localgroup
get-ADPrincipalGroupMembership administrator | select name

net group /domai "Domain Admins"
net groups "Account Operators" /doma
net groups "Exchange Organization Management" /doma
net group "BUILTIN\Backup Operators" /doma

{'windows': {'psh': {'command': 'gpresult /R\n'}}, 'darwin': {'sh': {'command': 'groups'}}, 'linux': {'sh': {'command': 'groups'}}}
{'darwin': {'sh': {'command': "dscl . list /Users | grep -v '_'\n"}}, 'windows': {'psh': {'command': 'Get-WmiObject -Class Win32_UserAccount\n'}}}
powershell/situational_awareness/host/get_pathacl
powershell/situational_awareness/host/get_pathacl
powershell/situational_awareness/network/powerview/get_object_acl
powershell/situational_awareness/network/powerview/get_object_acl
powershell/situational_awareness/network/powerview/map_domain_trust
powershell/situational_awareness/network/powerview/map_domain_trust
powershell/situational_awareness/host/get_uaclevel
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
 {'command': 'dscacheutil -q group\ndscl . -list /Groups\ngroups\n',
  'name': None,
  'source': 'atomics/T1069/T1069.yaml'},
 {'command': 'net localgroup\n'
             'net group /domain\n'
             'net group "domain admins" /domain\n',
  'name': None,
  'source': 'atomics/T1069/T1069.yaml'},
 {'command': 'get-localgroup\n'
             'get-ADPrincipalGroupMembership administrator | select name\n',
  'name': None,
  'source': 'atomics/T1069/T1069.yaml'},
 {'command': 'net group /domai "Domain Admins"\n'
             'net groups "Account Operators" /doma\n'
             'net groups "Exchange Organization Management" /doma\n'
             'net group "BUILTIN\\Backup Operators" /doma\n',
  'name': None,
  'source': 'atomics/T1069/T1069.yaml'},
 {'command': {'darwin': {'sh': {'command': 'groups'}},
              'linux': {'sh': {'command': 'groups'}},
              'windows': {'psh': {'command': 'gpresult /R\n'}}},
  'name': 'Summary of permission and security groups',
  'source': 'data/abilities/discovery/5c4dd985-89e3-4590-9b57-71fed66ff4e2.yml'},
 {'command': {'darwin': {'sh': {'command': 'dscl . list /Users | grep -v '
                                           "'_'\n"}},
              'windows': {'psh': {'command': 'Get-WmiObject -Class '
                                             'Win32_UserAccount\n'}}},
  'name': 'Identify all local users',
  'source': 'data/abilities/discovery/feaced8f-f43f-452a-9500-a5219488abb8.yml'},
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
           '"*get-ADPrinicipalGroupMembership*")'}]
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
 {'Atomic Red Team Test - Permission Groups Discovery': {'atomic_tests': [{'description': 'Permission '
                                                                                          'Groups '
                                                                                          'Discovery\n',
                                                                           'executor': {'command': 'dscacheutil '
                                                                                                   '-q '
                                                                                                   'group\n'
                                                                                                   'dscl '
                                                                                                   '. '
                                                                                                   '-list '
                                                                                                   '/Groups\n'
                                                                                                   'groups\n',
                                                                                        'name': 'sh'},
                                                                           'name': 'Permission '
                                                                                   'Groups '
                                                                                   'Discovery',
                                                                           'supported_platforms': ['macos',
                                                                                                   'linux']},
                                                                          {'description': 'Basic '
                                                                                          'Permission '
                                                                                          'Groups '
                                                                                          'Discovery '
                                                                                          'for '
                                                                                          'Windows. '
                                                                                          'This '
                                                                                          'test '
                                                                                          'will '
                                                                                          'display '
                                                                                          'some '
                                                                                          'errors '
                                                                                          'if '
                                                                                          'run '
                                                                                          'on '
                                                                                          'a '
                                                                                          'computer '
                                                                                          'not '
                                                                                          'connected '
                                                                                          'to '
                                                                                          'a '
                                                                                          'domain. '
                                                                                          'Upon '
                                                                                          'execution, '
                                                                                          'domain\n'
                                                                                          'information '
                                                                                          'will '
                                                                                          'be '
                                                                                          'displayed.\n',
                                                                           'executor': {'command': 'net '
                                                                                                   'localgroup\n'
                                                                                                   'net '
                                                                                                   'group '
                                                                                                   '/domain\n'
                                                                                                   'net '
                                                                                                   'group '
                                                                                                   '"domain '
                                                                                                   'admins" '
                                                                                                   '/domain\n',
                                                                                        'elevation_required': False,
                                                                                        'name': 'command_prompt'},
                                                                           'name': 'Basic '
                                                                                   'Permission '
                                                                                   'Groups '
                                                                                   'Discovery '
                                                                                   'Windows',
                                                                           'supported_platforms': ['windows']},
                                                                          {'description': 'Permission '
                                                                                          'Groups '
                                                                                          'Discovery '
                                                                                          'utilizing '
                                                                                          'PowerShell. '
                                                                                          'This '
                                                                                          'test '
                                                                                          'will '
                                                                                          'display '
                                                                                          'some '
                                                                                          'errors '
                                                                                          'if '
                                                                                          'run '
                                                                                          'on '
                                                                                          'a '
                                                                                          'computer '
                                                                                          'not '
                                                                                          'connected '
                                                                                          'to '
                                                                                          'a '
                                                                                          'domain. '
                                                                                          'Upon '
                                                                                          'execution, '
                                                                                          'domain\n'
                                                                                          'information '
                                                                                          'will '
                                                                                          'be '
                                                                                          'displayed.\n',
                                                                           'executor': {'command': 'get-localgroup\n'
                                                                                                   'get-ADPrincipalGroupMembership '
                                                                                                   '#{user} '
                                                                                                   '| '
                                                                                                   'select '
                                                                                                   'name\n',
                                                                                        'elevation_required': False,
                                                                                        'name': 'powershell'},
                                                                           'input_arguments': {'user': {'default': 'administrator',
                                                                                                        'description': 'User '
                                                                                                                       'to '
                                                                                                                       'identify '
                                                                                                                       'what '
                                                                                                                       'groups '
                                                                                                                       'a '
                                                                                                                       'user '
                                                                                                                       'is '
                                                                                                                       'a '
                                                                                                                       'member '
                                                                                                                       'of',
                                                                                                        'type': 'string'}},
                                                                           'name': 'Permission '
                                                                                   'Groups '
                                                                                   'Discovery '
                                                                                   'PowerShell',
                                                                           'supported_platforms': ['windows']},
                                                                          {'description': 'Runs '
                                                                                          '"net '
                                                                                          'group" '
                                                                                          'command '
                                                                                          'including '
                                                                                          'command '
                                                                                          'aliases '
                                                                                          'and '
                                                                                          'loose '
                                                                                          'typing '
                                                                                          'to '
                                                                                          'simulate '
                                                                                          'enumeration/discovery '
                                                                                          'of '
                                                                                          'high '
                                                                                          'value '
                                                                                          'domain '
                                                                                          'groups. '
                                                                                          'This\n'
                                                                                          'test '
                                                                                          'will '
                                                                                          'display '
                                                                                          'some '
                                                                                          'errors '
                                                                                          'if '
                                                                                          'run '
                                                                                          'on '
                                                                                          'a '
                                                                                          'computer '
                                                                                          'not '
                                                                                          'connected '
                                                                                          'to '
                                                                                          'a '
                                                                                          'domain. '
                                                                                          'Upon '
                                                                                          'execution, '
                                                                                          'domain '
                                                                                          'information '
                                                                                          'will '
                                                                                          'be '
                                                                                          'displayed.\n',
                                                                           'executor': {'command': 'net '
                                                                                                   'group '
                                                                                                   '/domai '
                                                                                                   '"Domain '
                                                                                                   'Admins"\n'
                                                                                                   'net '
                                                                                                   'groups '
                                                                                                   '"Account '
                                                                                                   'Operators" '
                                                                                                   '/doma\n'
                                                                                                   'net '
                                                                                                   'groups '
                                                                                                   '"Exchange '
                                                                                                   'Organization '
                                                                                                   'Management" '
                                                                                                   '/doma\n'
                                                                                                   'net '
                                                                                                   'group '
                                                                                                   '"BUILTIN\\Backup '
                                                                                                   'Operators" '
                                                                                                   '/doma\n',
                                                                                        'elevation_required': False,
                                                                                        'name': 'command_prompt'},
                                                                           'name': 'Elevated '
                                                                                   'group '
                                                                                   'enumeration '
                                                                                   'using '
                                                                                   'net '
                                                                                   'group',
                                                                           'supported_platforms': ['windows']}],
                                                         'attack_technique': 'T1069',
                                                         'display_name': 'Permission '
                                                                         'Groups '
                                                                         'Discovery'}},
 {'Mitre Stockpile - Summary of permission and security groups': {'description': 'Summary '
                                                                                 'of '
                                                                                 'permission '
                                                                                 'and '
                                                                                 'security '
                                                                                 'groups',
                                                                  'id': '5c4dd985-89e3-4590-9b57-71fed66ff4e2',
                                                                  'name': 'Permission '
                                                                          'Groups '
                                                                          'Discovery',
                                                                  'platforms': {'darwin': {'sh': {'command': 'groups'}},
                                                                                'linux': {'sh': {'command': 'groups'}},
                                                                                'windows': {'psh': {'command': 'gpresult '
                                                                                                               '/R\n'}}},
                                                                  'tactic': 'discovery',
                                                                  'technique': {'attack_id': 'T1069',
                                                                                'name': 'Permission '
                                                                                        'Groups '
                                                                                        'Discovery'}}},
 {'Mitre Stockpile - Identify all local users': {'description': 'Identify all '
                                                                'local users',
                                                 'id': 'feaced8f-f43f-452a-9500-a5219488abb8',
                                                 'name': 'Identify local users',
                                                 'platforms': {'darwin': {'sh': {'command': 'dscl '
                                                                                            '. '
                                                                                            'list '
                                                                                            '/Users '
                                                                                            '| '
                                                                                            'grep '
                                                                                            '-v '
                                                                                            "'_'\n"}},
                                                               'windows': {'psh': {'command': 'Get-WmiObject '
                                                                                              '-Class '
                                                                                              'Win32_UserAccount\n'}}},
                                                 'tactic': 'discovery',
                                                 'technique': {'attack_id': 'T1069',
                                                               'name': 'Permission '
                                                                       'Groups '
                                                                       'Discovery'}}},
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

None

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [admin@338](../actors/admin@338.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [APT3](../actors/APT3.md)
    
* [FIN6](../actors/FIN6.md)
    
