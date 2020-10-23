
# Account Discovery

## Description

### MITRE Description

> Adversaries may attempt to get a listing of accounts on a system or within an environment. This information can help adversaries determine which accounts exist to aid in follow-on behavior.

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
* Wiki: https://attack.mitre.org/techniques/T1087

## Potential Commands

```
net user [username] [/domain]
shell net user [username] [/domain]
post/windows/gather/enum_ad_users
auxiliary/scanner/smb/smb_enumusers
dsquery group "ou=Domain Admins,dc=domain,dc=com"
dsquery user "dc=domain,dc=com"
dsquery * OU="Domain Admins",DC=domain,DC=com -scope base -attr SAMAccountName userPrincipalName Description
dsquery * -filter "(&(objectCategory=contact)(objectCategory=person)(mail=*)(objectClass=user))" -Attr samAccountName mail -Limit 0
dsquery * -filter "(&(objectCategory=group)(name=*Admin*))" -Attr name description members
shell dsquery group "out=Domain Admins",dc=domain,dc=com"
shell dsquery user "dc=domain,dc=com"
shell dsquery * OU="Domain Admins",dc=domain,dc=com -scope base -attr SAMAccountName userPrincipleName Description
shell dsquery * -filter "(&(objectCategory=contact)(objectCategory=person)(mail=*)(objectClass=user))" -Attr samAccountName mail -Limit 0
shell dsquery * -filter "(&(objectCategory=group)(name=*Admin*))" -Attr name description members
Net.exe localgroup "administrators"
Net.exe group "domain admins" /domain
Net.exe user * /domain
wmic.exe useraccount get /ALL
wmic.exe useraccount list
wmic.exe qfe get description,installedOn /format:csv
wmic.exe process get caption,executablepath,commandline
wmic.exe service get name,displayname,pathname,startmode
wmic.exe share list
wmic.exe /node:"192.168.0.1" service where (caption like "%sql server (%")
wmic.exe get-wmiobject -class "win32_share" -namespace "root\CIMV2" -computer "targetname"
nltest.exe
powershell/management/get_domain_sid
powershell/management/sid_to_user
powershell/management/user_to_sid
powershell/situational_awareness/network/get_spn
powershell/situational_awareness/network/powerview/find_foreign_group
powershell/situational_awareness/network/powerview/find_foreign_user
powershell/situational_awareness/network/powerview/find_gpo_computer_admin
powershell/situational_awareness/network/powerview/find_gpo_location
powershell/situational_awareness/network/powerview/find_localadmin_access
powershell/situational_awareness/network/powerview/find_managed_security_group
powershell/situational_awareness/network/powerview/get_gpo_computer
powershell/situational_awareness/network/powerview/get_group
powershell/situational_awareness/network/powerview/get_group_member
powershell/situational_awareness/network/powerview/get_localgroup
powershell/situational_awareness/network/powerview/get_loggedon
powershell/situational_awareness/network/powerview/get_ou
powershell/situational_awareness/network/powerview/get_user
powershell/situational_awareness/network/powerview/user_hunter
python/situational_awareness/network/active_directory/dscl_get_groupmembers
python/situational_awareness/network/active_directory/dscl_get_groups
python/situational_awareness/network/active_directory/dscl_get_users
python/situational_awareness/network/active_directory/get_groupmembers
python/situational_awareness/network/active_directory/get_groupmemberships
python/situational_awareness/network/active_directory/get_groups
python/situational_awareness/network/active_directory/get_ous
python/situational_awareness/network/active_directory/get_userinformation
python/situational_awareness/network/active_directory/get_users
cat /etc/passwd > #{output_file}
Atomic Test #1 - Enumerate all accounts
Atomic Test #4 - Show if a user account has ever logger in remotely
id
lastlog > #{output_file}
cat /etc/sudoers > #{output_file}
lsof $USER
Atomic Test #2 - View sudoers access
username=$(echo $HOME | awk -F'/' '{print $3}') && lsof -u $username
groups
Atomic Test #5 - Enumerate users and groups
Atomic Test #3 - View accounts with UID 0
```

## Commands Dataset

```
[{'command': 'net user [username] [/domain]',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell net user [username] [/domain]',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'post/windows/gather/enum_ad_users\n'
             'auxiliary/scanner/smb/smb_enumusers',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'dsquery group "ou=Domain Admins,dc=domain,dc=com"\n'
             'dsquery user "dc=domain,dc=com"\n'
             'dsquery * OU="Domain Admins",DC=domain,DC=com -scope base -attr '
             'SAMAccountName userPrincipalName Description\n'
             'dsquery * -filter '
             '"(&(objectCategory=contact)(objectCategory=person)(mail=*)(objectClass=user))" '
             '-Attr samAccountName mail -Limit 0\n'
             'dsquery * -filter "(&(objectCategory=group)(name=*Admin*))" '
             '-Attr name description members',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell dsquery group "out=Domain Admins",dc=domain,dc=com"\n'
             'shell dsquery user "dc=domain,dc=com"\n'
             'shell dsquery * OU="Domain Admins",dc=domain,dc=com -scope base '
             '-attr SAMAccountName userPrincipleName Description\n'
             'shell dsquery * -filter '
             '"(&(objectCategory=contact)(objectCategory=person)(mail=*)(objectClass=user))" '
             '-Attr samAccountName mail -Limit 0\n'
             'shell dsquery * -filter '
             '"(&(objectCategory=group)(name=*Admin*))" -Attr name description '
             'members',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Net.exe localgroup "administrators"',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'Net.exe group "domain admins" /domain',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'Net.exe user * /domain',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe useraccount get /ALL',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe useraccount list',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe qfe get description,installedOn /format:csv',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe process get caption,executablepath,commandline',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe service get name,displayname,pathname,startmode',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe share list',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe /node:"192.168.0.1" service where (caption like "%sql '
             'server (%")',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe get-wmiobject -class "win32_share" -namespace '
             '"root\\CIMV2" -computer "targetname"',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'nltest.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell/management/get_domain_sid',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/get_domain_sid',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/sid_to_user',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/sid_to_user',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/user_to_sid',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/user_to_sid',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/get_spn',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/get_spn',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/find_foreign_group',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/find_foreign_group',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/find_foreign_user',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/find_foreign_user',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/find_gpo_computer_admin',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/find_gpo_computer_admin',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/find_gpo_location',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/find_gpo_location',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/find_localadmin_access',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/find_localadmin_access',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/find_managed_security_group',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/find_managed_security_group',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_gpo_computer',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_gpo_computer',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_group',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_group',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_group_member',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_group_member',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_localgroup',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_localgroup',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_loggedon',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_loggedon',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_ou',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_ou',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_user',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_user',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/user_hunter',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/user_hunter',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/dscl_get_groupmembers',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/dscl_get_groupmembers',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/dscl_get_groups',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/dscl_get_groups',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/dscl_get_users',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/dscl_get_users',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_groupmembers',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_groupmembers',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_groupmemberships',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_groupmemberships',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_groups',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_groups',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_ous',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_ous',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_userinformation',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_userinformation',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_users',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_users',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'Atomic Test #1 - Enumerate all accounts',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'cat /etc/passwd > #{output_file}',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'Atomic Test #2 - View sudoers access',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'cat /etc/sudoers > #{output_file}',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'Atomic Test #3 - View accounts with UID 0',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': "username=$(echo $HOME | awk -F'/' '{print $3}') && lsof -u "
             '$username',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'lsof $USER', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'Atomic Test #4 - Show if a user account has ever logger in '
             'remotely',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'lastlog > #{output_file}',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'Atomic Test #5 - Enumerate users and groups',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'groups', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'id', 'name': None, 'source': 'Kirtar22/Litmus_Test'}]
```

## Potential Detections

```json
[{'data_source': 'bash_history logs'},
 {'data_source': {'author': 'Samir Bousseaden',
                  'description': 'Detect priv users or groups recon based on '
                                 '4661 eventid and known privileged users or '
                                 'groups SIDs',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 4661,
                                              'ObjectName': ['*-512',
                                                             '*-502',
                                                             '*-500',
                                                             '*-505',
                                                             '*-519',
                                                             '*-520',
                                                             '*-544',
                                                             '*-551',
                                                             '*-555',
                                                             '*admin*'],
                                              'ObjectType': ['SAM_USER',
                                                             'SAM_GROUP']}},
                  'falsepositives': ['if source account name is not an admin '
                                     'then its super suspicious'],
                  'id': '35ba1d85-724d-42a3-889f-2e2362bcaf23',
                  'level': 'high',
                  'logsource': {'definition': 'Requirements: enable Object '
                                              'Access SAM on your Domain '
                                              'Controllers',
                                'product': 'windows',
                                'service': 'security'},
                  'references': ['https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html'],
                  'status': 'experimental',
                  'tags': ['attack.discovery', 'attack.t1087'],
                  'title': 'AD Privileged Users or Groups Reconnaissance'}},
 {'data_source': {'author': 'Timur Zinniatullin, Daniil Yugoslavskiy, '
                            'oscd.community',
                  'date': '2019/10/21',
                  'description': 'Local accounts, System Owner/User discovery '
                                 'using operating systems utilities',
                  'detection': {'condition': 'selection_1 or ( selection_2 and '
                                             'not filter )',
                                'filter': {'CommandLine|contains': ['/domain',
                                                                    '/add',
                                                                    '/delete',
                                                                    '/active',
                                                                    '/expires',
                                                                    '/passwordreq',
                                                                    '/scriptpath',
                                                                    '/times',
                                                                    '/workstations']},
                                'selection_1': [{'Image|endswith': '\\whoami.exe'},
                                                {'CommandLine|contains|all': ['useraccount',
                                                                              'get'],
                                                 'Image|endswith': '\\wmic.exe'},
                                                {'Image|endswith': ['\\quser.exe',
                                                                    '\\qwinsta.exe']},
                                                {'CommandLine|contains': '/list',
                                                 'Image|endswith': '\\cmdkey.exe'},
                                                {'CommandLine|contains|all': ['/c',
                                                                              'dir',
                                                                              '\\Users\\'],
                                                 'Image|endswith': '\\cmd.exe'}],
                                'selection_2': {'CommandLine|contains': 'user',
                                                'Image|endswith': ['\\net.exe',
                                                                   '\\net1.exe']}},
                  'falsepositives': ['Legitimate administrator or user '
                                     'enumerates local users for legitimate '
                                     'reason'],
                  'fields': ['Image',
                             'CommandLine',
                             'User',
                             'LogonGuid',
                             'Hashes',
                             'ParentProcessGuid',
                             'ParentCommandLine'],
                  'id': '502b42de-4306-40b4-9596-6f590c81f073',
                  'level': 'low',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.yaml'],
                  'status': 'experimental',
                  'tags': ['attack.discovery', 'attack.t1033', 'attack.t1087'],
                  'title': 'Local Accounts Discovery'}},
 {'data_source': {'analysis': {'recommendation': 'Check if the user that '
                                                 'executed the commands is '
                                                 'suspicious (e.g. service '
                                                 'accounts, LOCAL_SYSTEM)'},
                  'author': 'Florian Roth',
                  'description': 'Detects suspicious command line activity on '
                                 'Windows systems',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['net group '
                                                              '"domain admins" '
                                                              '/domain',
                                                              'net localgroup '
                                                              'administrators']}},
                  'falsepositives': ['Inventory tool runs',
                                     'Penetration tests',
                                     'Administrative activity'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': 'd95de845-b83c-4a9a-8a6a-4fc802ebf6c0',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'status': 'experimental',
                  'tags': ['attack.discovery', 'attack.t1087'],
                  'title': 'Suspicious Reconnaissance Activity'}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['API monitoring']}]
```

## Potential Queries

```json
[{'name': 'Account Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains "net.exe"or '
           'process_path contains "powershell.exe")and (process_command_line '
           'contains "*net* user*"or process_command_line contains "*net* '
           'group*"or process_command_line contains "*net* localgroup*"or '
           'process_command_line contains "cmdkey*\\\\/list*"or '
           'process_command_line contains "*get-localuser*"or '
           'process_command_line contains "*get-localgroupmembers*"or '
           'process_command_line contains "*get-aduser*"or '
           'process_command_line contains "query*user*")'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=bash_history cat /etc/passwd | table '
           'host,user_name,bash_command'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=bash_history cat /etc/sudoers | table '
           'host,user_name,bash_command'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=bash_history "lsof -u *" | table '
           'host,user_name,bash_command'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=bash_history lastlog | table '
           'host,user_name,bash_command'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=bash_history group OR id | table '
           'host,user_name,bash_command'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'net '
                                                                              'user '
                                                                              '[username] '
                                                                              '[/domain]',
                                                  'Category': 'T1087',
                                                  'Cobalt Strike': 'shell net '
                                                                   'user '
                                                                   '[username] '
                                                                   '[/domain]',
                                                  'Description': 'Used to add, '
                                                                 'delete, and '
                                                                 'manage the '
                                                                 'users on the '
                                                                 'computer. '
                                                                 'Run this '
                                                                 'command on '
                                                                 'the users '
                                                                 'discovered '
                                                                 'from the '
                                                                 'previous two '
                                                                 'commands to '
                                                                 'gather more '
                                                                 'information '
                                                                 'on targeted '
                                                                 'users.',
                                                  'Metasploit': 'post/windows/gather/enum_ad_users\n'
                                                                'auxiliary/scanner/smb/smb_enumusers'}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'dsquery '
                                                                              'group '
                                                                              '"ou=Domain '
                                                                              'Admins,dc=domain,dc=com"\n'
                                                                              'dsquery '
                                                                              'user '
                                                                              '"dc=domain,dc=com"\n'
                                                                              'dsquery '
                                                                              '* '
                                                                              'OU="Domain '
                                                                              'Admins",DC=domain,DC=com '
                                                                              '-scope '
                                                                              'base '
                                                                              '-attr '
                                                                              'SAMAccountName '
                                                                              'userPrincipalName '
                                                                              'Description\n'
                                                                              'dsquery '
                                                                              '* '
                                                                              '-filter '
                                                                              '"(&(objectCategory=contact)(objectCategory=person)(mail=*)(objectClass=user))" '
                                                                              '-Attr '
                                                                              'samAccountName '
                                                                              'mail '
                                                                              '-Limit '
                                                                              '0\n'
                                                                              'dsquery '
                                                                              '* '
                                                                              '-filter '
                                                                              '"(&(objectCategory=group)(name=*Admin*))" '
                                                                              '-Attr '
                                                                              'name '
                                                                              'description '
                                                                              'members',
                                                  'Category': 'T1087',
                                                  'Cobalt Strike': 'shell '
                                                                   'dsquery '
                                                                   'group '
                                                                   '"out=Domain '
                                                                   'Admins",dc=domain,dc=com"\n'
                                                                   'shell '
                                                                   'dsquery '
                                                                   'user '
                                                                   '"dc=domain,dc=com"\n'
                                                                   'shell '
                                                                   'dsquery * '
                                                                   'OU="Domain '
                                                                   'Admins",dc=domain,dc=com '
                                                                   '-scope '
                                                                   'base -attr '
                                                                   'SAMAccountName '
                                                                   'userPrincipleName '
                                                                   'Description\n'
                                                                   'shell '
                                                                   'dsquery * '
                                                                   '-filter '
                                                                   '"(&(objectCategory=contact)(objectCategory=person)(mail=*)(objectClass=user))" '
                                                                   '-Attr '
                                                                   'samAccountName '
                                                                   'mail '
                                                                   '-Limit 0\n'
                                                                   'shell '
                                                                   'dsquery * '
                                                                   '-filter '
                                                                   '"(&(objectCategory=group)(name=*Admin*))" '
                                                                   '-Attr name '
                                                                   'description '
                                                                   'members',
                                                  'Description': 'Dsquery is a '
                                                                 'Windows '
                                                                 'utility on '
                                                                 'servers that '
                                                                 'facilitates '
                                                                 'querying the '
                                                                 'Active '
                                                                 'Directory of '
                                                                 'the domain '
                                                                 'for lots of '
                                                                 'information '
                                                                 'about users, '
                                                                 'groups, and '
                                                                 'permissions. '
                                                                 'When '
                                                                 'constructing '
                                                                 'dsquery '
                                                                 'commands, if '
                                                                 'your domain '
                                                                 'is '
                                                                 '"subdomain.domain.tld", '
                                                                 'then your '
                                                                 'query will '
                                                                 'include '
                                                                 '"dc=subdomain,dc=domain,dc=tld"',
                                                  'Metasploit': ''}},
 {'Threat Hunting Tables': {'chain_id': '100137',
                            'commandline_string': 'localgroup "administrators"',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1087',
                            'mitre_caption': 'account_discovery',
                            'os': 'windows',
                            'parent_process': 'Net.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100138',
                            'commandline_string': 'group "domain admins" '
                                                  '/domain',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1087',
                            'mitre_caption': 'account_discovery',
                            'os': 'windows',
                            'parent_process': 'Net.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100139',
                            'commandline_string': 'user * /domain',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1087',
                            'mitre_caption': 'account_discovery',
                            'os': 'windows',
                            'parent_process': 'Net.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100140',
                            'commandline_string': 'useraccount get /ALL',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1087',
                            'mitre_caption': 'account_discovery',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100141',
                            'commandline_string': 'useraccount list',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1087',
                            'mitre_caption': 'account_discovery',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100142',
                            'commandline_string': 'qfe get '
                                                  'description,installedOn '
                                                  '/format:csv',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1087',
                            'mitre_caption': 'account_discovery',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100143',
                            'commandline_string': 'process get '
                                                  'caption,executablepath,commandline',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1087',
                            'mitre_caption': 'account_discovery',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100144',
                            'commandline_string': 'service get '
                                                  'name,displayname,pathname,startmode',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1087',
                            'mitre_caption': 'account_discovery',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100145',
                            'commandline_string': 'share list',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1087',
                            'mitre_caption': 'account_discovery',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100146',
                            'commandline_string': '/node:"192.168.0.1" service '
                                                  'where (caption like "%sql '
                                                  'server (%")',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1087',
                            'mitre_caption': 'account_discovery',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100147',
                            'commandline_string': 'get-wmiobject -class '
                                                  '"win32_share" -namespace '
                                                  '"root\\CIMV2" -computer '
                                                  '"targetname"',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1087',
                            'mitre_caption': 'account_discovery',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100215',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': 'https://www.hybrid-analysis.com/sample/43bc3efd795f4a1e84f9017f6b39ab331614665b4998e6c806dc8d0417ec314f?environmentId=100',
                            'loaded_dll': '',
                            'mitre_attack': 'T1087',
                            'mitre_caption': 'account_discovery',
                            'os': 'windows',
                            'parent_process': 'nltest.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/get_domain_sid":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/management/get_domain_sid',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/sid_to_user":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/management/sid_to_user',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/user_to_sid":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/management/user_to_sid',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/get_spn":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/get_spn',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/find_foreign_group":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/find_foreign_group',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/find_foreign_user":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/find_foreign_user',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/find_gpo_computer_admin":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/find_gpo_computer_admin',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/find_gpo_location":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/find_gpo_location',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/find_localadmin_access":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/find_localadmin_access',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/find_managed_security_group":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/find_managed_security_group',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_gpo_computer":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_gpo_computer',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_group":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_group',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_group_member":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_group_member',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_localgroup":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_localgroup',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': 'T1033',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_loggedon":  '
                                                                                 '["T1087","T1033"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_loggedon',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_ou":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_ou',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_user":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_user',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/user_hunter":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/user_hunter',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/active_directory/dscl_get_groupmembers":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'python/situational_awareness/network/active_directory/dscl_get_groupmembers',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/active_directory/dscl_get_groups":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'python/situational_awareness/network/active_directory/dscl_get_groups',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/active_directory/dscl_get_users":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'python/situational_awareness/network/active_directory/dscl_get_users',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/active_directory/get_groupmembers":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'python/situational_awareness/network/active_directory/get_groupmembers',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/active_directory/get_groupmemberships":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'python/situational_awareness/network/active_directory/get_groupmemberships',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/active_directory/get_groups":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'python/situational_awareness/network/active_directory/get_groups',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/active_directory/get_ous":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'python/situational_awareness/network/active_directory/get_ous',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/active_directory/get_userinformation":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'python/situational_awareness/network/active_directory/get_userinformation',
                                            'Technique': 'Account Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1087',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/active_directory/get_users":  '
                                                                                 '["T1087"],',
                                            'Empire Module': 'python/situational_awareness/network/active_directory/get_users',
                                            'Technique': 'Account Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [Account Discovery Mitigation](../mitigations/Account-Discovery-Mitigation.md)

* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    

# Actors

None
