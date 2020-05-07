
# Account Discovery

## Description

### MITRE Description

> Adversaries may attempt to get a listing of local system or domain accounts. 

### Windows

Example commands that can acquire this information are <code>net user</code>, <code>net group <groupname></code>, and <code>net localgroup <groupname></code> using the [Net](https://attack.mitre.org/software/S0039) utility or through use of [dsquery](https://attack.mitre.org/software/S0105). If adversaries attempt to identify the primary user, currently logged in user, or set of users that commonly uses a system, [System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) may apply.

### Mac

On Mac, groups can be enumerated through the <code>groups</code> and <code>id</code> commands. In mac specifically, <code>dscl . list /Groups</code> and <code>dscacheutil -q group</code> can also be used to enumerate groups and users.

### Linux

On Linux, local users can be enumerated through the use of the <code>/etc/passwd</code> file which is world readable. In mac, this same file is only used in single-user mode in addition to the <code>/etc/master.passwd</code> file.

Also, groups can be enumerated through the <code>groups</code> and <code>id</code> commands.

### Office 365 and Azure AD

With authenticated access there are several tools that can be used to find accounts. The <code>Get-MsolRoleMember</code> PowerShell cmdlet can be used to obtain account names given a role or permissions group.(Citation: Microsoft msolrolemember)(Citation: GitHub Raindance)

Azure CLI (AZ CLI) also provides an interface to obtain user accounts with authenticated access to a domain. The command <code>az ad user list</code> will list all users within a domain.(Citation: Microsoft AZ CLI)(Citation: Black Hills Red Teaming MS AD Azure, 2018) 

The <code>Get-GlobalAddressList</code> PowerShell cmdlet can be used to obtain email addresses and accounts from a domain using an authenticated session.(Citation: Microsoft getglobaladdresslist)(Citation: Black Hills Attacking Exchange MailSniper, 2016)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows', 'Office 365', 'Azure AD']
* Remote: intentionally left blank
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
cat /etc/passwd > /tmp/T1087.txt
cat /tmp/T1087.txt

cat /etc/sudoers > /tmp/T1087.txt
cat /tmp/T1087.txt

grep 'x:0:' /etc/passwd > /tmp/T1087.txt
cat /tmp/T1087.txt 2>/dev/null

username=$(echo $HOME | awk -F'/' '{print $3}') && lsof -u $username

lastlog > /tmp/T1087.txt
cat /tmp/T1087.txt

groups
id

dscl . list /Groups
dscl . list /Users
dscl . list /Users | grep -v '_'
dscacheutil -q group
dscacheutil -q user

net user
net user /domain
dir c:\Users\
cmdkey.exe /list
net localgroup "Users"
net localgroup

net user
net user /domain
get-localuser
get-localgroupmember -group Users
cmdkey.exe /list
ls C:/Users
get-childitem C:\Users\
dir C:\Users\
get-aduser -filter *
get-localgroup
net localgroup

query user

query user

{'windows': {'cmd,psh': {'command': 'net user #{domain.user.name} /domain'}}}
{'darwin': {'sh': {'command': "cut -d: -f1 /etc/passwd | grep -v '_' | grep -v '#'\n", 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'}]}}}, 'linux': {'sh': {'command': "cut -d: -f1 /etc/passwd | grep -v '_' | grep -v '#'\n", 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'}]}}}}
{'windows': {'cmd': {'command': 'net user /domain'}}}
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
powershell/management/get_domain_sid
powershell/management/sid_to_user
powershell/management/sid_to_user
powershell/management/user_to_sid
powershell/management/user_to_sid
powershell/situational_awareness/network/get_spn
powershell/situational_awareness/network/get_spn
powershell/situational_awareness/network/powerview/find_foreign_group
powershell/situational_awareness/network/powerview/find_foreign_group
powershell/situational_awareness/network/powerview/find_foreign_user
powershell/situational_awareness/network/powerview/find_foreign_user
powershell/situational_awareness/network/powerview/find_gpo_computer_admin
powershell/situational_awareness/network/powerview/find_gpo_computer_admin
powershell/situational_awareness/network/powerview/find_gpo_location
powershell/situational_awareness/network/powerview/find_gpo_location
powershell/situational_awareness/network/powerview/find_localadmin_access
powershell/situational_awareness/network/powerview/find_localadmin_access
powershell/situational_awareness/network/powerview/find_managed_security_group
powershell/situational_awareness/network/powerview/find_managed_security_group
powershell/situational_awareness/network/powerview/get_gpo_computer
powershell/situational_awareness/network/powerview/get_gpo_computer
powershell/situational_awareness/network/powerview/get_group
powershell/situational_awareness/network/powerview/get_group
powershell/situational_awareness/network/powerview/get_group_member
powershell/situational_awareness/network/powerview/get_group_member
powershell/situational_awareness/network/powerview/get_localgroup
powershell/situational_awareness/network/powerview/get_localgroup
powershell/situational_awareness/network/powerview/get_loggedon
powershell/situational_awareness/network/powerview/get_loggedon
powershell/situational_awareness/network/powerview/get_ou
powershell/situational_awareness/network/powerview/get_ou
powershell/situational_awareness/network/powerview/get_user
powershell/situational_awareness/network/powerview/get_user
powershell/situational_awareness/network/powerview/user_hunter
powershell/situational_awareness/network/powerview/user_hunter
python/situational_awareness/network/active_directory/dscl_get_groupmembers
python/situational_awareness/network/active_directory/dscl_get_groupmembers
python/situational_awareness/network/active_directory/dscl_get_groups
python/situational_awareness/network/active_directory/dscl_get_groups
python/situational_awareness/network/active_directory/dscl_get_users
python/situational_awareness/network/active_directory/dscl_get_users
python/situational_awareness/network/active_directory/get_groupmembers
python/situational_awareness/network/active_directory/get_groupmembers
python/situational_awareness/network/active_directory/get_groupmemberships
python/situational_awareness/network/active_directory/get_groupmemberships
python/situational_awareness/network/active_directory/get_groups
python/situational_awareness/network/active_directory/get_groups
python/situational_awareness/network/active_directory/get_ous
python/situational_awareness/network/active_directory/get_ous
python/situational_awareness/network/active_directory/get_userinformation
python/situational_awareness/network/active_directory/get_userinformation
python/situational_awareness/network/active_directory/get_users
python/situational_awareness/network/active_directory/get_users
Atomic Test #1 - Enumerate all accounts
cat /etc/passwd > #{output_file}
Atomic Test #2 - View sudoers access
cat /etc/sudoers > #{output_file}
Atomic Test #3 - View accounts with UID 0
username=$(echo $HOME | awk -F'/' '{print $3}') && lsof -u $username
lsof $USER
Atomic Test #4 - Show if a user account has ever logger in remotely
lastlog > #{output_file}
Atomic Test #5 - Enumerate users and groups
groups
id
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
 {'command': 'cat /etc/passwd > /tmp/T1087.txt\ncat /tmp/T1087.txt\n',
  'name': None,
  'source': 'atomics/T1087/T1087.yaml'},
 {'command': 'cat /etc/sudoers > /tmp/T1087.txt\ncat /tmp/T1087.txt\n',
  'name': None,
  'source': 'atomics/T1087/T1087.yaml'},
 {'command': "grep 'x:0:' /etc/passwd > /tmp/T1087.txt\n"
             'cat /tmp/T1087.txt 2>/dev/null\n',
  'name': None,
  'source': 'atomics/T1087/T1087.yaml'},
 {'command': "username=$(echo $HOME | awk -F'/' '{print $3}') && lsof -u "
             '$username\n',
  'name': None,
  'source': 'atomics/T1087/T1087.yaml'},
 {'command': 'lastlog > /tmp/T1087.txt\ncat /tmp/T1087.txt\n',
  'name': None,
  'source': 'atomics/T1087/T1087.yaml'},
 {'command': 'groups\nid\n',
  'name': None,
  'source': 'atomics/T1087/T1087.yaml'},
 {'command': 'dscl . list /Groups\n'
             'dscl . list /Users\n'
             "dscl . list /Users | grep -v '_'\n"
             'dscacheutil -q group\n'
             'dscacheutil -q user\n',
  'name': None,
  'source': 'atomics/T1087/T1087.yaml'},
 {'command': 'net user\n'
             'net user /domain\n'
             'dir c:\\Users\\\n'
             'cmdkey.exe /list\n'
             'net localgroup "Users"\n'
             'net localgroup\n',
  'name': None,
  'source': 'atomics/T1087/T1087.yaml'},
 {'command': 'net user\n'
             'net user /domain\n'
             'get-localuser\n'
             'get-localgroupmember -group Users\n'
             'cmdkey.exe /list\n'
             'ls C:/Users\n'
             'get-childitem C:\\Users\\\n'
             'dir C:\\Users\\\n'
             'get-aduser -filter *\n'
             'get-localgroup\n'
             'net localgroup\n',
  'name': None,
  'source': 'atomics/T1087/T1087.yaml'},
 {'command': 'query user\n',
  'name': None,
  'source': 'atomics/T1087/T1087.yaml'},
 {'command': 'query user\n',
  'name': None,
  'source': 'atomics/T1087/T1087.yaml'},
 {'command': {'windows': {'cmd,psh': {'command': 'net user #{domain.user.name} '
                                                 '/domain'}}},
  'name': 'The net utility is executed via cmd to enumerate detailed '
          'information about a specific user account.',
  'source': 'data/abilities/discovery/364ea817-bbb9-4083-87dd-94b9dba45f6f.yml'},
 {'command': {'darwin': {'sh': {'command': 'cut -d: -f1 /etc/passwd | grep -v '
                                           "'_' | grep -v '#'\n",
                                'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'}]}}},
              'linux': {'sh': {'command': 'cut -d: -f1 /etc/passwd | grep -v '
                                          "'_' | grep -v '#'\n",
                               'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'}]}}}},
  'name': 'Get a list of all local users',
  'source': 'data/abilities/discovery/c1cd6388-3ced-48c7-a511-0434c6ba8f48.yml'},
 {'command': {'windows': {'cmd': {'command': 'net user /domain'}}},
  'name': 'The net utility is executed via cmd to enumerate domain user '
          'accounts.',
  'source': 'data/abilities/discovery/c7ec57cd-933e-42b6-99a4-e852a9e57a33.yml'},
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
[{'data_source': 'bash_history logs'}]
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
 {'Atomic Red Team Test - Account Discovery': {'atomic_tests': [{'description': 'Enumerate '
                                                                                'all '
                                                                                'accounts '
                                                                                'by '
                                                                                'copying '
                                                                                '/etc/passwd '
                                                                                'to '
                                                                                'another '
                                                                                'file\n',
                                                                 'executor': {'cleanup_command': 'rm '
                                                                                                 '-f '
                                                                                                 '#{output_file}\n',
                                                                              'command': 'cat '
                                                                                         '/etc/passwd '
                                                                                         '> '
                                                                                         '#{output_file}\n'
                                                                                         'cat '
                                                                                         '#{output_file}\n',
                                                                              'name': 'sh'},
                                                                 'input_arguments': {'output_file': {'default': '/tmp/T1087.txt',
                                                                                                     'description': 'Path '
                                                                                                                    'where '
                                                                                                                    'captured '
                                                                                                                    'results '
                                                                                                                    'will '
                                                                                                                    'be '
                                                                                                                    'placed',
                                                                                                     'type': 'Path'}},
                                                                 'name': 'Enumerate '
                                                                         'all '
                                                                         'accounts',
                                                                 'supported_platforms': ['linux',
                                                                                         'macos']},
                                                                {'description': '(requires '
                                                                                'root)\n',
                                                                 'executor': {'cleanup_command': 'rm '
                                                                                                 '-f '
                                                                                                 '#{output_file}\n',
                                                                              'command': 'cat '
                                                                                         '/etc/sudoers '
                                                                                         '> '
                                                                                         '#{output_file}\n'
                                                                                         'cat '
                                                                                         '#{output_file}\n',
                                                                              'elevation_required': True,
                                                                              'name': 'sh'},
                                                                 'input_arguments': {'output_file': {'default': '/tmp/T1087.txt',
                                                                                                     'description': 'Path '
                                                                                                                    'where '
                                                                                                                    'captured '
                                                                                                                    'results '
                                                                                                                    'will '
                                                                                                                    'be '
                                                                                                                    'placed',
                                                                                                     'type': 'Path'}},
                                                                 'name': 'View '
                                                                         'sudoers '
                                                                         'access',
                                                                 'supported_platforms': ['linux',
                                                                                         'macos']},
                                                                {'description': 'View '
                                                                                'accounts '
                                                                                'wtih '
                                                                                'UID '
                                                                                '0\n',
                                                                 'executor': {'cleanup_command': 'rm '
                                                                                                 '-f '
                                                                                                 '#{output_file} '
                                                                                                 '2>/dev/null\n',
                                                                              'command': 'grep '
                                                                                         "'x:0:' "
                                                                                         '/etc/passwd '
                                                                                         '> '
                                                                                         '#{output_file}\n'
                                                                                         'cat '
                                                                                         '#{output_file} '
                                                                                         '2>/dev/null\n',
                                                                              'name': 'sh'},
                                                                 'input_arguments': {'output_file': {'default': '/tmp/T1087.txt',
                                                                                                     'description': 'Path '
                                                                                                                    'where '
                                                                                                                    'captured '
                                                                                                                    'results '
                                                                                                                    'will '
                                                                                                                    'be '
                                                                                                                    'placed',
                                                                                                     'type': 'Path'}},
                                                                 'name': 'View '
                                                                         'accounts '
                                                                         'with '
                                                                         'UID '
                                                                         '0',
                                                                 'supported_platforms': ['linux',
                                                                                         'macos']},
                                                                {'description': 'List '
                                                                                'opened '
                                                                                'files '
                                                                                'by '
                                                                                'user\n',
                                                                 'executor': {'command': 'username=$(echo '
                                                                                         '$HOME '
                                                                                         '| '
                                                                                         'awk '
                                                                                         "-F'/' "
                                                                                         "'{print "
                                                                                         "$3}') "
                                                                                         '&& '
                                                                                         'lsof '
                                                                                         '-u '
                                                                                         '$username\n',
                                                                              'name': 'sh'},
                                                                 'name': 'List '
                                                                         'opened '
                                                                         'files '
                                                                         'by '
                                                                         'user',
                                                                 'supported_platforms': ['linux',
                                                                                         'macos']},
                                                                {'dependencies': [{'description': 'Check '
                                                                                                  'if '
                                                                                                  'lastlog '
                                                                                                  'command '
                                                                                                  'exists '
                                                                                                  'on '
                                                                                                  'the '
                                                                                                  'machine\n',
                                                                                   'get_prereq_command': 'echo '
                                                                                                         '"Install '
                                                                                                         'lastlog '
                                                                                                         'on '
                                                                                                         'the '
                                                                                                         'machine '
                                                                                                         'to '
                                                                                                         'run '
                                                                                                         'the '
                                                                                                         'test."; '
                                                                                                         'exit '
                                                                                                         '1;   \n',
                                                                                   'prereq_command': 'if '
                                                                                                     '[ '
                                                                                                     '-x '
                                                                                                     '"$(command '
                                                                                                     '-v '
                                                                                                     'lastlog)" '
                                                                                                     ']; '
                                                                                                     'then '
                                                                                                     'exit '
                                                                                                     '0; '
                                                                                                     'else '
                                                                                                     'exit '
                                                                                                     '1;\n'}],
                                                                 'dependency_executor_name': 'sh',
                                                                 'description': 'Show '
                                                                                'if '
                                                                                'a '
                                                                                'user '
                                                                                'account '
                                                                                'has '
                                                                                'ever '
                                                                                'logged '
                                                                                'in '
                                                                                'remotely\n',
                                                                 'executor': {'cleanup_command': 'rm '
                                                                                                 '-f '
                                                                                                 '#{output_file}\n',
                                                                              'command': 'lastlog '
                                                                                         '> '
                                                                                         '#{output_file}\n'
                                                                                         'cat '
                                                                                         '#{output_file}\n',
                                                                              'name': 'sh'},
                                                                 'input_arguments': {'output_file': {'default': '/tmp/T1087.txt',
                                                                                                     'description': 'Path '
                                                                                                                    'where '
                                                                                                                    'captured '
                                                                                                                    'results '
                                                                                                                    'will '
                                                                                                                    'be '
                                                                                                                    'placed',
                                                                                                     'type': 'Path'}},
                                                                 'name': 'Show '
                                                                         'if a '
                                                                         'user '
                                                                         'account '
                                                                         'has '
                                                                         'ever '
                                                                         'logged '
                                                                         'in '
                                                                         'remotely',
                                                                 'supported_platforms': ['linux']},
                                                                {'description': 'Utilize '
                                                                                'groups '
                                                                                'and '
                                                                                'id '
                                                                                'to '
                                                                                'enumerate '
                                                                                'users '
                                                                                'and '
                                                                                'groups\n',
                                                                 'executor': {'command': 'groups\n'
                                                                                         'id\n',
                                                                              'name': 'sh'},
                                                                 'name': 'Enumerate '
                                                                         'users '
                                                                         'and '
                                                                         'groups',
                                                                 'supported_platforms': ['linux',
                                                                                         'macos']},
                                                                {'description': 'Utilize '
                                                                                'local '
                                                                                'utilities '
                                                                                'to '
                                                                                'enumerate '
                                                                                'users '
                                                                                'and '
                                                                                'groups\n',
                                                                 'executor': {'command': 'dscl '
                                                                                         '. '
                                                                                         'list '
                                                                                         '/Groups\n'
                                                                                         'dscl '
                                                                                         '. '
                                                                                         'list '
                                                                                         '/Users\n'
                                                                                         'dscl '
                                                                                         '. '
                                                                                         'list '
                                                                                         '/Users '
                                                                                         '| '
                                                                                         'grep '
                                                                                         '-v '
                                                                                         "'_'\n"
                                                                                         'dscacheutil '
                                                                                         '-q '
                                                                                         'group\n'
                                                                                         'dscacheutil '
                                                                                         '-q '
                                                                                         'user\n',
                                                                              'name': 'sh'},
                                                                 'name': 'Enumerate '
                                                                         'users '
                                                                         'and '
                                                                         'groups',
                                                                 'supported_platforms': ['macos']},
                                                                {'description': 'Enumerate '
                                                                                'all '
                                                                                'accounts\n'
                                                                                'Upon '
                                                                                'exection, '
                                                                                'multiple '
                                                                                'enumeration '
                                                                                'commands '
                                                                                'will '
                                                                                'be '
                                                                                'run '
                                                                                'and '
                                                                                'their '
                                                                                'output '
                                                                                'displayed '
                                                                                'in '
                                                                                'the '
                                                                                'PowerShell '
                                                                                'session\n',
                                                                 'executor': {'command': 'net '
                                                                                         'user\n'
                                                                                         'net '
                                                                                         'user '
                                                                                         '/domain\n'
                                                                                         'dir '
                                                                                         'c:\\Users\\\n'
                                                                                         'cmdkey.exe '
                                                                                         '/list\n'
                                                                                         'net '
                                                                                         'localgroup '
                                                                                         '"Users"\n'
                                                                                         'net '
                                                                                         'localgroup\n',
                                                                              'elevation_required': False,
                                                                              'name': 'command_prompt'},
                                                                 'name': 'Enumerate '
                                                                         'all '
                                                                         'accounts',
                                                                 'supported_platforms': ['windows']},
                                                                {'description': 'Enumerate '
                                                                                'all '
                                                                                'accounts '
                                                                                'via '
                                                                                'PowerShell. '
                                                                                'Upon '
                                                                                'execution, '
                                                                                'lots '
                                                                                'of '
                                                                                'user '
                                                                                'account '
                                                                                'and '
                                                                                'group '
                                                                                'information '
                                                                                'will '
                                                                                'be '
                                                                                'displayed.\n',
                                                                 'executor': {'command': 'net '
                                                                                         'user\n'
                                                                                         'net '
                                                                                         'user '
                                                                                         '/domain\n'
                                                                                         'get-localuser\n'
                                                                                         'get-localgroupmember '
                                                                                         '-group '
                                                                                         'Users\n'
                                                                                         'cmdkey.exe '
                                                                                         '/list\n'
                                                                                         'ls '
                                                                                         'C:/Users\n'
                                                                                         'get-childitem '
                                                                                         'C:\\Users\\\n'
                                                                                         'dir '
                                                                                         'C:\\Users\\\n'
                                                                                         'get-aduser '
                                                                                         '-filter '
                                                                                         '*\n'
                                                                                         'get-localgroup\n'
                                                                                         'net '
                                                                                         'localgroup\n',
                                                                              'elevation_required': False,
                                                                              'name': 'powershell'},
                                                                 'name': 'Enumerate '
                                                                         'all '
                                                                         'accounts '
                                                                         'via '
                                                                         'PowerShell',
                                                                 'supported_platforms': ['windows']},
                                                                {'description': 'Enumerate '
                                                                                'logged '
                                                                                'on '
                                                                                'users. '
                                                                                'Upon '
                                                                                'exeuction, '
                                                                                'logged '
                                                                                'on '
                                                                                'users '
                                                                                'will '
                                                                                'be '
                                                                                'displayed.\n',
                                                                 'executor': {'command': 'query '
                                                                                         'user\n',
                                                                              'elevation_required': False,
                                                                              'name': 'command_prompt'},
                                                                 'name': 'Enumerate '
                                                                         'logged '
                                                                         'on '
                                                                         'users '
                                                                         'via '
                                                                         'CMD',
                                                                 'supported_platforms': ['windows']},
                                                                {'description': 'Enumerate '
                                                                                'logged '
                                                                                'on '
                                                                                'users '
                                                                                'via '
                                                                                'PowerShell. '
                                                                                'Upon '
                                                                                'exeuction, '
                                                                                'logged '
                                                                                'on '
                                                                                'users '
                                                                                'will '
                                                                                'be '
                                                                                'displayed.\n',
                                                                 'executor': {'command': 'query '
                                                                                         'user\n',
                                                                              'elevation_required': False,
                                                                              'name': 'powershell'},
                                                                 'name': 'Enumerate '
                                                                         'logged '
                                                                         'on '
                                                                         'users '
                                                                         'via '
                                                                         'PowerShell',
                                                                 'supported_platforms': ['windows']}],
                                               'attack_technique': 'T1087',
                                               'display_name': 'Account '
                                                               'Discovery'}},
 {'Mitre Stockpile - The net utility is executed via cmd to enumerate detailed information about a specific user account.': {'description': 'The '
                                                                                                                                            'net '
                                                                                                                                            'utility '
                                                                                                                                            'is '
                                                                                                                                            'executed '
                                                                                                                                            'via '
                                                                                                                                            'cmd '
                                                                                                                                            'to '
                                                                                                                                            'enumerate '
                                                                                                                                            'detailed '
                                                                                                                                            'information '
                                                                                                                                            'about '
                                                                                                                                            'a '
                                                                                                                                            'specific '
                                                                                                                                            'user '
                                                                                                                                            'account.',
                                                                                                                             'id': '364ea817-bbb9-4083-87dd-94b9dba45f6f',
                                                                                                                             'name': 'Account '
                                                                                                                                     'Discovery '
                                                                                                                                     '(targeted)',
                                                                                                                             'platforms': {'windows': {'cmd,psh': {'command': 'net '
                                                                                                                                                                              'user '
                                                                                                                                                                              '#{domain.user.name} '
                                                                                                                                                                              '/domain'}}},
                                                                                                                             'tactic': 'discovery',
                                                                                                                             'technique': {'attack_id': 'T1087',
                                                                                                                                           'name': 'Account '
                                                                                                                                                   'Discovery'}}},
 {'Mitre Stockpile - Get a list of all local users': {'description': 'Get a '
                                                                     'list of '
                                                                     'all '
                                                                     'local '
                                                                     'users',
                                                      'id': 'c1cd6388-3ced-48c7-a511-0434c6ba8f48',
                                                      'name': 'Find local '
                                                              'users',
                                                      'platforms': {'darwin': {'sh': {'command': 'cut '
                                                                                                 '-d: '
                                                                                                 '-f1 '
                                                                                                 '/etc/passwd '
                                                                                                 '| '
                                                                                                 'grep '
                                                                                                 '-v '
                                                                                                 "'_' "
                                                                                                 '| '
                                                                                                 'grep '
                                                                                                 '-v '
                                                                                                 "'#'\n",
                                                                                      'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'}]}}},
                                                                    'linux': {'sh': {'command': 'cut '
                                                                                                '-d: '
                                                                                                '-f1 '
                                                                                                '/etc/passwd '
                                                                                                '| '
                                                                                                'grep '
                                                                                                '-v '
                                                                                                "'_' "
                                                                                                '| '
                                                                                                'grep '
                                                                                                '-v '
                                                                                                "'#'\n",
                                                                                     'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.user.name'}]}}}},
                                                      'tactic': 'discovery',
                                                      'technique': {'attack_id': 'T1087',
                                                                    'name': 'Account '
                                                                            'Discovery'}}},
 {'Mitre Stockpile - The net utility is executed via cmd to enumerate domain user accounts.': {'description': 'The '
                                                                                                              'net '
                                                                                                              'utility '
                                                                                                              'is '
                                                                                                              'executed '
                                                                                                              'via '
                                                                                                              'cmd '
                                                                                                              'to '
                                                                                                              'enumerate '
                                                                                                              'domain '
                                                                                                              'user '
                                                                                                              'accounts.',
                                                                                               'id': 'c7ec57cd-933e-42b6-99a4-e852a9e57a33',
                                                                                               'name': 'Account '
                                                                                                       'Discovery '
                                                                                                       '(all)',
                                                                                               'platforms': {'windows': {'cmd': {'command': 'net '
                                                                                                                                            'user '
                                                                                                                                            '/domain'}}},
                                                                                               'tactic': 'discovery',
                                                                                               'technique': {'attack_id': 'T1087',
                                                                                                             'name': 'Account '
                                                                                                                     'Discovery'}}},
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

None

# Actors


* [APT3](../actors/APT3.md)

* [FIN6](../actors/FIN6.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [admin@338](../actors/admin@338.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [menuPass](../actors/menuPass.md)
    
* [APT32](../actors/APT32.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [OilRig](../actors/OilRig.md)
    
* [APT1](../actors/APT1.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Poseidon Group](../actors/Poseidon-Group.md)
    
