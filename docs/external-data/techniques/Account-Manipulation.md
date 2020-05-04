
# Account Manipulation

## Description

### MITRE Description

> Account manipulation may aid adversaries in maintaining access to credentials and certain permission levels within an environment. Manipulation could consist of modifying permissions, modifying credentials, adding or changing permission groups, modifying account settings, or modifying how authentication is performed. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to subvert password duration policies and preserve the life of compromised credentials. In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain.

### Exchange Email Account Takeover

The Add-MailboxPermission PowerShell cmdlet, available in on-premises Exchange and in the cloud-based service Office 365, adds permissions to a mailbox.(Citation: Microsoft - Add-MailboxPermission) This command can be run, given adequate permissions, to further access granted to certain user accounts. This may be used in persistent threat incidents as well as BEC (Business Email Compromise) incidents where an adversary can assign more access rights to the accounts they wish to compromise. This may further enable use of additional techniques for gaining access to systems. For example, compromised business accounts are often used to send messages to other accounts in the network of the target business while creating inbox rules so the messages evade spam/phishing detection mechanisms.(Citation: Bienstock, D. - Defending O365 - 2019)

### Azure AD

In Azure, an adversary can set a second password for Service Principals, facilitating persistence.(Citation: Blue Cloud of Death)

### AWS

AWS policies allow trust between accounts by simply identifying the account name. It is then up to the trusted account to only allow the correct roles to have access.(Citation: Summit Route Advanced AWS policy auditing)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator']
* Platforms: ['Windows', 'Office 365', 'Azure', 'GCP', 'Azure AD', 'AWS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1098

## Potential Commands

```
$x = Get-Random -Minimum 2 -Maximum 9999
$y = Get-Random -Minimum 2 -Maximum 9999
$z = Get-Random -Minimum 2 -Maximum 9999
$w = Get-Random -Minimum 2 -Maximum 9999
Write-Host HaHaHa_$x$y$z$w

$hostname = (Get-CIMInstance CIM_ComputerSystem).Name

$fmm = Get-CimInstance -ClassName win32_group -Filter "name = 'Administrators'" | Get-CimAssociatedInstance -Association win32_groupuser | Select Name

foreach($member in $fmm) {
    if($member -like "*Administrator*") {
        Rename-LocalUser -Name $member.Name -NewName "HaHaHa_$x$y$z$w"
        Write-Host "Successfully Renamed Administrator Account on" $hostname
        }
    }

powershell/management/honeyhash
powershell/management/honeyhash
powershell/situational_awareness/network/powerview/set_ad_object
powershell/situational_awareness/network/powerview/set_ad_object
Dos
C: \ Windows \ system32> net user test321 Test.321 / add
The command completed successfully.
Dos
C: \ Windows \ system32> net user test321 Test.321 / add
The command completed successfully.
```

## Commands Dataset

```
[{'command': '$x = Get-Random -Minimum 2 -Maximum 9999\n'
             '$y = Get-Random -Minimum 2 -Maximum 9999\n'
             '$z = Get-Random -Minimum 2 -Maximum 9999\n'
             '$w = Get-Random -Minimum 2 -Maximum 9999\n'
             'Write-Host HaHaHa_$x$y$z$w\n'
             '\n'
             '$hostname = (Get-CIMInstance CIM_ComputerSystem).Name\n'
             '\n'
             '$fmm = Get-CimInstance -ClassName win32_group -Filter "name = '
             '\'Administrators\'" | Get-CimAssociatedInstance -Association '
             'win32_groupuser | Select Name\n'
             '\n'
             'foreach($member in $fmm) {\n'
             '    if($member -like "*Administrator*") {\n'
             '        Rename-LocalUser -Name $member.Name -NewName '
             '"HaHaHa_$x$y$z$w"\n'
             '        Write-Host "Successfully Renamed Administrator Account '
             'on" $hostname\n'
             '        }\n'
             '    }\n',
  'name': None,
  'source': 'atomics/T1098/T1098.yaml'},
 {'command': 'powershell/management/honeyhash',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/honeyhash',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/set_ad_object',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/set_ad_object',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'Dos\n'
             'C: \\ Windows \\ system32> net user test321 Test.321 / add\n'
             'The command completed successfully.',
  'name': 'Dos',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Dos\n'
             'C: \\ Windows \\ system32> net user test321 Test.321 / add\n'
             'The command completed successfully.',
  'name': 'Dos',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows local account manipulation\n'
           'description: win7 test\n'
           'references:\n'
           'tags: T1087 / T1069\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 #'ve created a new "
           'process\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ * \\ "
           "net.exe'\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Tokenpromotiontype: '
           'TokenElevationTypeFull (2)\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 #'ve created a new "
           'process\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ * \\ "
           "net1.exe'\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Tokenpromotiontype: '
           'TokenElevationTypeFull (2)\n'
           '\xa0\xa0\xa0\xa0selection3:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4656 # has been requested '
           'to handle objects\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ObjectServer: 'Security Account "
           "Manager' # Object> Object Server\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Objecttype: 'SAM_DOMAIN' # Object> "
           'Object Type\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processname: 'C: \\ Windows \\ "
           "System32 \\ lsass.exe' # process> process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Access: 'CreateUser'\n"
           '\xa0\xa0\xa0\xa0selection4:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4728 # has enabled global '
           'security group to add a member.\n'
           '\xa0\xa0\xa0\xa0selection5:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4720 # user account has '
           'been created.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0SecurityID: '*' # new account> "
           'Security ID\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Accountname: '*' # new account> "
           'account name\n'
           '\xa0\xa0\xa0\xa0selection6:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4722 #-enabled user '
           'accounts.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Security ID: '*' # target account> "
           'Security ID\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Accountname: '*' # target account> "
           'account name\n'
           '\xa0\xa0\xa0\xa0selection7:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4738 # Changed user '
           'account.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Security ID: '*' # target account> "
           'Security ID\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Accountname: '*' # target account> "
           'account name\n'
           '\xa0\xa0\xa0\xa0timeframe: last 20s\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: Windows-AdminSDHolder\n'
           'description: Windows server 2008 R2 (AD domain controller)\n'
           'references: '
           'https://github.com/infosecn1nja/AD-Attack-Defense/blob/master/README.md '
           'OR '
           'https://github.com/0Kee-Team/WatchAD/blob/master/modules/detect/event_log/ '
           'persistence / AdminSDHolder.py\n'
           'tags: 1098\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 5136 # directory service '
           'object was modified. AdminSDHolder change, as a general authority '
           'to maintain, because the situation changes very little\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4780 #ACL provided on a '
           'member of the Administrators group account\n'
           '\xa0\xa0\xa0\xa0timeframe: last 1h # default wait 60 minutes to '
           'take effect, the specific reasons described below with reference '
           'may SDPROP\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows local account manipulation\n'
           'description: win7 test\n'
           'tags: T1087 / T1069\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 #'ve created a new "
           'process\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ * \\ "
           "net.exe'\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Tokenpromotiontype: '
           'TokenElevationTypeFull (2)\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 #'ve created a new "
           'process\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ * \\ "
           "net1.exe'\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Tokenpromotiontype: '
           'TokenElevationTypeFull (2)\n'
           '\xa0\xa0\xa0\xa0selection3:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4656 # has been requested '
           'to handle objects\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ObjectServer: 'Security Account "
           "Manager' # Object> Object Server\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Objecttype: 'SAM_DOMAIN' # Object> "
           'Object Type\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processname: 'C: \\ Windows \\ "
           "System32 \\ lsass.exe' # process> process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Access: 'CreateUser'\n"
           '\xa0\xa0\xa0\xa0selection4:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4728 # has enabled global '
           'security group to add a member.\n'
           '\xa0\xa0\xa0\xa0selection5:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4720 # user account has '
           'been created.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0SecurityID: '*' # new account> "
           'Security ID\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Accountname: '*' # new account> "
           'account name\n'
           '\xa0\xa0\xa0\xa0selection6:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4722 #-enabled user '
           'accounts.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Security ID: '*' # target account> "
           'Security ID\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Accountname: '*' # target account> "
           'account name\n'
           '\xa0\xa0\xa0\xa0selection7:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4738 # Changed user '
           'account.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Security ID: '*' # target account> "
           'Security ID\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Accountname: '*' # target account> "
           'account name\n'
           '\xa0\xa0\xa0\xa0timeframe: last 20s\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Account Manipulation': {'atomic_tests': [{'description': 'Manipulate '
                                                                                   'Admin '
                                                                                   'Account '
                                                                                   'Name\n',
                                                                    'executor': {'command': '$x '
                                                                                            '= '
                                                                                            'Get-Random '
                                                                                            '-Minimum '
                                                                                            '2 '
                                                                                            '-Maximum '
                                                                                            '9999\n'
                                                                                            '$y '
                                                                                            '= '
                                                                                            'Get-Random '
                                                                                            '-Minimum '
                                                                                            '2 '
                                                                                            '-Maximum '
                                                                                            '9999\n'
                                                                                            '$z '
                                                                                            '= '
                                                                                            'Get-Random '
                                                                                            '-Minimum '
                                                                                            '2 '
                                                                                            '-Maximum '
                                                                                            '9999\n'
                                                                                            '$w '
                                                                                            '= '
                                                                                            'Get-Random '
                                                                                            '-Minimum '
                                                                                            '2 '
                                                                                            '-Maximum '
                                                                                            '9999\n'
                                                                                            'Write-Host '
                                                                                            'HaHaHa_$x$y$z$w\n'
                                                                                            '\n'
                                                                                            '$hostname '
                                                                                            '= '
                                                                                            '(Get-CIMInstance '
                                                                                            'CIM_ComputerSystem).Name\n'
                                                                                            '\n'
                                                                                            '$fmm '
                                                                                            '= '
                                                                                            'Get-CimInstance '
                                                                                            '-ClassName '
                                                                                            'win32_group '
                                                                                            '-Filter '
                                                                                            '"name '
                                                                                            '= '
                                                                                            '\'Administrators\'" '
                                                                                            '| '
                                                                                            'Get-CimAssociatedInstance '
                                                                                            '-Association '
                                                                                            'win32_groupuser '
                                                                                            '| '
                                                                                            'Select '
                                                                                            'Name\n'
                                                                                            '\n'
                                                                                            'foreach($member '
                                                                                            'in '
                                                                                            '$fmm) '
                                                                                            '{\n'
                                                                                            '    '
                                                                                            'if($member '
                                                                                            '-like '
                                                                                            '"*Administrator*") '
                                                                                            '{\n'
                                                                                            '        '
                                                                                            'Rename-LocalUser '
                                                                                            '-Name '
                                                                                            '$member.Name '
                                                                                            '-NewName '
                                                                                            '"HaHaHa_$x$y$z$w"\n'
                                                                                            '        '
                                                                                            'Write-Host '
                                                                                            '"Successfully '
                                                                                            'Renamed '
                                                                                            'Administrator '
                                                                                            'Account '
                                                                                            'on" '
                                                                                            '$hostname\n'
                                                                                            '        '
                                                                                            '}\n'
                                                                                            '    '
                                                                                            '}\n',
                                                                                 'elevation_required': True,
                                                                                 'name': 'powershell'},
                                                                    'name': 'Admin '
                                                                            'Account '
                                                                            'Manipulate',
                                                                    'supported_platforms': ['windows']}],
                                                  'attack_technique': 'T1098',
                                                  'display_name': 'Account '
                                                                  'Manipulation'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1098',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/honeyhash":  '
                                                                                 '["T1098"],',
                                            'Empire Module': 'powershell/management/honeyhash',
                                            'Technique': 'Account '
                                                         'Manipulation'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1098',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/set_ad_object":  '
                                                                                 '["T1098"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/set_ad_object',
                                            'Technique': 'Account '
                                                         'Manipulation'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)

* [Persistence](../tactics/Persistence.md)
    

# Mitigations

None

# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

* [APT3](../actors/APT3.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
