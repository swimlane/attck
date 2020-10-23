
# Account Manipulation

## Description

### MITRE Description

> Adversaries may manipulate accounts to maintain access to victim systems. Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials. In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows', 'Office 365', 'Azure', 'GCP', 'Azure AD', 'AWS', 'Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1098

## Potential Commands

```
$x = Get-Random -Minimum 2 -Maximum 99
$y = Get-Random -Minimum 2 -Maximum 99
$z = Get-Random -Minimum 2 -Maximum 99
$w = Get-Random -Minimum 2 -Maximum 99

Import-Module ActiveDirectory
$account = "#{account_prefix}-$x$y$z"
New-ADUser -Name $account -GivenName "Test" -DisplayName $account -SamAccountName $account -Surname $account -Enabled:$False #{create_args}
Add-ADGroupMember "Domain Admins" $account
$x = Get-Random -Minimum 2 -Maximum 99
$y = Get-Random -Minimum 2 -Maximum 99
$z = Get-Random -Minimum 2 -Maximum 99
$w = Get-Random -Minimum 2 -Maximum 99

Import-Module ActiveDirectory
$account = "#{account_prefix}-$x$y$z"
New-ADUser -Name $account -GivenName "Test" -DisplayName $account -SamAccountName $account -Surname $account -Enabled:$False 
Add-ADGroupMember "#{group}" $account
$x = Get-Random -Minimum 2 -Maximum 9999
$y = Get-Random -Minimum 2 -Maximum 9999
$z = Get-Random -Minimum 2 -Maximum 9999
$w = Get-Random -Minimum 2 -Maximum 9999
Write-Host HaHa_$x$y$z

$fmm = Get-LocalGroupMember -Group Administrators |?{ $_.ObjectClass -match "User" -and $_.PrincipalSource -match "Local"} | Select Name

foreach($member in $fmm) {
    if($member -like "*Administrator*") {
        $account = $member.Name -replace ".+\\\","" # strip computername\
        $originalDescription = (Get-LocalUser -Name $account).Description
        Set-LocalUser -Name $account -Description "atr:$account;$originalDescription".Substring(0,48) # Keep original name in description
        Rename-LocalUser -Name $account -NewName "HaHa_$x$y$z" # Required due to length limitation
        Write-Host "Successfully Renamed $account Account on " $Env:COMPUTERNAME
        }
    }
$x = Get-Random -Minimum 2 -Maximum 99
$y = Get-Random -Minimum 2 -Maximum 99
$z = Get-Random -Minimum 2 -Maximum 99
$w = Get-Random -Minimum 2 -Maximum 99

Import-Module ActiveDirectory
$account = "atr--$x$y$z"
New-ADUser -Name $account -GivenName "Test" -DisplayName $account -SamAccountName $account -Surname $account -Enabled:$False #{create_args}
Add-ADGroupMember "#{group}" $account
powershell/management/honeyhash
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
             'Write-Host HaHa_$x$y$z\n'
             '\n'
             '$fmm = Get-LocalGroupMember -Group Administrators |?{ '
             '$_.ObjectClass -match "User" -and $_.PrincipalSource -match '
             '"Local"} | Select Name\n'
             '\n'
             'foreach($member in $fmm) {\n'
             '    if($member -like "*Administrator*") {\n'
             '        $account = $member.Name -replace ".+\\\\\\","" # strip '
             'computername\\\n'
             '        $originalDescription = (Get-LocalUser -Name '
             '$account).Description\n'
             '        Set-LocalUser -Name $account -Description '
             '"atr:$account;$originalDescription".Substring(0,48) # Keep '
             'original name in description\n'
             '        Rename-LocalUser -Name $account -NewName "HaHa_$x$y$z" # '
             'Required due to length limitation\n'
             '        Write-Host "Successfully Renamed $account Account on " '
             '$Env:COMPUTERNAME\n'
             '        }\n'
             '    }\n',
  'name': None,
  'source': 'atomics/T1098/T1098.yaml'},
 {'command': '$x = Get-Random -Minimum 2 -Maximum 99\n'
             '$y = Get-Random -Minimum 2 -Maximum 99\n'
             '$z = Get-Random -Minimum 2 -Maximum 99\n'
             '$w = Get-Random -Minimum 2 -Maximum 99\n'
             '\n'
             'Import-Module ActiveDirectory\n'
             '$account = "atr--$x$y$z"\n'
             'New-ADUser -Name $account -GivenName "Test" -DisplayName '
             '$account -SamAccountName $account -Surname $account '
             '-Enabled:$False #{create_args}\n'
             'Add-ADGroupMember "#{group}" $account\n',
  'name': None,
  'source': 'atomics/T1098/T1098.yaml'},
 {'command': '$x = Get-Random -Minimum 2 -Maximum 99\n'
             '$y = Get-Random -Minimum 2 -Maximum 99\n'
             '$z = Get-Random -Minimum 2 -Maximum 99\n'
             '$w = Get-Random -Minimum 2 -Maximum 99\n'
             '\n'
             'Import-Module ActiveDirectory\n'
             '$account = "#{account_prefix}-$x$y$z"\n'
             'New-ADUser -Name $account -GivenName "Test" -DisplayName '
             '$account -SamAccountName $account -Surname $account '
             '-Enabled:$False #{create_args}\n'
             'Add-ADGroupMember "Domain Admins" $account\n',
  'name': None,
  'source': 'atomics/T1098/T1098.yaml'},
 {'command': '$x = Get-Random -Minimum 2 -Maximum 99\n'
             '$y = Get-Random -Minimum 2 -Maximum 99\n'
             '$z = Get-Random -Minimum 2 -Maximum 99\n'
             '$w = Get-Random -Minimum 2 -Maximum 99\n'
             '\n'
             'Import-Module ActiveDirectory\n'
             '$account = "#{account_prefix}-$x$y$z"\n'
             'New-ADUser -Name $account -GivenName "Test" -DisplayName '
             '$account -SamAccountName $account -Surname $account '
             '-Enabled:$False \n'
             'Add-ADGroupMember "#{group}" $account\n',
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
[{'data_source': {'author': '@neu5ron',
                  'description': 'Detects scenarios where one can control '
                                 'another users or computers account without '
                                 'having to use their credentials.',
                  'detection': {'condition': '(selection1 and not 1 of '
                                             'filter*) or selection2 or '
                                             'selection3 or selection4',
                                'filter1': {'AllowedToDelegateTo': None},
                                'filter2': {'AllowedToDelegateTo': '-'},
                                'selection1': {'EventID': 4738},
                                'selection2': {'AttributeLDAPDisplayName': 'msDS-AllowedToDelegateTo',
                                               'EventID': 5136},
                                'selection3': {'AttributeLDAPDisplayName': 'servicePrincipalName',
                                               'EventID': 5136,
                                               'ObjectClass': 'user'},
                                'selection4': {'AttributeLDAPDisplayName': 'msDS-AllowedToActOnBehalfOfOtherIdentity',
                                               'EventID': 5136}},
                  'falsepositives': ['Unknown'],
                  'id': '300bac00-e041-4ee2-9c36-e262656a6ecc',
                  'level': 'high',
                  'logsource': {'definition1': 'Requirements: Audit Policy : '
                                               'Account Management > Audit '
                                               'User Account Management, Group '
                                               'Policy : Computer '
                                               'Configuration\\Windows '
                                               'Settings\\Security '
                                               'Settings\\Advanced Audit '
                                               'Policy Configuration\\Audit '
                                               'Policies\\Account '
                                               'Management\\Audit User Account '
                                               'Management',
                                'definition2': 'Requirements: Audit Policy : '
                                               'DS Access > Audit Directory '
                                               'Service Changes, Group Policy '
                                               ': Computer '
                                               'Configuration\\Windows '
                                               'Settings\\Security '
                                               'Settings\\Advanced Audit '
                                               'Policy Configuration\\Audit '
                                               'Policies\\DS Access\\Audit '
                                               'Directory Service Changes',
                                'product': 'windows',
                                'service': 'security'},
                  'references': ['https://msdn.microsoft.com/en-us/library/cc220234.aspx',
                                 'https://adsecurity.org/?p=3466',
                                 'https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/'],
                  'tags': ['attack.t1098',
                           'attack.credential_access',
                           'attack.persistence'],
                  'title': 'Active Directory User Backdoors'}},
 {'data_source': {'author': 'Thomas Patzke',
                  'description': 'The Directory Service Restore Mode (DSRM) '
                                 'account is a local administrator account on '
                                 'Domain Controllers. Attackers may change the '
                                 'password to gain persistence.',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 4794}},
                  'falsepositives': ['Initial installation of a domain '
                                     'controller'],
                  'id': '53ad8e36-f573-46bf-97e4-15ba5bf4bb51',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'references': ['https://adsecurity.org/?p=1714'],
                  'status': 'stable',
                  'tags': ['attack.persistence',
                           'attack.privilege_escalation',
                           'attack.t1098'],
                  'title': 'Password Change on Directory Service Restore Mode '
                           '(DSRM) Account'}},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['Windows event logs']},
 {'data_source': ['Packet capture']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['Windows event logs']},
 {'data_source': ['Packet capture']},
 {'data_source': ['API monitoring']}]
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
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection1:\n'
           "        EventID: 4688 #'ve created a new process\n"
           "        Newprocessname: 'C: \\ * \\ net.exe'\n"
           '        Tokenpromotiontype: TokenElevationTypeFull (2)\n'
           '    selection2:\n'
           "        EventID: 4688 #'ve created a new process\n"
           "        Newprocessname: 'C: \\ * \\ net1.exe'\n"
           '        Tokenpromotiontype: TokenElevationTypeFull (2)\n'
           '    selection3:\n'
           '        EventID: 4656 # has been requested to handle objects\n'
           "        ObjectServer: 'Security Account Manager' # Object> Object "
           'Server\n'
           "        Objecttype: 'SAM_DOMAIN' # Object> Object Type\n"
           "        Processname: 'C: \\ Windows \\ System32 \\ lsass.exe' # "
           'process> process name\n'
           "        Access: 'CreateUser'\n"
           '    selection4:\n'
           '        EventID: 4728 # has enabled global security group to add a '
           'member.\n'
           '    selection5:\n'
           '        EventID: 4720 # user account has been created.\n'
           "        SecurityID: '*' # new account> Security ID\n"
           "        Accountname: '*' # new account> account name\n"
           '    selection6:\n'
           '        EventID: 4722 #-enabled user accounts.\n'
           "        Security ID: '*' # target account> Security ID\n"
           "        Accountname: '*' # target account> account name\n"
           '    selection7:\n'
           '        EventID: 4738 # Changed user account.\n'
           "        Security ID: '*' # target account> Security ID\n"
           "        Accountname: '*' # target account> account name\n"
           '    timeframe: last 20s\n'
           '    condition: all of them\n'
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
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection1:\n'
           '        EventID: 5136 # directory service object was modified. '
           'AdminSDHolder change, as a general authority to maintain, because '
           'the situation changes very little\n'
           '    selection2:\n'
           '        EventID: 4780 #ACL provided on a member of the '
           'Administrators group account\n'
           '    timeframe: last 1h # default wait 60 minutes to take effect, '
           'the specific reasons described below with reference may SDPROP\n'
           '    condition: all of them\n'
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
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection1:\n'
           "        EventID: 4688 #'ve created a new process\n"
           "        Newprocessname: 'C: \\ * \\ net.exe'\n"
           '        Tokenpromotiontype: TokenElevationTypeFull (2)\n'
           '    selection2:\n'
           "        EventID: 4688 #'ve created a new process\n"
           "        Newprocessname: 'C: \\ * \\ net1.exe'\n"
           '        Tokenpromotiontype: TokenElevationTypeFull (2)\n'
           '    selection3:\n'
           '        EventID: 4656 # has been requested to handle objects\n'
           "        ObjectServer: 'Security Account Manager' # Object> Object "
           'Server\n'
           "        Objecttype: 'SAM_DOMAIN' # Object> Object Type\n"
           "        Processname: 'C: \\ Windows \\ System32 \\ lsass.exe' # "
           'process> process name\n'
           "        Access: 'CreateUser'\n"
           '    selection4:\n'
           '        EventID: 4728 # has enabled global security group to add a '
           'member.\n'
           '    selection5:\n'
           '        EventID: 4720 # user account has been created.\n'
           "        SecurityID: '*' # new account> Security ID\n"
           "        Accountname: '*' # new account> account name\n"
           '    selection6:\n'
           '        EventID: 4722 #-enabled user accounts.\n'
           "        Security ID: '*' # target account> Security ID\n"
           "        Accountname: '*' # target account> account name\n"
           '    selection7:\n'
           '        EventID: 4738 # Changed user account.\n'
           "        Security ID: '*' # target account> Security ID\n"
           "        Accountname: '*' # target account> account name\n"
           '    timeframe: last 20s\n'
           '    condition: all of them\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Account Manipulation': {'atomic_tests': [{'auto_generated_guid': '5598f7cb-cf43-455e-883a-f6008c5d46af',
                                                                    'description': 'Manipulate '
                                                                                   'Admin '
                                                                                   'Account '
                                                                                   'Name\n',
                                                                    'executor': {'cleanup_command': '$list '
                                                                                                    '= '
                                                                                                    'Get-LocalUser '
                                                                                                    '|?{$_.Description '
                                                                                                    '-like '
                                                                                                    '"atr:*"}\n'
                                                                                                    'foreach($u '
                                                                                                    'in '
                                                                                                    '$list) '
                                                                                                    '{\n'
                                                                                                    '  '
                                                                                                    '$u.Description '
                                                                                                    '-match '
                                                                                                    '"atr:(?<Name>[^;]+);(?<Description>.*)"\n'
                                                                                                    '  '
                                                                                                    'Set-LocalUser '
                                                                                                    '-Name '
                                                                                                    '$u.Name '
                                                                                                    '-Description '
                                                                                                    '$Matches.Description\n'
                                                                                                    '  '
                                                                                                    'Rename-LocalUser '
                                                                                                    '-Name '
                                                                                                    '$u.Name '
                                                                                                    '-NewName '
                                                                                                    '$Matches.Name\n'
                                                                                                    '  '
                                                                                                    'Write-Host '
                                                                                                    '"Successfully '
                                                                                                    'Reverted '
                                                                                                    'Account '
                                                                                                    '$($u.Name) '
                                                                                                    'to '
                                                                                                    '$($Matches.Name) '
                                                                                                    'on '
                                                                                                    '" '
                                                                                                    '$Env:COMPUTERNAME\n'
                                                                                                    '}\n',
                                                                                 'command': '$x '
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
                                                                                            'HaHa_$x$y$z\n'
                                                                                            '\n'
                                                                                            '$fmm '
                                                                                            '= '
                                                                                            'Get-LocalGroupMember '
                                                                                            '-Group '
                                                                                            'Administrators '
                                                                                            '|?{ '
                                                                                            '$_.ObjectClass '
                                                                                            '-match '
                                                                                            '"User" '
                                                                                            '-and '
                                                                                            '$_.PrincipalSource '
                                                                                            '-match '
                                                                                            '"Local"} '
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
                                                                                            '$account '
                                                                                            '= '
                                                                                            '$member.Name '
                                                                                            '-replace '
                                                                                            '".+\\\\\\","" '
                                                                                            '# '
                                                                                            'strip '
                                                                                            'computername\\\n'
                                                                                            '        '
                                                                                            '$originalDescription '
                                                                                            '= '
                                                                                            '(Get-LocalUser '
                                                                                            '-Name '
                                                                                            '$account).Description\n'
                                                                                            '        '
                                                                                            'Set-LocalUser '
                                                                                            '-Name '
                                                                                            '$account '
                                                                                            '-Description '
                                                                                            '"atr:$account;$originalDescription".Substring(0,48) '
                                                                                            '# '
                                                                                            'Keep '
                                                                                            'original '
                                                                                            'name '
                                                                                            'in '
                                                                                            'description\n'
                                                                                            '        '
                                                                                            'Rename-LocalUser '
                                                                                            '-Name '
                                                                                            '$account '
                                                                                            '-NewName '
                                                                                            '"HaHa_$x$y$z" '
                                                                                            '# '
                                                                                            'Required '
                                                                                            'due '
                                                                                            'to '
                                                                                            'length '
                                                                                            'limitation\n'
                                                                                            '        '
                                                                                            'Write-Host '
                                                                                            '"Successfully '
                                                                                            'Renamed '
                                                                                            '$account '
                                                                                            'Account '
                                                                                            'on '
                                                                                            '" '
                                                                                            '$Env:COMPUTERNAME\n'
                                                                                            '        '
                                                                                            '}\n'
                                                                                            '    '
                                                                                            '}\n',
                                                                                 'elevation_required': True,
                                                                                 'name': 'powershell'},
                                                                    'name': 'Admin '
                                                                            'Account '
                                                                            'Manipulate',
                                                                    'supported_platforms': ['windows']},
                                                                   {'auto_generated_guid': 'a55a22e9-a3d3-42ce-bd48-2653adb8f7a9',
                                                                    'dependencies': [{'description': 'PS '
                                                                                                     'Module '
                                                                                                     'ActiveDirectory\n',
                                                                                      'get_prereq_command': 'if((Get-CimInstance '
                                                                                                            '-ClassName '
                                                                                                            'Win32_OperatingSystem).ProductType '
                                                                                                            '-eq '
                                                                                                            '1) '
                                                                                                            '{\n'
                                                                                                            '  '
                                                                                                            'Add-WindowsCapability '
                                                                                                            '-Name '
                                                                                                            '(Get-WindowsCapability '
                                                                                                            '-Name '
                                                                                                            'RSAT.ActiveDirectory.DS* '
                                                                                                            '-Online).Name '
                                                                                                            '-Online\n'
                                                                                                            '} '
                                                                                                            'else '
                                                                                                            '{\n'
                                                                                                            '  '
                                                                                                            'Install-WindowsFeature '
                                                                                                            'RSAT-AD-PowerShell\n'
                                                                                                            '}\n',
                                                                                      'prereq_command': 'Try '
                                                                                                        '{\n'
                                                                                                        '    '
                                                                                                        'Import-Module '
                                                                                                        'ActiveDirectory '
                                                                                                        '-ErrorAction '
                                                                                                        'Stop '
                                                                                                        '| '
                                                                                                        'Out-Null\n'
                                                                                                        '    '
                                                                                                        'exit '
                                                                                                        '0\n'
                                                                                                        '} \n'
                                                                                                        'Catch '
                                                                                                        '{\n'
                                                                                                        '    '
                                                                                                        'exit '
                                                                                                        '1\n'
                                                                                                        '}\n'}],
                                                                    'description': 'Create '
                                                                                   'a '
                                                                                   'random '
                                                                                   'atr-nnnnnnnn '
                                                                                   'account '
                                                                                   'and '
                                                                                   'add '
                                                                                   'it '
                                                                                   'to '
                                                                                   'a '
                                                                                   'domain '
                                                                                   'group '
                                                                                   '(by '
                                                                                   'default, '
                                                                                   'Domain '
                                                                                   'Admins). \n'
                                                                                   '\n'
                                                                                   'The '
                                                                                   'quickest '
                                                                                   'way '
                                                                                   'to '
                                                                                   'run '
                                                                                   'it '
                                                                                   'is '
                                                                                   'against '
                                                                                   'a '
                                                                                   'domain '
                                                                                   'controller, '
                                                                                   'using '
                                                                                   '`-Session` '
                                                                                   'of '
                                                                                   '`Invoke-AtomicTest`. '
                                                                                   'Alternatively,\n'
                                                                                   'you '
                                                                                   'need '
                                                                                   'to '
                                                                                   'install '
                                                                                   'PS '
                                                                                   'Module '
                                                                                   'ActiveDirectory '
                                                                                   '(in '
                                                                                   'prereqs) '
                                                                                   'and '
                                                                                   'run '
                                                                                   'the '
                                                                                   'script '
                                                                                   'with '
                                                                                   'appropriare '
                                                                                   'AD '
                                                                                   'privileges '
                                                                                   'to \n'
                                                                                   'create '
                                                                                   'the '
                                                                                   'user '
                                                                                   'and '
                                                                                   'alter '
                                                                                   'the '
                                                                                   'group. '
                                                                                   'Automatic '
                                                                                   'installation '
                                                                                   'of '
                                                                                   'the '
                                                                                   'dependency '
                                                                                   'requires '
                                                                                   'an '
                                                                                   'elevated '
                                                                                   'session, \n'
                                                                                   'and '
                                                                                   'is '
                                                                                   'unlikely '
                                                                                   'to '
                                                                                   'work '
                                                                                   'with '
                                                                                   'Powershell '
                                                                                   'Core '
                                                                                   '(untested).\n'
                                                                                   '\n'
                                                                                   'If '
                                                                                   'you '
                                                                                   'consider '
                                                                                   'running '
                                                                                   'this '
                                                                                   'test '
                                                                                   'against '
                                                                                   'a '
                                                                                   'production '
                                                                                   'Active '
                                                                                   'Directory, '
                                                                                   'the '
                                                                                   'good '
                                                                                   'practise '
                                                                                   'is '
                                                                                   'to '
                                                                                   'create '
                                                                                   'a '
                                                                                   'dedicated\n'
                                                                                   'service '
                                                                                   'account '
                                                                                   'whose '
                                                                                   'delegation '
                                                                                   'is '
                                                                                   'given '
                                                                                   'onto '
                                                                                   'a '
                                                                                   'dedicated '
                                                                                   'OU '
                                                                                   'for '
                                                                                   'user '
                                                                                   'creation '
                                                                                   'and '
                                                                                   'deletion, '
                                                                                   'as '
                                                                                   'well '
                                                                                   'as '
                                                                                   'delegated\n'
                                                                                   'as '
                                                                                   'group '
                                                                                   'manager '
                                                                                   'of '
                                                                                   'the '
                                                                                   'target '
                                                                                   'group.\n'
                                                                                   '\n'
                                                                                   'Example: '
                                                                                   '`Invoke-AtomicTest '
                                                                                   '-Session '
                                                                                   '$session '
                                                                                   "'T1098' "
                                                                                   '-TestNames '
                                                                                   '"Domain '
                                                                                   'Account '
                                                                                   'and '
                                                                                   'Group '
                                                                                   'Manipulate" '
                                                                                   '-InputArgs '
                                                                                   '@{"group" '
                                                                                   '= '
                                                                                   '"DNSAdmins" '
                                                                                   '}`\n',
                                                                    'executor': {'cleanup_command': 'Get-ADUser '
                                                                                                    '-LDAPFilter '
                                                                                                    '"(&(samaccountname=#{account_prefix}-*)(givenName=Test))" '
                                                                                                    '| '
                                                                                                    'Remove-ADUser '
                                                                                                    '-Confirm:$False\n',
                                                                                 'command': '$x '
                                                                                            '= '
                                                                                            'Get-Random '
                                                                                            '-Minimum '
                                                                                            '2 '
                                                                                            '-Maximum '
                                                                                            '99\n'
                                                                                            '$y '
                                                                                            '= '
                                                                                            'Get-Random '
                                                                                            '-Minimum '
                                                                                            '2 '
                                                                                            '-Maximum '
                                                                                            '99\n'
                                                                                            '$z '
                                                                                            '= '
                                                                                            'Get-Random '
                                                                                            '-Minimum '
                                                                                            '2 '
                                                                                            '-Maximum '
                                                                                            '99\n'
                                                                                            '$w '
                                                                                            '= '
                                                                                            'Get-Random '
                                                                                            '-Minimum '
                                                                                            '2 '
                                                                                            '-Maximum '
                                                                                            '99\n'
                                                                                            '\n'
                                                                                            'Import-Module '
                                                                                            'ActiveDirectory\n'
                                                                                            '$account '
                                                                                            '= '
                                                                                            '"#{account_prefix}-$x$y$z"\n'
                                                                                            'New-ADUser '
                                                                                            '-Name '
                                                                                            '$account '
                                                                                            '-GivenName '
                                                                                            '"Test" '
                                                                                            '-DisplayName '
                                                                                            '$account '
                                                                                            '-SamAccountName '
                                                                                            '$account '
                                                                                            '-Surname '
                                                                                            '$account '
                                                                                            '-Enabled:$False '
                                                                                            '#{create_args}\n'
                                                                                            'Add-ADGroupMember '
                                                                                            '"#{group}" '
                                                                                            '$account\n',
                                                                                 'name': 'powershell'},
                                                                    'input_arguments': {'account_prefix': {'default': 'atr-',
                                                                                                           'description': 'Prefix '
                                                                                                                          'string '
                                                                                                                          'of '
                                                                                                                          'the '
                                                                                                                          'random '
                                                                                                                          'username '
                                                                                                                          '(by '
                                                                                                                          'default, '
                                                                                                                          'atr-). '
                                                                                                                          'Because '
                                                                                                                          'the '
                                                                                                                          'cleanup '
                                                                                                                          'deletes '
                                                                                                                          'such '
                                                                                                                          'account '
                                                                                                                          'based '
                                                                                                                          'on\n'
                                                                                                                          'a '
                                                                                                                          'match '
                                                                                                                          '`(&(samaccountname=#{account_prefix}-*)(givenName=Test))`, '
                                                                                                                          'if '
                                                                                                                          'you '
                                                                                                                          'are '
                                                                                                                          'to '
                                                                                                                          'change '
                                                                                                                          'it, '
                                                                                                                          'be '
                                                                                                                          'careful.\n',
                                                                                                           'type': 'String'},
                                                                                        'create_args': {'default': '',
                                                                                                        'description': 'Additional '
                                                                                                                       'string '
                                                                                                                       'appended '
                                                                                                                       'to '
                                                                                                                       'New-ADUser '
                                                                                                                       'call',
                                                                                                        'type': 'String'},
                                                                                        'group': {'default': 'Domain '
                                                                                                             'Admins',
                                                                                                  'description': 'Name '
                                                                                                                 'of '
                                                                                                                 'the '
                                                                                                                 'group '
                                                                                                                 'to '
                                                                                                                 'alter',
                                                                                                  'type': 'String'}},
                                                                    'name': 'Domain '
                                                                            'Account '
                                                                            'and '
                                                                            'Group '
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


* [Persistence](../tactics/Persistence.md)


# Mitigations


* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)

* [Network Segmentation](../mitigations/Network-Segmentation.md)
    
* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    

# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

* [APT3](../actors/APT3.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
