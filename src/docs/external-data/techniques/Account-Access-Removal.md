
# Account Access Removal

## Description

### MITRE Description

> Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts.

Adversaries may also subsequently log off and/or reboot boxes to set malicious changes into place.(Citation: CarbonBlack LockerGoga 2019)(Citation: Unit42 LockerGoga 2019)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'root', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1531

## Potential Commands

```
net user AtomicAdministrator #{new_user_password} /add
net.exe user AtomicAdministrator #{new_password}

net user #{user_account} User2ChangePW! /add
net.exe user #{user_account} #{new_password}

net user #{user_account} #{new_user_password} /add
net.exe user #{user_account} HuHuHUHoHo283283@dJD

net user #{user_account} User2DeletePW! /add
net.exe user #{user_account} /delete

net user AtomicUser #{new_user_password} /add
net.exe user AtomicUser /delete

$PWord = ConvertTo-SecureString -String #{super_pass} -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList domain\super_user, $PWord
if((Get-ADUser #{remove_user} -Properties memberof).memberof -like "CN=Domain Admins*"){
  Remove-ADGroupMember -Identity "Domain Admins" -Members #{remove_user} -Credential $Credential -Confirm:$False
} else{
    write-host "Error - Make sure #{remove_user} is in the domain admins group" -foregroundcolor Red
}

$PWord = ConvertTo-SecureString -String password -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList #{super_user}, $PWord
if((Get-ADUser #{remove_user} -Properties memberof).memberof -like "CN=Domain Admins*"){
  Remove-ADGroupMember -Identity "Domain Admins" -Members #{remove_user} -Credential $Credential -Confirm:$False
} else{
    write-host "Error - Make sure #{remove_user} is in the domain admins group" -foregroundcolor Red
}

$PWord = ConvertTo-SecureString -String #{super_pass} -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList #{super_user}, $PWord
if((Get-ADUser remove_user -Properties memberof).memberof -like "CN=Domain Admins*"){
  Remove-ADGroupMember -Identity "Domain Admins" -Members remove_user -Credential $Credential -Confirm:$False
} else{
    write-host "Error - Make sure remove_user is in the domain admins group" -foregroundcolor Red
}

```

## Commands Dataset

```
[{'command': 'net user AtomicAdministrator #{new_user_password} /add\n'
             'net.exe user AtomicAdministrator #{new_password}\n',
  'name': None,
  'source': 'atomics/T1531/T1531.yaml'},
 {'command': 'net user #{user_account} User2ChangePW! /add\n'
             'net.exe user #{user_account} #{new_password}\n',
  'name': None,
  'source': 'atomics/T1531/T1531.yaml'},
 {'command': 'net user #{user_account} #{new_user_password} /add\n'
             'net.exe user #{user_account} HuHuHUHoHo283283@dJD\n',
  'name': None,
  'source': 'atomics/T1531/T1531.yaml'},
 {'command': 'net user #{user_account} User2DeletePW! /add\n'
             'net.exe user #{user_account} /delete\n',
  'name': None,
  'source': 'atomics/T1531/T1531.yaml'},
 {'command': 'net user AtomicUser #{new_user_password} /add\n'
             'net.exe user AtomicUser /delete\n',
  'name': None,
  'source': 'atomics/T1531/T1531.yaml'},
 {'command': '$PWord = ConvertTo-SecureString -String #{super_pass} '
             '-AsPlainText -Force\n'
             '$Credential = New-Object -TypeName '
             'System.Management.Automation.PSCredential -ArgumentList '
             'domain\\super_user, $PWord\n'
             'if((Get-ADUser #{remove_user} -Properties memberof).memberof '
             '-like "CN=Domain Admins*"){\n'
             '  Remove-ADGroupMember -Identity "Domain Admins" -Members '
             '#{remove_user} -Credential $Credential -Confirm:$False\n'
             '} else{\n'
             '    write-host "Error - Make sure #{remove_user} is in the '
             'domain admins group" -foregroundcolor Red\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1531/T1531.yaml'},
 {'command': '$PWord = ConvertTo-SecureString -String password -AsPlainText '
             '-Force\n'
             '$Credential = New-Object -TypeName '
             'System.Management.Automation.PSCredential -ArgumentList '
             '#{super_user}, $PWord\n'
             'if((Get-ADUser #{remove_user} -Properties memberof).memberof '
             '-like "CN=Domain Admins*"){\n'
             '  Remove-ADGroupMember -Identity "Domain Admins" -Members '
             '#{remove_user} -Credential $Credential -Confirm:$False\n'
             '} else{\n'
             '    write-host "Error - Make sure #{remove_user} is in the '
             'domain admins group" -foregroundcolor Red\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1531/T1531.yaml'},
 {'command': '$PWord = ConvertTo-SecureString -String #{super_pass} '
             '-AsPlainText -Force\n'
             '$Credential = New-Object -TypeName '
             'System.Management.Automation.PSCredential -ArgumentList '
             '#{super_user}, $PWord\n'
             'if((Get-ADUser remove_user -Properties memberof).memberof -like '
             '"CN=Domain Admins*"){\n'
             '  Remove-ADGroupMember -Identity "Domain Admins" -Members '
             'remove_user -Credential $Credential -Confirm:$False\n'
             '} else{\n'
             '    write-host "Error - Make sure remove_user is in the domain '
             'admins group" -foregroundcolor Red\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1531/T1531.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Account Access Removal': {'atomic_tests': [{'auto_generated_guid': '1b99ef28-f83c-4ec5-8a08-1a56263a5bb2',
                                                                      'description': 'Changes '
                                                                                     'the '
                                                                                     'user '
                                                                                     'password '
                                                                                     'to '
                                                                                     'hinder '
                                                                                     'access '
                                                                                     'attempts. '
                                                                                     'Seen '
                                                                                     'in '
                                                                                     'use '
                                                                                     'by '
                                                                                     'LockerGoga. '
                                                                                     'Upon '
                                                                                     'execution, '
                                                                                     'log '
                                                                                     'into '
                                                                                     'the '
                                                                                     'user '
                                                                                     'account '
                                                                                     '"AtomicAdministrator" '
                                                                                     'with\n'
                                                                                     'the '
                                                                                     'password '
                                                                                     '"HuHuHUHoHo283283".\n',
                                                                      'executor': {'cleanup_command': 'net.exe '
                                                                                                      'user '
                                                                                                      '#{user_account} '
                                                                                                      '/delete '
                                                                                                      '>nul '
                                                                                                      '2>&1\n',
                                                                                   'command': 'net '
                                                                                              'user '
                                                                                              '#{user_account} '
                                                                                              '#{new_user_password} '
                                                                                              '/add\n'
                                                                                              'net.exe '
                                                                                              'user '
                                                                                              '#{user_account} '
                                                                                              '#{new_password}\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'command_prompt'},
                                                                      'input_arguments': {'new_password': {'default': 'HuHuHUHoHo283283@dJD',
                                                                                                           'description': 'New '
                                                                                                                          'password '
                                                                                                                          'for '
                                                                                                                          'the '
                                                                                                                          'specified '
                                                                                                                          'account.',
                                                                                                           'type': 'string'},
                                                                                          'new_user_password': {'default': 'User2ChangePW!',
                                                                                                                'description': 'Password '
                                                                                                                               'to '
                                                                                                                               'use '
                                                                                                                               'if '
                                                                                                                               'user '
                                                                                                                               'account '
                                                                                                                               'must '
                                                                                                                               'be '
                                                                                                                               'created '
                                                                                                                               'first',
                                                                                                                'type': 'string'},
                                                                                          'user_account': {'default': 'AtomicAdministrator',
                                                                                                           'description': 'User '
                                                                                                                          'account '
                                                                                                                          'whose '
                                                                                                                          'password '
                                                                                                                          'will '
                                                                                                                          'be '
                                                                                                                          'changed.',
                                                                                                           'type': 'string'}},
                                                                      'name': 'Change '
                                                                              'User '
                                                                              'Password '
                                                                              '- '
                                                                              'Windows',
                                                                      'supported_platforms': ['windows']},
                                                                     {'auto_generated_guid': 'f21a1d7d-a62f-442a-8c3a-2440d43b19e5',
                                                                      'description': 'Deletes '
                                                                                     'a '
                                                                                     'user '
                                                                                     'account '
                                                                                     'to '
                                                                                     'prevent '
                                                                                     'access. '
                                                                                     'Upon '
                                                                                     'execution, '
                                                                                     'run '
                                                                                     'the '
                                                                                     'command '
                                                                                     '"net '
                                                                                     'user" '
                                                                                     'to '
                                                                                     'verify '
                                                                                     'that '
                                                                                     'the '
                                                                                     'new '
                                                                                     '"AtomicUser" '
                                                                                     'account '
                                                                                     'was '
                                                                                     'deleted.\n',
                                                                      'executor': {'command': 'net '
                                                                                              'user '
                                                                                              '#{user_account} '
                                                                                              '#{new_user_password} '
                                                                                              '/add\n'
                                                                                              'net.exe '
                                                                                              'user '
                                                                                              '#{user_account} '
                                                                                              '/delete\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'command_prompt'},
                                                                      'input_arguments': {'new_user_password': {'default': 'User2DeletePW!',
                                                                                                                'description': 'Password '
                                                                                                                               'to '
                                                                                                                               'use '
                                                                                                                               'if '
                                                                                                                               'user '
                                                                                                                               'account '
                                                                                                                               'must '
                                                                                                                               'be '
                                                                                                                               'created '
                                                                                                                               'first',
                                                                                                                'type': 'string'},
                                                                                          'user_account': {'default': 'AtomicUser',
                                                                                                           'description': 'User '
                                                                                                                          'account '
                                                                                                                          'to '
                                                                                                                          'be '
                                                                                                                          'deleted.',
                                                                                                           'type': 'string'}},
                                                                      'name': 'Delete '
                                                                              'User '
                                                                              '- '
                                                                              'Windows',
                                                                      'supported_platforms': ['windows']},
                                                                     {'auto_generated_guid': '43f71395-6c37-498e-ab17-897d814a0947',
                                                                      'dependencies': [{'description': 'Requires '
                                                                                                       'the '
                                                                                                       'Active '
                                                                                                       'Directory '
                                                                                                       'module '
                                                                                                       'for '
                                                                                                       'powershell '
                                                                                                       'to '
                                                                                                       'be '
                                                                                                       'installed.\n',
                                                                                        'get_prereq_command': 'Add-WindowsCapability '
                                                                                                              '-Online '
                                                                                                              '-Name '
                                                                                                              '"Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"\n',
                                                                                        'prereq_command': 'if(Get-Module '
                                                                                                          '-ListAvailable '
                                                                                                          '-Name '
                                                                                                          'ActiveDirectory) '
                                                                                                          '{exit '
                                                                                                          '0} '
                                                                                                          'else '
                                                                                                          '{exit '
                                                                                                          '1}\n'}],
                                                                      'dependency_executor_name': 'powershell',
                                                                      'description': 'This '
                                                                                     'test '
                                                                                     'will '
                                                                                     'remove '
                                                                                     'an '
                                                                                     'account '
                                                                                     'from '
                                                                                     'the '
                                                                                     'domain '
                                                                                     'admins '
                                                                                     'group\n',
                                                                      'executor': {'command': '$PWord '
                                                                                              '= '
                                                                                              'ConvertTo-SecureString '
                                                                                              '-String '
                                                                                              '#{super_pass} '
                                                                                              '-AsPlainText '
                                                                                              '-Force\n'
                                                                                              '$Credential '
                                                                                              '= '
                                                                                              'New-Object '
                                                                                              '-TypeName '
                                                                                              'System.Management.Automation.PSCredential '
                                                                                              '-ArgumentList '
                                                                                              '#{super_user}, '
                                                                                              '$PWord\n'
                                                                                              'if((Get-ADUser '
                                                                                              '#{remove_user} '
                                                                                              '-Properties '
                                                                                              'memberof).memberof '
                                                                                              '-like '
                                                                                              '"CN=Domain '
                                                                                              'Admins*"){\n'
                                                                                              '  '
                                                                                              'Remove-ADGroupMember '
                                                                                              '-Identity '
                                                                                              '"Domain '
                                                                                              'Admins" '
                                                                                              '-Members '
                                                                                              '#{remove_user} '
                                                                                              '-Credential '
                                                                                              '$Credential '
                                                                                              '-Confirm:$False\n'
                                                                                              '} '
                                                                                              'else{\n'
                                                                                              '    '
                                                                                              'write-host '
                                                                                              '"Error '
                                                                                              '- '
                                                                                              'Make '
                                                                                              'sure '
                                                                                              '#{remove_user} '
                                                                                              'is '
                                                                                              'in '
                                                                                              'the '
                                                                                              'domain '
                                                                                              'admins '
                                                                                              'group" '
                                                                                              '-foregroundcolor '
                                                                                              'Red\n'
                                                                                              '}\n',
                                                                                   'elevation_required': False,
                                                                                   'name': 'powershell'},
                                                                      'input_arguments': {'remove_user': {'default': 'remove_user',
                                                                                                          'description': 'Account '
                                                                                                                         'to '
                                                                                                                         'remove '
                                                                                                                         'from '
                                                                                                                         'domain '
                                                                                                                         'admins.',
                                                                                                          'type': 'string'},
                                                                                          'super_pass': {'default': 'password',
                                                                                                         'description': 'super_user '
                                                                                                                        'account '
                                                                                                                        'password.',
                                                                                                         'type': 'string'},
                                                                                          'super_user': {'default': 'domain\\super_user',
                                                                                                         'description': 'Account '
                                                                                                                        'used '
                                                                                                                        'to '
                                                                                                                        'run '
                                                                                                                        'the '
                                                                                                                        'execution '
                                                                                                                        'command '
                                                                                                                        '(must '
                                                                                                                        'include '
                                                                                                                        'domain).',
                                                                                                         'type': 'string'}},
                                                                      'name': 'Remove '
                                                                              'Account '
                                                                              'From '
                                                                              'Domain '
                                                                              'Admin '
                                                                              'Group',
                                                                      'supported_platforms': ['windows']}],
                                                    'attack_technique': 'T1531',
                                                    'display_name': 'Account '
                                                                    'Access '
                                                                    'Removal'}}]
```

# Tactics


* [Impact](../tactics/Impact.md)


# Mitigations

None

# Actors

None
