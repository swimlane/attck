
# Password Policy Discovery

## Description

### MITRE Description

> Password policies for networks are a way to enforce complex passwords that are difficult to guess or crack through [Brute Force](https://attack.mitre.org/techniques/T1110). An adversary may attempt to access detailed information about the password policy used within an enterprise network. This would help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).

Password policies can be set and discovered on Windows, Linux, and macOS systems. (Citation: Superuser Linux Password Policies) (Citation: Jamf User Password Policies)

### Windows
* <code>net accounts</code>
* <code>net accounts /domain</code>

### Linux
* <code>chage -l <username></code>
* <code>cat /etc/pam.d/common-password</code>

### macOS
* <code>pwpolicy getaccountpolicies</code>

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows', 'Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1201

## Potential Commands

```
cat /etc/pam.d/common-password

cat /etc/security/pwquality.conf

cat /etc/pam.d/system-auth
cat /etc/security/pwquality.conf

cat /etc/login.defs

net accounts

net accounts /domain

pwpolicy getaccountpolicies
{'darwin': {'sh': {'command': 'pwpolicy getaccountpolicies\n'}}, 'linux': {'sh': {'command': 'cat /etc/pam.d/common-password\n'}}, 'windows': {'psh': {'command': 'net accounts'}}}
powershell/situational_awareness/network/powerview/get_gpo
powershell/situational_awareness/network/powerview/get_gpo
Dos
Microsoft Windows [Version 10.0.14393]
(C) 2016 Microsoft Corporation. all rights reserved.

C: \ Users \ administrator.0DAY> net accounts
How long must force users to log off after time expires:? Never
Minimum password age (days): 1
Maximum password age (days): 42
Minimum password length: 7
Keep the length of the password history: 24
Lockout threshold: Never
Lockout duration (minutes): 30
Lock observation window (minutes): 30
Computer role: SERVER
The command completed successfully.
```

## Commands Dataset

```
[{'command': 'cat /etc/pam.d/common-password\n',
  'name': None,
  'source': 'atomics/T1201/T1201.yaml'},
 {'command': 'cat /etc/security/pwquality.conf\n',
  'name': None,
  'source': 'atomics/T1201/T1201.yaml'},
 {'command': 'cat /etc/pam.d/system-auth\ncat /etc/security/pwquality.conf\n',
  'name': None,
  'source': 'atomics/T1201/T1201.yaml'},
 {'command': 'cat /etc/login.defs\n',
  'name': None,
  'source': 'atomics/T1201/T1201.yaml'},
 {'command': 'net accounts\n',
  'name': None,
  'source': 'atomics/T1201/T1201.yaml'},
 {'command': 'net accounts /domain\n',
  'name': None,
  'source': 'atomics/T1201/T1201.yaml'},
 {'command': 'pwpolicy getaccountpolicies',
  'name': None,
  'source': 'atomics/T1201/T1201.yaml'},
 {'command': {'darwin': {'sh': {'command': 'pwpolicy getaccountpolicies\n'}},
              'linux': {'sh': {'command': 'cat /etc/pam.d/common-password\n'}},
              'windows': {'psh': {'command': 'net accounts'}}},
  'name': 'Password Policy Discovery',
  'source': 'data/abilities/discovery/e82f39e2-56f8-4f19-8376-b007f9ac5f8a.yml'},
 {'command': 'powershell/situational_awareness/network/powerview/get_gpo',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_gpo',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'Dos\n'
             'Microsoft Windows [Version 10.0.14393]\n'
             '(C) 2016 Microsoft Corporation. all rights reserved.\n'
             '\n'
             'C: \\ Users \\ administrator.0DAY> net accounts\n'
             'How long must force users to log off after time expires:? Never\n'
             'Minimum password age (days): 1\n'
             'Maximum password age (days): 42\n'
             'Minimum password length: 7\n'
             'Keep the length of the password history: 24\n'
             'Lockout threshold: Never\n'
             'Lockout duration (minutes): 30\n'
             'Lock observation window (minutes): 30\n'
             'Computer role: SERVER\n'
             'The command completed successfully.',
  'name': 'Dos',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json
[{'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']}]
```

## Potential Queries

```json
[{'name': 'Password Policy Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 11and (process_command_line contains "net '
           'accounts"or process_command_line contains "net accounts '
           '\\\\/domain")'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows system password policies found\n'
           'description: windows server 2016\n'
           'references:\n'
           'tags: T1016\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ net.exe' # process information> new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ Windows "
           "\\ System32 \\ cmd.exe' # Process Information> Creator Process "
           'Name\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: net accounts # '
           'Process Information> process command line\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ net1.exe' # process information> new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ Windows "
           "\\ System32 \\ net.exe' # Process Information> Creator Process "
           'Name\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: C: \\ Windows '
           '\\ system32 \\ net1 accounts # Process Information> process '
           'command line\n'
           '\xa0\xa0\xa0\xa0condition: selection1 and selection2\n'
           'level: low'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Password Policy Discovery': {'atomic_tests': [{'auto_generated_guid': '085fe567-ac84-47c7-ac4c-2688ce28265b',
                                                                         'description': 'Lists '
                                                                                        'the '
                                                                                        'password '
                                                                                        'complexity '
                                                                                        'policy '
                                                                                        'to '
                                                                                        'console '
                                                                                        'on '
                                                                                        'Ubuntu '
                                                                                        'Linux.\n',
                                                                         'executor': {'command': 'cat '
                                                                                                 '/etc/pam.d/common-password\n',
                                                                                      'name': 'bash'},
                                                                         'name': 'Examine '
                                                                                 'password '
                                                                                 'complexity '
                                                                                 'policy '
                                                                                 '- '
                                                                                 'Ubuntu',
                                                                         'supported_platforms': ['linux']},
                                                                        {'auto_generated_guid': '78a12e65-efff-4617-bc01-88f17d71315d',
                                                                         'dependencies': [{'description': 'System '
                                                                                                          'must '
                                                                                                          'be '
                                                                                                          'CentOS '
                                                                                                          'or '
                                                                                                          'RHEL '
                                                                                                          'v7\n',
                                                                                           'get_prereq_command': 'echo '
                                                                                                                 'Please '
                                                                                                                 'run '
                                                                                                                 'from '
                                                                                                                 'CentOS '
                                                                                                                 'or '
                                                                                                                 'RHEL '
                                                                                                                 'v7\n',
                                                                                           'prereq_command': 'if '
                                                                                                             '[ '
                                                                                                             '$(rpm '
                                                                                                             '-q '
                                                                                                             '--queryformat '
                                                                                                             "'%{VERSION}') "
                                                                                                             '-eq '
                                                                                                             '"7" '
                                                                                                             ']; '
                                                                                                             'then '
                                                                                                             'exit '
                                                                                                             '/b '
                                                                                                             '0; '
                                                                                                             'else '
                                                                                                             'exit '
                                                                                                             '/b '
                                                                                                             '1; '
                                                                                                             'fi;\n'}],
                                                                         'description': 'Lists '
                                                                                        'the '
                                                                                        'password '
                                                                                        'complexity '
                                                                                        'policy '
                                                                                        'to '
                                                                                        'console '
                                                                                        'on '
                                                                                        'CentOS/RHEL '
                                                                                        '7.x '
                                                                                        'Linux.\n',
                                                                         'executor': {'command': 'cat '
                                                                                                 '/etc/security/pwquality.conf\n',
                                                                                      'name': 'bash'},
                                                                         'name': 'Examine '
                                                                                 'password '
                                                                                 'complexity '
                                                                                 'policy '
                                                                                 '- '
                                                                                 'CentOS/RHEL '
                                                                                 '7.x',
                                                                         'supported_platforms': ['linux']},
                                                                        {'auto_generated_guid': '6ce12552-0adb-4f56-89ff-95ce268f6358',
                                                                         'dependencies': [{'description': 'System '
                                                                                                          'must '
                                                                                                          'be '
                                                                                                          'CentOS '
                                                                                                          'or '
                                                                                                          'RHEL '
                                                                                                          'v6\n',
                                                                                           'get_prereq_command': 'echo '
                                                                                                                 'Please '
                                                                                                                 'run '
                                                                                                                 'from '
                                                                                                                 'CentOS '
                                                                                                                 'or '
                                                                                                                 'RHEL '
                                                                                                                 'v6\n',
                                                                                           'prereq_command': 'if '
                                                                                                             '[ '
                                                                                                             '$(rpm '
                                                                                                             '-q '
                                                                                                             '--queryformat '
                                                                                                             "'%{VERSION}') "
                                                                                                             '-eq '
                                                                                                             '"6" '
                                                                                                             ']; '
                                                                                                             'then '
                                                                                                             'exit '
                                                                                                             '/b '
                                                                                                             '0; '
                                                                                                             'else '
                                                                                                             'exit '
                                                                                                             '/b '
                                                                                                             '1; '
                                                                                                             'fi;\n'}],
                                                                         'description': 'Lists '
                                                                                        'the '
                                                                                        'password '
                                                                                        'complexity '
                                                                                        'policy '
                                                                                        'to '
                                                                                        'console '
                                                                                        'on '
                                                                                        'CentOS/RHEL '
                                                                                        '6.x '
                                                                                        'Linux.\n',
                                                                         'executor': {'command': 'cat '
                                                                                                 '/etc/pam.d/system-auth\n'
                                                                                                 'cat '
                                                                                                 '/etc/security/pwquality.conf\n',
                                                                                      'name': 'bash'},
                                                                         'name': 'Examine '
                                                                                 'password '
                                                                                 'complexity '
                                                                                 'policy '
                                                                                 '- '
                                                                                 'CentOS/RHEL '
                                                                                 '6.x',
                                                                         'supported_platforms': ['linux']},
                                                                        {'auto_generated_guid': '7c86c55c-70fa-4a05-83c9-3aa19b145d1a',
                                                                         'description': 'Lists '
                                                                                        'the '
                                                                                        'password '
                                                                                        'expiration '
                                                                                        'policy '
                                                                                        'to '
                                                                                        'console '
                                                                                        'on '
                                                                                        'CentOS/RHEL/Ubuntu.\n',
                                                                         'executor': {'command': 'cat '
                                                                                                 '/etc/login.defs\n',
                                                                                      'name': 'bash'},
                                                                         'name': 'Examine '
                                                                                 'password '
                                                                                 'expiration '
                                                                                 'policy '
                                                                                 '- '
                                                                                 'All '
                                                                                 'Linux',
                                                                         'supported_platforms': ['linux']},
                                                                        {'auto_generated_guid': '4588d243-f24e-4549-b2e3-e627acc089f6',
                                                                         'description': 'Lists '
                                                                                        'the '
                                                                                        'local '
                                                                                        'password '
                                                                                        'policy '
                                                                                        'to '
                                                                                        'console '
                                                                                        'on '
                                                                                        'Windows.\n',
                                                                         'executor': {'command': 'net '
                                                                                                 'accounts\n',
                                                                                      'elevation_required': False,
                                                                                      'name': 'command_prompt'},
                                                                         'name': 'Examine '
                                                                                 'local '
                                                                                 'password '
                                                                                 'policy '
                                                                                 '- '
                                                                                 'Windows',
                                                                         'supported_platforms': ['windows']},
                                                                        {'auto_generated_guid': '46c2c362-2679-4ef5-aec9-0e958e135be4',
                                                                         'description': 'Lists '
                                                                                        'the '
                                                                                        'domain '
                                                                                        'password '
                                                                                        'policy '
                                                                                        'to '
                                                                                        'console '
                                                                                        'on '
                                                                                        'Windows.\n',
                                                                         'executor': {'command': 'net '
                                                                                                 'accounts '
                                                                                                 '/domain\n',
                                                                                      'elevation_required': False,
                                                                                      'name': 'command_prompt'},
                                                                         'name': 'Examine '
                                                                                 'domain '
                                                                                 'password '
                                                                                 'policy '
                                                                                 '- '
                                                                                 'Windows',
                                                                         'supported_platforms': ['windows']},
                                                                        {'auto_generated_guid': '4b7fa042-9482-45e1-b348-4b756b2a0742',
                                                                         'description': 'Lists '
                                                                                        'the '
                                                                                        'password '
                                                                                        'policy '
                                                                                        'to '
                                                                                        'console '
                                                                                        'on '
                                                                                        'macOS.\n',
                                                                         'executor': {'command': 'pwpolicy '
                                                                                                 'getaccountpolicies',
                                                                                      'name': 'bash'},
                                                                         'name': 'Examine '
                                                                                 'password '
                                                                                 'policy '
                                                                                 '- '
                                                                                 'macOS',
                                                                         'supported_platforms': ['macos']}],
                                                       'attack_technique': 'T1201',
                                                       'display_name': 'Password '
                                                                       'Policy '
                                                                       'Discovery'}},
 {'Mitre Stockpile - Password Policy Discovery': {'description': 'Password '
                                                                 'Policy '
                                                                 'Discovery',
                                                  'id': 'e82f39e2-56f8-4f19-8376-b007f9ac5f8a',
                                                  'name': 'Password Policy',
                                                  'platforms': {'darwin': {'sh': {'command': 'pwpolicy '
                                                                                             'getaccountpolicies\n'}},
                                                                'linux': {'sh': {'command': 'cat '
                                                                                            '/etc/pam.d/common-password\n'}},
                                                                'windows': {'psh': {'command': 'net '
                                                                                               'accounts'}}},
                                                  'tactic': 'discovery',
                                                  'technique': {'attack_id': 'T1201',
                                                                'name': 'Password '
                                                                        'Policy '
                                                                        'Discovery'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1201',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_gpo":  '
                                                                                 '["T1201"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_gpo',
                                            'Technique': 'Password Policy '
                                                         'Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations

None

# Actors


* [OilRig](../actors/OilRig.md)

