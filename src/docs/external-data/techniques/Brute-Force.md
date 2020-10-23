
# Brute Force

## Description

### MITRE Description

> Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows', 'Office 365', 'Azure AD', 'SaaS', 'GCP', 'AWS', 'Azure']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1110

## Potential Commands

```
powershell/recon/get_sql_server_login_default_pw
powershell/recon/http_login
powershell/situational_awareness/network/smbautobrute
powershell/situational_awareness/network/smbscanner
Shell
root @ icbc: / hacker / mima # hydra -l root -P passwd.txt ssh: //192.168.159.132 -V
Hydra v9.0 (c) 2019 by van Hauser / THC - Please do not use in military or secret service organizations, or for illegal purposes.
Log
Failed password for root from 192.168.159.129 port 43728 ssh2
Log
type = USER_AUTH msg = audit (1572163129.581: 316): pid = 2165 uid = 0 auid = 4294967295 ses = 4294967295 msg = 'op = PAM: authentication acct = "root" exe = "/ usr / sbin / sshd" hostname = 192.168 .159.129 addr = 192.168.159.129 terminal = ssh res = failed '
auth.log
audit.log
```

## Commands Dataset

```
[{'command': 'powershell/recon/get_sql_server_login_default_pw',
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
[{'data_source': '/var/log/secure'},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['4624', 'Authentication logs']}]
```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: linux under ssh brute force\n'
           'description: Ubuntu18.04, kali\n'
           'references:\n'
           'tags: T1110-003\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: linux\n'
           '    service: auth.log / audit.log\n'
           'detection:\n'
           '    keywords:\n'
           "       - 'Failed password for * ssh2' #linux auth.log\n"
           '       - \'* exe = "/ usr / sbin / sshd" * terminal = ssh res = '
           "failed' #linux audit.log\n"
           '    condition: keywords\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: brute\n'
           'description: validation failure is detected from a source to a '
           'destination of many identities, suggesting that there may be '
           'violence\n'
           'tags:\n'
           '    - attack.t1110\n'
           'author: Aleksandr Akhremchik, oscd.community\n'
           'Translator: 12306Bro\n'
           'date: 2019/10/25\n'
           'status: experimental\n'
           'logsource:\n'
           '    category: authentication # authentication data\n'
           'detection:\n'
           '    selection:\n'
           '         action: failure # Failed\n'
           '    timeframe: 600s\n'
           '    condition: selection | count (category) by dst_ip> 30 # '
           'Certification statistical data within 10 minutes of target greater '
           'than 30 IP and source IP address authentication failure\n'
           'fields:\n'
           '    - src_ip # source IP\n'
           '    - dst_ip # destination IP\n'
           '    - user # User\n'
           'falsepositives: # false\n'
           '    - Inventarization # inventory\n'
           '    - Penetration testing # Penetration Testing\n'
           '    - Vulnerability scanner # Vulnerability Scanner\n'
           '    - Legitimate application # legitimate application\n'
           'level: medium # in'}]
```

## Raw Dataset

```json
[{'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1110',
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


* [Brute Force Mitigation](../mitigations/Brute-Force-Mitigation.md)

* [Password Policies](../mitigations/Password-Policies.md)
    
* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)
    
* [Account Use Policies](../mitigations/Account-Use-Policies.md)
    
* [User Account Management](../mitigations/User-Account-Management.md)
    

# Actors


* [Turla](../actors/Turla.md)

* [FIN5](../actors/FIN5.md)
    
* [OilRig](../actors/OilRig.md)
    
* [APT39](../actors/APT39.md)
    
* [DarkVishnya](../actors/DarkVishnya.md)
    
