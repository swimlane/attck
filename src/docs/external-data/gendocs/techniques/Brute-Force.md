
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
powershell/recon/get_sql_server_login_default_pw
powershell/recon/http_login
powershell/recon/http_login
powershell/situational_awareness/network/smbautobrute
powershell/situational_awareness/network/smbautobrute
powershell/situational_awareness/network/smbscanner
powershell/situational_awareness/network/smbscanner
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
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': '/var/log/secure'},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['4624', 'Authentication logs']}]
```

## Potential Queries

```json

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
    
