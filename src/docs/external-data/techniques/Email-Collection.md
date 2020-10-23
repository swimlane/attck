
# Email Collection

## Description

### MITRE Description

> Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Adversaries can collect or forward email from mail servers or clients. 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows', 'Office 365']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1114

## Potential Commands

```
powershell/management/mailraider/disable_security
powershell/management/mailraider/get_emailitems
powershell/management/mailraider/get_subfolders
powershell/management/mailraider/mail_search
powershell/management/mailraider/search_gal
powershell/management/mailraider/send_mail
powershell/management/mailraider/view_email
python/collection/osx/search_email
```

## Commands Dataset

```
[{'command': 'powershell/management/mailraider/disable_security',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/mailraider/disable_security',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/mailraider/get_emailitems',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/mailraider/get_emailitems',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/mailraider/get_subfolders',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/mailraider/get_subfolders',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/mailraider/mail_search',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/mailraider/mail_search',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/mailraider/search_gal',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/mailraider/search_gal',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/mailraider/send_mail',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/mailraider/send_mail',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/mailraider/view_email',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/mailraider/view_email',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/search_email',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/search_email',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Firewall Logs']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Firewall Logs']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['4663', 'File monitoring']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1114',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/mailraider/disable_security":  '
                                                                                 '["T1114"],',
                                            'Empire Module': 'powershell/management/mailraider/disable_security',
                                            'Technique': 'Email Collection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1114',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/mailraider/get_emailitems":  '
                                                                                 '["T1114"],',
                                            'Empire Module': 'powershell/management/mailraider/get_emailitems',
                                            'Technique': 'Email Collection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1114',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/mailraider/get_subfolders":  '
                                                                                 '["T1114"],',
                                            'Empire Module': 'powershell/management/mailraider/get_subfolders',
                                            'Technique': 'Email Collection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1114',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/mailraider/mail_search":  '
                                                                                 '["T1114"],',
                                            'Empire Module': 'powershell/management/mailraider/mail_search',
                                            'Technique': 'Email Collection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1114',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/mailraider/search_gal":  '
                                                                                 '["T1114"],',
                                            'Empire Module': 'powershell/management/mailraider/search_gal',
                                            'Technique': 'Email Collection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1114',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/mailraider/send_mail":  '
                                                                                 '["T1114"],',
                                            'Empire Module': 'powershell/management/mailraider/send_mail',
                                            'Technique': 'Email Collection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1114',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/mailraider/view_email":  '
                                                                                 '["T1114"],',
                                            'Empire Module': 'powershell/management/mailraider/view_email',
                                            'Technique': 'Email Collection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1114',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/search_email":  '
                                                                                 '["T1114"],',
                                            'Empire Module': 'python/collection/osx/search_email',
                                            'Technique': 'Email Collection'}}]
```

# Tactics


* [Collection](../tactics/Collection.md)


# Mitigations


* [Email Collection Mitigation](../mitigations/Email-Collection-Mitigation.md)

* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)
    
* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)
    
* [Audit](../mitigations/Audit.md)
    

# Actors

None
