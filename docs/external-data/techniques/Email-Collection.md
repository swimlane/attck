
# Email Collection

## Description

### MITRE Description

> Adversaries may target user email to collect sensitive information from a target.

Files containing email data can be acquired from a user's system, such as Outlook storage or cache files .pst and .ost.

Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network. Adversaries may also access externally facing Exchange services or Office 365 to access email using credentials or access tokens. Tools such as [MailSniper](https://attack.mitre.org/software/S0413) can be used to automate searches for specific key words.(Citation: Black Hills MailSniper, 2017)

### Email Forwarding Rule

Adversaries may also abuse email-forwarding rules to monitor the activities of a victim, steal information, and further gain intelligence on the victim or the victim’s organization to use as part of further exploits or operations.(Citation: US-CERT TA18-068A 2018) Outlook and Outlook Web App (OWA) allow users to create inbox rules for various email functions, including forwarding to a different recipient. Messages can be forwarded to internal or external recipients, and there are no restrictions limiting the extent of this rule. Administrators may also create forwarding rules for user accounts with the same considerations and outcomes.(Citation: TIMMCMIC, 2014)

Any user or administrator within the organization (or adversary with valid credentials) can create rules to automatically forward all received messages to another recipient, forward emails to different locations based on the sender, and more. 

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
powershell -executionpolicy bypass -command PathToAtomicsFolder\T1114\src\Get-Inbox.ps1 -file #{output_file}

powershell -executionpolicy bypass -command #{file_path}\Get-Inbox.ps1 -file $env:TEMP\mail.csv

powershell/management/mailraider/disable_security
powershell/management/mailraider/disable_security
powershell/management/mailraider/get_emailitems
powershell/management/mailraider/get_emailitems
powershell/management/mailraider/get_subfolders
powershell/management/mailraider/get_subfolders
powershell/management/mailraider/mail_search
powershell/management/mailraider/mail_search
powershell/management/mailraider/search_gal
powershell/management/mailraider/search_gal
powershell/management/mailraider/send_mail
powershell/management/mailraider/send_mail
powershell/management/mailraider/view_email
powershell/management/mailraider/view_email
python/collection/osx/search_email
python/collection/osx/search_email
```

## Commands Dataset

```
[{'command': 'powershell -executionpolicy bypass -command '
             'PathToAtomicsFolder\\T1114\\src\\Get-Inbox.ps1 -file '
             '#{output_file}\n',
  'name': None,
  'source': 'atomics/T1114/T1114.yaml'},
 {'command': 'powershell -executionpolicy bypass -command '
             '#{file_path}\\Get-Inbox.ps1 -file $env:TEMP\\mail.csv\n',
  'name': None,
  'source': 'atomics/T1114/T1114.yaml'},
 {'command': 'powershell/management/mailraider/disable_security',
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
[{'Atomic Red Team Test - Email Collection': {'atomic_tests': [{'auto_generated_guid': '3f1b5096-0139-4736-9b78-19bcb02bb1cb',
                                                                'dependencies': [{'description': 'Get-Inbox.ps1 '
                                                                                                 'must '
                                                                                                 'be '
                                                                                                 'located '
                                                                                                 'at '
                                                                                                 '#{file_path}\n',
                                                                                  'get_prereq_command': 'Invoke-WebRequest '
                                                                                                        '"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114/src/Get-Inbox.ps1" '
                                                                                                        '-OutFile '
                                                                                                        '"#{file_path}\\Get-Inbox.ps1"\n',
                                                                                  'prereq_command': 'if '
                                                                                                    '(Test-Path '
                                                                                                    '#{file_path}\\Get-Inbox.ps1) '
                                                                                                    '{exit '
                                                                                                    '0} '
                                                                                                    'else '
                                                                                                    '{exit '
                                                                                                    '1}\n'}],
                                                                'dependency_executor_name': 'powershell',
                                                                'description': 'Search '
                                                                               'through '
                                                                               'local '
                                                                               'Outlook '
                                                                               'installation, '
                                                                               'extract '
                                                                               'mail, '
                                                                               'compress '
                                                                               'the '
                                                                               'contents, '
                                                                               'and '
                                                                               'saves '
                                                                               'everything '
                                                                               'to '
                                                                               'a '
                                                                               'directory '
                                                                               'for '
                                                                               'later '
                                                                               'exfiltration.\n'
                                                                               'Successful '
                                                                               'execution '
                                                                               'will '
                                                                               'produce '
                                                                               'stdout '
                                                                               'message '
                                                                               'stating '
                                                                               '"Please '
                                                                               'be '
                                                                               'patient, '
                                                                               'this '
                                                                               'may '
                                                                               'take '
                                                                               'some '
                                                                               'time...". '
                                                                               'Upon '
                                                                               'completion, '
                                                                               'final '
                                                                               'output '
                                                                               'will '
                                                                               'be '
                                                                               'a '
                                                                               'mail.csv '
                                                                               'file.\n'
                                                                               '\n'
                                                                               'Note: '
                                                                               'Outlook '
                                                                               'is '
                                                                               'required, '
                                                                               'but '
                                                                               'no '
                                                                               'email '
                                                                               'account '
                                                                               'necessary '
                                                                               'to '
                                                                               'produce '
                                                                               'artifacts.\n',
                                                                'executor': {'cleanup_command': 'Remove-Item '
                                                                                                '#{output_file} '
                                                                                                '-Force '
                                                                                                '-ErrorAction '
                                                                                                'Ignore\n',
                                                                             'command': 'powershell '
                                                                                        '-executionpolicy '
                                                                                        'bypass '
                                                                                        '-command '
                                                                                        '#{file_path}\\Get-Inbox.ps1 '
                                                                                        '-file '
                                                                                        '#{output_file}\n',
                                                                             'elevation_required': False,
                                                                             'name': 'powershell'},
                                                                'input_arguments': {'file_path': {'default': 'PathToAtomicsFolder\\T1114\\src',
                                                                                                  'description': 'File '
                                                                                                                 'path '
                                                                                                                 'for '
                                                                                                                 'Get-Inbox.ps1',
                                                                                                  'type': 'String'},
                                                                                    'output_file': {'default': '$env:TEMP\\mail.csv',
                                                                                                    'description': 'Output '
                                                                                                                   'file '
                                                                                                                   'path',
                                                                                                    'type': 'String'}},
                                                                'name': 'Email '
                                                                        'Collection '
                                                                        'with '
                                                                        'PowerShell '
                                                                        'Get-Inbox',
                                                                'supported_platforms': ['windows']}],
                                              'attack_link': 'https://attack.mitre.org/wiki/Technique/T1114',
                                              'attack_technique': 'T1114',
                                              'display_name': 'Email '
                                                              'Collection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1114',
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

None

# Actors


* [APT28](../actors/APT28.md)

* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Leafminer](../actors/Leafminer.md)
    
* [APT1](../actors/APT1.md)
    
* [FIN4](../actors/FIN4.md)
    
