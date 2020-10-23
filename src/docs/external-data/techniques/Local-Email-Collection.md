
# Local Email Collection

## Description

### MITRE Description

> Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files.

Outlook stores data locally in offline data files with an extension of .ost. Outlook 2010 and later supports .ost file sizes up to 50GB, while earlier versions of Outlook support up to 20GB.(Citation: Outlook File Sizes) IMAP accounts in Outlook 2013 (and earlier) and POP accounts use Outlook Data Files (.pst) as opposed to .ost, whereas IMAP accounts in Outlook 2016 (and later) use .ost files. Both types of Outlook data files are typically stored in `C:\Users\<username>\Documents\Outlook Files` or `C:\Users\<username>\AppData\Local\Microsoft\Outlook`.(Citation: Microsoft Outlook Files)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1114/001

## Potential Commands

```
powershell -executionpolicy bypass -command #{file_path}\Get-Inbox.ps1 -file $env:TEMP\mail.csv
powershell -executionpolicy bypass -command PathToAtomicsFolder\T1114.001\src\Get-Inbox.ps1 -file #{output_file}
```

## Commands Dataset

```
[{'command': 'powershell -executionpolicy bypass -command '
             '#{file_path}\\Get-Inbox.ps1 -file $env:TEMP\\mail.csv\n',
  'name': None,
  'source': 'atomics/T1114.001/T1114.001.yaml'},
 {'command': 'powershell -executionpolicy bypass -command '
             'PathToAtomicsFolder\\T1114.001\\src\\Get-Inbox.ps1 -file '
             '#{output_file}\n',
  'name': None,
  'source': 'atomics/T1114.001/T1114.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Email Collection: Local Email Collection': {'atomic_tests': [{'auto_generated_guid': '3f1b5096-0139-4736-9b78-19bcb02bb1cb',
                                                                                        'dependencies': [{'description': 'Get-Inbox.ps1 '
                                                                                                                         'must '
                                                                                                                         'be '
                                                                                                                         'located '
                                                                                                                         'at '
                                                                                                                         '#{file_path}\n',
                                                                                                          'get_prereq_command': 'Invoke-WebRequest '
                                                                                                                                '"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.001/src/Get-Inbox.ps1" '
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
                                                                                                     'name': 'powershell'},
                                                                                        'input_arguments': {'file_path': {'default': 'PathToAtomicsFolder\\T1114.001\\src',
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
                                                                      'attack_technique': 'T1114.001',
                                                                      'display_name': 'Email '
                                                                                      'Collection: '
                                                                                      'Local '
                                                                                      'Email '
                                                                                      'Collection'}}]
```

# Tactics


* [Collection](../tactics/Collection.md)


# Mitigations


* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)


# Actors


* [Magic Hound](../actors/Magic-Hound.md)

* [APT1](../actors/APT1.md)
    
