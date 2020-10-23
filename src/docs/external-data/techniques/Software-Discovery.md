
# Software Discovery

## Description

### MITRE Description

> Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment. Adversaries may use the information from [Software Discovery](https://attack.mitre.org/techniques/T1518) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable to [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure', 'Office 365', 'Azure AD', 'SaaS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1518

## Potential Commands

```
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer" /v svcVersion

Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -Autosize
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -Autosize

/usr/libexec/PlistBuddy -c "print :CFBundleShortVersionString" /Applications/Safari.app/Contents/Info.plist
/usr/libexec/PlistBuddy -c "print :CFBundleVersion" /Applications/Safari.app/Contents/Info.plist
{'darwin': {'sh': {'command': 'which google-chrome\n'}}, 'linux': {'sh': {'command': 'which google-chrome\n'}}}
{'darwin': {'sh': {'command': 'which go\n'}}, 'linux': {'sh': {'command': 'which go\n'}}}
{'darwin': {'sh': {'command': 'python3 --version\n'}}, 'linux': {'sh': {'command': 'python3 --version\n'}}}
{'windows': {'psh': {'command': "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Internet Explorer').Version\n"}}}
```

## Commands Dataset

```
[{'command': 'reg query "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Internet '
             'Explorer" /v svcVersion\n',
  'name': None,
  'source': 'atomics/T1518/T1518.yaml'},
 {'command': 'Get-ItemProperty '
             'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* '
             '| Select-Object DisplayName, DisplayVersion, Publisher, '
             'InstallDate | Format-Table -Autosize\n'
             'Get-ItemProperty '
             'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* '
             '| Select-Object DisplayName, DisplayVersion, Publisher, '
             'InstallDate | Format-Table -Autosize\n',
  'name': None,
  'source': 'atomics/T1518/T1518.yaml'},
 {'command': '/usr/libexec/PlistBuddy -c "print :CFBundleShortVersionString" '
             '/Applications/Safari.app/Contents/Info.plist\n'
             '/usr/libexec/PlistBuddy -c "print :CFBundleVersion" '
             '/Applications/Safari.app/Contents/Info.plist',
  'name': None,
  'source': 'atomics/T1518/T1518.yaml'},
 {'command': {'darwin': {'sh': {'command': 'which google-chrome\n'}},
              'linux': {'sh': {'command': 'which google-chrome\n'}}},
  'name': 'Check to see if Gooogle Chrome browser is installed',
  'source': 'data/abilities/discovery/830bb6ed-9594-4817-b1a1-c298c0f9f425.yml'},
 {'command': {'darwin': {'sh': {'command': 'which go\n'}},
              'linux': {'sh': {'command': 'which go\n'}}},
  'name': 'Check to see if GoLang is installed',
  'source': 'data/abilities/discovery/9849d956-37ea-49f2-a8b5-f2ca080b315d.yml'},
 {'command': {'darwin': {'sh': {'command': 'python3 --version\n'}},
              'linux': {'sh': {'command': 'python3 --version\n'}}},
  'name': 'Check to see what version of python is installed',
  'source': 'data/abilities/discovery/b18e8767-b7ea-41a3-8e80-baf65a5ddef5.yml'},
 {'command': {'windows': {'psh': {'command': '(Get-ItemProperty '
                                             "'HKLM:\\SOFTWARE\\Microsoft\\Internet "
                                             "Explorer').Version\n"}}},
  'name': 'Determine the version of Internet Explorer running',
  'source': 'data/abilities/discovery/c9be8043-a445-4cbf-b77b-ed7bb007fc7c.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Software Discovery': {'atomic_tests': [{'auto_generated_guid': '68981660-6670-47ee-a5fa-7e74806420a4',
                                                                  'description': 'Query '
                                                                                 'the '
                                                                                 'registry '
                                                                                 'to '
                                                                                 'determine '
                                                                                 'the '
                                                                                 'version '
                                                                                 'of '
                                                                                 'internet '
                                                                                 'explorer '
                                                                                 'installed '
                                                                                 'on '
                                                                                 'the '
                                                                                 'system.\n'
                                                                                 'Upon '
                                                                                 'execution, '
                                                                                 'version '
                                                                                 'information '
                                                                                 'about '
                                                                                 'internet '
                                                                                 'explorer '
                                                                                 'will '
                                                                                 'be '
                                                                                 'displayed.\n',
                                                                  'executor': {'command': 'reg '
                                                                                          'query '
                                                                                          '"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Internet '
                                                                                          'Explorer" '
                                                                                          '/v '
                                                                                          'svcVersion\n',
                                                                               'name': 'command_prompt'},
                                                                  'name': 'Find '
                                                                          'and '
                                                                          'Display '
                                                                          'Internet '
                                                                          'Explorer '
                                                                          'Browser '
                                                                          'Version',
                                                                  'supported_platforms': ['windows']},
                                                                 {'auto_generated_guid': 'c49978f6-bd6e-4221-ad2c-9e3e30cc1e3b',
                                                                  'description': 'Query '
                                                                                 'the '
                                                                                 'registry '
                                                                                 'to '
                                                                                 'determine '
                                                                                 'software '
                                                                                 'and '
                                                                                 'versions '
                                                                                 'installed '
                                                                                 'on '
                                                                                 'the '
                                                                                 'system. '
                                                                                 'Upon '
                                                                                 'execution '
                                                                                 'a '
                                                                                 'table '
                                                                                 'of\n'
                                                                                 'software '
                                                                                 'name '
                                                                                 'and '
                                                                                 'version '
                                                                                 'information '
                                                                                 'will '
                                                                                 'be '
                                                                                 'displayed.\n',
                                                                  'executor': {'command': 'Get-ItemProperty '
                                                                                          'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* '
                                                                                          '| '
                                                                                          'Select-Object '
                                                                                          'DisplayName, '
                                                                                          'DisplayVersion, '
                                                                                          'Publisher, '
                                                                                          'InstallDate '
                                                                                          '| '
                                                                                          'Format-Table '
                                                                                          '-Autosize\n'
                                                                                          'Get-ItemProperty '
                                                                                          'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* '
                                                                                          '| '
                                                                                          'Select-Object '
                                                                                          'DisplayName, '
                                                                                          'DisplayVersion, '
                                                                                          'Publisher, '
                                                                                          'InstallDate '
                                                                                          '| '
                                                                                          'Format-Table '
                                                                                          '-Autosize\n',
                                                                               'name': 'powershell'},
                                                                  'name': 'Applications '
                                                                          'Installed',
                                                                  'supported_platforms': ['windows']},
                                                                 {'auto_generated_guid': '103d6533-fd2a-4d08-976a-4a598565280f',
                                                                  'description': 'Adversaries '
                                                                                 'may '
                                                                                 'attempt '
                                                                                 'to '
                                                                                 'get '
                                                                                 'a '
                                                                                 'listing '
                                                                                 'of '
                                                                                 'non-security '
                                                                                 'related '
                                                                                 'software '
                                                                                 'that '
                                                                                 'is '
                                                                                 'installed '
                                                                                 'on '
                                                                                 'the '
                                                                                 'system. '
                                                                                 'Adversaries '
                                                                                 'may '
                                                                                 'use '
                                                                                 'the '
                                                                                 'information '
                                                                                 'from '
                                                                                 'Software '
                                                                                 'Discovery '
                                                                                 'during '
                                                                                 'automated '
                                                                                 'discovery '
                                                                                 'to '
                                                                                 'shape '
                                                                                 'follow-on '
                                                                                 'behaviors\n',
                                                                  'executor': {'command': '/usr/libexec/PlistBuddy '
                                                                                          '-c '
                                                                                          '"print '
                                                                                          ':CFBundleShortVersionString" '
                                                                                          '/Applications/Safari.app/Contents/Info.plist\n'
                                                                                          '/usr/libexec/PlistBuddy '
                                                                                          '-c '
                                                                                          '"print '
                                                                                          ':CFBundleVersion" '
                                                                                          '/Applications/Safari.app/Contents/Info.plist',
                                                                               'elevation_required': False,
                                                                               'name': 'command_prompt'},
                                                                  'name': 'Find '
                                                                          'and '
                                                                          'Display '
                                                                          'Safari '
                                                                          'Browser '
                                                                          'Version',
                                                                  'supported_platforms': ['macos']}],
                                                'attack_technique': 'T1518',
                                                'display_name': 'Software '
                                                                'Discovery'}},
 {'Mitre Stockpile - Check to see if Gooogle Chrome browser is installed': {'description': 'Check '
                                                                                           'to '
                                                                                           'see '
                                                                                           'if '
                                                                                           'Gooogle '
                                                                                           'Chrome '
                                                                                           'browser '
                                                                                           'is '
                                                                                           'installed',
                                                                            'id': '830bb6ed-9594-4817-b1a1-c298c0f9f425',
                                                                            'name': 'Check '
                                                                                    'Chrome',
                                                                            'platforms': {'darwin': {'sh': {'command': 'which '
                                                                                                                       'google-chrome\n'}},
                                                                                          'linux': {'sh': {'command': 'which '
                                                                                                                      'google-chrome\n'}}},
                                                                            'tactic': 'discovery',
                                                                            'technique': {'attack_id': 'T1518',
                                                                                          'name': 'Software '
                                                                                                  'Discovery'}}},
 {'Mitre Stockpile - Check to see if GoLang is installed': {'description': 'Check '
                                                                           'to '
                                                                           'see '
                                                                           'if '
                                                                           'GoLang '
                                                                           'is '
                                                                           'installed',
                                                            'id': '9849d956-37ea-49f2-a8b5-f2ca080b315d',
                                                            'name': 'Check Go',
                                                            'platforms': {'darwin': {'sh': {'command': 'which '
                                                                                                       'go\n'}},
                                                                          'linux': {'sh': {'command': 'which '
                                                                                                      'go\n'}}},
                                                            'tactic': 'discovery',
                                                            'technique': {'attack_id': 'T1518',
                                                                          'name': 'Software '
                                                                                  'Discovery'}}},
 {'Mitre Stockpile - Check to see what version of python is installed': {'description': 'Check '
                                                                                        'to '
                                                                                        'see '
                                                                                        'what '
                                                                                        'version '
                                                                                        'of '
                                                                                        'python '
                                                                                        'is '
                                                                                        'installed',
                                                                         'id': 'b18e8767-b7ea-41a3-8e80-baf65a5ddef5',
                                                                         'name': 'Check '
                                                                                 'Python',
                                                                         'platforms': {'darwin': {'sh': {'command': 'python3 '
                                                                                                                    '--version\n'}},
                                                                                       'linux': {'sh': {'command': 'python3 '
                                                                                                                   '--version\n'}}},
                                                                         'tactic': 'discovery',
                                                                         'technique': {'attack_id': 'T1518',
                                                                                       'name': 'Software '
                                                                                               'Discovery'}}},
 {'Mitre Stockpile - Determine the version of Internet Explorer running': {'description': 'Determine '
                                                                                          'the '
                                                                                          'version '
                                                                                          'of '
                                                                                          'Internet '
                                                                                          'Explorer '
                                                                                          'running',
                                                                           'id': 'c9be8043-a445-4cbf-b77b-ed7bb007fc7c',
                                                                           'name': 'Internet '
                                                                                   'Explorer '
                                                                                   'Version',
                                                                           'platforms': {'windows': {'psh': {'command': '(Get-ItemProperty '
                                                                                                                        "'HKLM:\\SOFTWARE\\Microsoft\\Internet "
                                                                                                                        "Explorer').Version\n"}}},
                                                                           'tactic': 'discovery',
                                                                           'technique': {'attack_id': 'T1518',
                                                                                         'name': 'Software '
                                                                                                 'Discovery'}}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations

None

# Actors


* [Inception](../actors/Inception.md)

* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
