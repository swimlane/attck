
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
                                                                  'supported_platforms': ['windows']}],
                                                'attack_technique': 'T1518',
                                                'display_name': 'Software '
                                                                'Discovery'}},
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
    
