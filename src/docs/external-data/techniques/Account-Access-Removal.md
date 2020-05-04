
# Account Access Removal

## Description

### MITRE Description

> Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts.

Adversaries may also subsequently log off and/or reboot boxes to set malicious changes into place.(Citation: CarbonBlack LockerGoga 2019)(Citation: Unit42 LockerGoga 2019)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator', 'root', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1531

## Potential Commands

```
net.exe user AtomicAdministrator #{new_password}

net.exe user #{user_account} HuHuHUHoHo283283@dJD

net.exe user #{user_account} #{new_password}

net.exe user AtomicUser /delete

net.exe user #{user_account} /delete

```

## Commands Dataset

```
[{'command': 'net.exe user AtomicAdministrator #{new_password}\n',
  'name': None,
  'source': 'atomics/T1531/T1531.yaml'},
 {'command': 'net.exe user #{user_account} HuHuHUHoHo283283@dJD\n',
  'name': None,
  'source': 'atomics/T1531/T1531.yaml'},
 {'command': 'net.exe user #{user_account} #{new_password}\n',
  'name': None,
  'source': 'atomics/T1531/T1531.yaml'},
 {'command': 'net.exe user AtomicUser /delete\n',
  'name': None,
  'source': 'atomics/T1531/T1531.yaml'},
 {'command': 'net.exe user #{user_account} /delete\n',
  'name': None,
  'source': 'atomics/T1531/T1531.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Account Access Removal': {'atomic_tests': [{'dependencies': [{'description': 'User '
                                                                                                       'account '
                                                                                                       'to '
                                                                                                       'change '
                                                                                                       'password '
                                                                                                       'of '
                                                                                                       'must '
                                                                                                       'exist '
                                                                                                       '(User: '
                                                                                                       '#{user_account})\n',
                                                                                        'get_prereq_command': 'net '
                                                                                                              'user '
                                                                                                              '#{user_account} '
                                                                                                              '#{new_user_password} '
                                                                                                              '/add\n',
                                                                                        'prereq_command': 'net '
                                                                                                          'user '
                                                                                                          '#{user_account}\n'}],
                                                                      'description': 'Changes '
                                                                                     'the '
                                                                                     'user '
                                                                                     'password '
                                                                                     'to '
                                                                                     'hinder '
                                                                                     'access '
                                                                                     'attempts. '
                                                                                     'Seen '
                                                                                     'in '
                                                                                     'use '
                                                                                     'by '
                                                                                     'LockerGoga. '
                                                                                     'Upon '
                                                                                     'execution, '
                                                                                     'log '
                                                                                     'into '
                                                                                     'the '
                                                                                     'user '
                                                                                     'account '
                                                                                     '"AtomicAdministrator" '
                                                                                     'with\n'
                                                                                     'the '
                                                                                     'password '
                                                                                     '"HuHuHUHoHo283283".\n',
                                                                      'executor': {'cleanup_command': 'net.exe '
                                                                                                      'user '
                                                                                                      '#{user_account} '
                                                                                                      '/delete '
                                                                                                      '>nul '
                                                                                                      '2>&1\n',
                                                                                   'command': 'net.exe '
                                                                                              'user '
                                                                                              '#{user_account} '
                                                                                              '#{new_password}\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'command_prompt'},
                                                                      'input_arguments': {'new_password': {'default': 'HuHuHUHoHo283283@dJD',
                                                                                                           'description': 'New '
                                                                                                                          'password '
                                                                                                                          'for '
                                                                                                                          'the '
                                                                                                                          'specified '
                                                                                                                          'account.',
                                                                                                           'type': 'string'},
                                                                                          'new_user_password': {'default': 'User2ChangePW!',
                                                                                                                'description': 'Password '
                                                                                                                               'to '
                                                                                                                               'use '
                                                                                                                               'if '
                                                                                                                               'user '
                                                                                                                               'account '
                                                                                                                               'must '
                                                                                                                               'be '
                                                                                                                               'created '
                                                                                                                               'first',
                                                                                                                'type': 'string'},
                                                                                          'user_account': {'default': 'AtomicAdministrator',
                                                                                                           'description': 'User '
                                                                                                                          'account '
                                                                                                                          'whose '
                                                                                                                          'password '
                                                                                                                          'will '
                                                                                                                          'be '
                                                                                                                          'changed.',
                                                                                                           'type': 'string'}},
                                                                      'name': 'Change '
                                                                              'User '
                                                                              'Password '
                                                                              '- '
                                                                              'Windows',
                                                                      'supported_platforms': ['windows']},
                                                                     {'dependencies': [{'description': 'User '
                                                                                                       'account '
                                                                                                       'to '
                                                                                                       'delete '
                                                                                                       'must '
                                                                                                       'exist '
                                                                                                       '(User: '
                                                                                                       '#{user_account})\n',
                                                                                        'get_prereq_command': 'net '
                                                                                                              'user '
                                                                                                              '#{user_account} '
                                                                                                              '#{new_user_password} '
                                                                                                              '/add\n',
                                                                                        'prereq_command': 'net '
                                                                                                          'user '
                                                                                                          '#{user_account}\n'}],
                                                                      'description': 'Deletes '
                                                                                     'a '
                                                                                     'user '
                                                                                     'account '
                                                                                     'to '
                                                                                     'prevent '
                                                                                     'access. '
                                                                                     'Upon '
                                                                                     'execution, '
                                                                                     'run '
                                                                                     'the '
                                                                                     'command '
                                                                                     '"net '
                                                                                     'user" '
                                                                                     'to '
                                                                                     'verify '
                                                                                     'that '
                                                                                     'the '
                                                                                     'new '
                                                                                     '"AtomicUser" '
                                                                                     'account '
                                                                                     'was '
                                                                                     'deleted.\n',
                                                                      'executor': {'command': 'net.exe '
                                                                                              'user '
                                                                                              '#{user_account} '
                                                                                              '/delete\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'command_prompt'},
                                                                      'input_arguments': {'new_user_password': {'default': 'User2DeletePW!',
                                                                                                                'description': 'Password '
                                                                                                                               'to '
                                                                                                                               'use '
                                                                                                                               'if '
                                                                                                                               'user '
                                                                                                                               'account '
                                                                                                                               'must '
                                                                                                                               'be '
                                                                                                                               'created '
                                                                                                                               'first',
                                                                                                                'type': 'string'},
                                                                                          'user_account': {'default': 'AtomicUser',
                                                                                                           'description': 'User '
                                                                                                                          'account '
                                                                                                                          'to '
                                                                                                                          'be '
                                                                                                                          'deleted.',
                                                                                                           'type': 'string'}},
                                                                      'name': 'Delete '
                                                                              'User '
                                                                              '- '
                                                                              'Windows',
                                                                      'supported_platforms': ['windows']}],
                                                    'attack_technique': 'T1531',
                                                    'display_name': 'Account '
                                                                    'Access '
                                                                    'Removal'}}]
```

# Tactics


* [Impact](../tactics/Impact.md)


# Mitigations

None

# Actors

None
