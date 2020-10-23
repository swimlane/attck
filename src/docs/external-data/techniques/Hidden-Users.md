
# Hidden Users

## Description

### MITRE Description

> Adversaries may use hidden users to mask the presence of user accounts they create. Every user account in macOS has a userID associated with it. When creating a user, you can specify the userID for that account.

There is a property value in <code>/Library/Preferences/com.apple.loginwindow</code> called <code>Hide500Users</code> that prevents users with userIDs 500 and lower from appearing at the login screen. When using the [Create Account](https://attack.mitre.org/techniques/T1136) technique with a userID under 500 (ex: <code>sudo dscl . -create /Users/username UniqueID 401</code>) and enabling this property (setting it to Yes), an adversary can conceal user accounts. (Citation: Cybereason OSX Pirrit).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['root', 'Administrator']
* Platforms: ['macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1564/002

## Potential Commands

```
sudo dscl . -create /Users/APT UniqueID 333
```

## Commands Dataset

```
[{'command': 'sudo dscl . -create /Users/APT UniqueID 333\n',
  'name': None,
  'source': 'atomics/T1564.002/T1564.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Hide Artifacts: Hidden Users': {'atomic_tests': [{'auto_generated_guid': '4238a7f0-a980-4fff-98a2-dfc0a363d507',
                                                                            'description': 'Add '
                                                                                           'a '
                                                                                           'hidden '
                                                                                           'user '
                                                                                           'on '
                                                                                           'MacOS\n',
                                                                            'executor': {'cleanup_command': 'sudo '
                                                                                                            'dscl '
                                                                                                            '. '
                                                                                                            '-delete '
                                                                                                            '/Users/#{user_name}\n',
                                                                                         'command': 'sudo '
                                                                                                    'dscl '
                                                                                                    '. '
                                                                                                    '-create '
                                                                                                    '/Users/#{user_name} '
                                                                                                    'UniqueID '
                                                                                                    '333\n',
                                                                                         'elevation_required': True,
                                                                                         'name': 'sh'},
                                                                            'input_arguments': {'user_name': {'default': 'APT',
                                                                                                              'description': 'username '
                                                                                                                             'to '
                                                                                                                             'add',
                                                                                                              'type': 'string'}},
                                                                            'name': 'Hidden '
                                                                                    'Users',
                                                                            'supported_platforms': ['macos']}],
                                                          'attack_technique': 'T1564.002',
                                                          'display_name': 'Hide '
                                                                          'Artifacts: '
                                                                          'Hidden '
                                                                          'Users'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)


# Actors

None
