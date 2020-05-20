
# Hidden Users

## Description

### MITRE Description

> Every user account in macOS has a userID associated with it. When creating a user, you can specify the userID for that account. There is a property value in <code>/Library/Preferences/com.apple.loginwindow</code> called <code>Hide500Users</code> that prevents users with userIDs 500 and lower from appearing at the login screen. By using the [Create Account](https://attack.mitre.org/techniques/T1136) technique with a userID under 500 and enabling this property (setting it to Yes), an adversary can hide their user accounts much more easily: <code>sudo dscl . -create /Users/username UniqueID 401</code> (Citation: Cybereason OSX Pirrit).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'root']
* Platforms: ['macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1147

## Potential Commands

```
sudo dscl . -create /Users/APT UniqueID 333

bash sudo xattr -r -d com.apple.quarantine /path/to/*.app
```

## Commands Dataset

```
[{'command': 'sudo dscl . -create /Users/APT UniqueID 333\n',
  'name': None,
  'source': 'atomics/T1147/T1147.yaml'},
 {'command': 'bash sudo xattr -r -d com.apple.quarantine /path/to/*.app',
  'name': None,
  'source': 'Threat Hunting Tables'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Hidden Users': {'atomic_tests': [{'auto_generated_guid': '4238a7f0-a980-4fff-98a2-dfc0a363d507',
                                                            'description': 'Add '
                                                                           'a '
                                                                           'hidden '
                                                                           'user '
                                                                           'on '
                                                                           'MacOS\n',
                                                            'executor': {'command': 'sudo '
                                                                                    'dscl '
                                                                                    '. '
                                                                                    '-create '
                                                                                    '/Users/#{user_name} '
                                                                                    'UniqueID '
                                                                                    '333\n',
                                                                         'name': 'sh'},
                                                            'input_arguments': {'user_name': {'default': 'APT',
                                                                                              'description': 'username '
                                                                                                             'to '
                                                                                                             'add',
                                                                                              'type': 'string'}},
                                                            'name': 'Hidden '
                                                                    'Users',
                                                            'supported_platforms': ['macos']}],
                                          'attack_technique': 'T1147',
                                          'display_name': 'Hidden Users'}},
 {'Threat Hunting Tables': {'chain_id': '100196',
                            'commandline_string': 'sudo xattr -r -d '
                                                  'com.apple.quarantine '
                                                  '/path/to/*.app',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1147',
                            'mitre_caption': 'defense_evasion',
                            'os': 'mac',
                            'parent_process': 'bash',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors

None
