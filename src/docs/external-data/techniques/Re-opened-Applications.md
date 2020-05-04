
# Re-opened Applications

## Description

### MITRE Description

> Starting in Mac OS X 10.7 (Lion), users can specify certain applications to be re-opened when a user reboots their machine. While this is usually done via a Graphical User Interface (GUI) on an app-by-app basis, there are property list files (plist) that contain this information as well located at <code>~/Library/Preferences/com.apple.loginwindow.plist</code> and <code>~/Library/Preferences/ByHost/com.apple.loginwindow.* .plist</code>. 

An adversary can modify one of these files directly to include a link to their malicious executable to provide a persistence mechanism each time the user reboots their machine (Citation: Methods of Mac Malware Persistence).

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1164

## Potential Commands

```
sudo defaults write com.apple.loginwindow LoginHook /path/to/script
sudo defaults delete com.apple.loginwindow LoginHook

```

## Commands Dataset

```
[{'command': 'sudo defaults write com.apple.loginwindow LoginHook '
             '/path/to/script\n'
             'sudo defaults delete com.apple.loginwindow LoginHook\n',
  'name': None,
  'source': 'atomics/T1164/T1164.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Re-Opened Applications': {'atomic_tests': [{'description': 'Plist '
                                                                                     'Method\n'
                                                                                     '\n'
                                                                                     '[Reference](https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CustomLogin.html)\n',
                                                                      'executor': {'name': 'manual',
                                                                                   'steps': '1. '
                                                                                            'create '
                                                                                            'a '
                                                                                            'custom '
                                                                                            'plist:\n'
                                                                                            '\n'
                                                                                            '    '
                                                                                            '~/Library/Preferences/com.apple.loginwindow.plist\n'
                                                                                            '\n'
                                                                                            'or\n'
                                                                                            '\n'
                                                                                            '    '
                                                                                            '~/Library/Preferences/ByHost/com.apple.loginwindow.*.plist\n'},
                                                                      'name': 'Re-Opened '
                                                                              'Applications',
                                                                      'supported_platforms': ['macos']},
                                                                     {'description': 'Mac '
                                                                                     'Defaults\n'
                                                                                     '\n'
                                                                                     '[Reference](https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CustomLogin.html)\n',
                                                                      'executor': {'command': 'sudo '
                                                                                              'defaults '
                                                                                              'write '
                                                                                              'com.apple.loginwindow '
                                                                                              'LoginHook '
                                                                                              '#{script}\n'
                                                                                              'sudo '
                                                                                              'defaults '
                                                                                              'delete '
                                                                                              'com.apple.loginwindow '
                                                                                              'LoginHook\n',
                                                                                   'name': 'sh'},
                                                                      'input_arguments': {'script': {'default': '/path/to/script',
                                                                                                     'description': 'path '
                                                                                                                    'to '
                                                                                                                    'script',
                                                                                                     'type': 'path'}},
                                                                      'name': 'Re-Opened '
                                                                              'Applications',
                                                                      'supported_platforms': ['macos']}],
                                                    'attack_technique': 'T1164',
                                                    'display_name': 'Re-Opened '
                                                                    'Applications'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors

None
