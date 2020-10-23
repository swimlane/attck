
# Logon Script (Mac)

## Description

### MITRE Description

> Adversaries may use macOS logon scripts automatically executed at logon initialization to establish persistence. macOS allows logon scripts (known as login hooks) to be executed whenever a specific user logs into a system. A login hook tells Mac OS X to execute a certain script when a user logs in, but unlike [Startup Items](https://attack.mitre.org/techniques/T1037/005), a login hook executes as the elevated root user.(Citation: creating login hook)

Adversaries may use these login hooks to maintain persistence on a single system.(Citation: S1 macOs Persistence) Access to login hook scripts may allow an adversary to insert additional malicious code. There can only be one login hook at a time though and depending on the access configuration of the hooks, either local credentials or an administrator account may be necessary. 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1037/002

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Boot or Logon Initialization Scripts: Logon Script (Mac)': {'atomic_tests': [{'auto_generated_guid': 'f047c7de-a2d9-406e-a62b-12a09d9516f4',
                                                                                                        'description': 'Mac '
                                                                                                                       'logon '
                                                                                                                       'script\n',
                                                                                                        'executor': {'name': 'manual',
                                                                                                                     'steps': '1. '
                                                                                                                              'Create '
                                                                                                                              'the '
                                                                                                                              'required '
                                                                                                                              'plist '
                                                                                                                              'file\n'
                                                                                                                              '\n'
                                                                                                                              '    '
                                                                                                                              'sudo '
                                                                                                                              'touch '
                                                                                                                              '/private/var/root/Library/Preferences/com.apple.loginwindow.plist\n'
                                                                                                                              '\n'
                                                                                                                              '2. '
                                                                                                                              'Populate '
                                                                                                                              'the '
                                                                                                                              'plist '
                                                                                                                              'with '
                                                                                                                              'the '
                                                                                                                              'location '
                                                                                                                              'of '
                                                                                                                              'your '
                                                                                                                              'shell '
                                                                                                                              'script\n'
                                                                                                                              '\n'
                                                                                                                              '    '
                                                                                                                              'sudo '
                                                                                                                              'defaults '
                                                                                                                              'write '
                                                                                                                              'com.apple.loginwindow '
                                                                                                                              'LoginHook '
                                                                                                                              '/Library/Scripts/AtomicRedTeam.sh\n'
                                                                                                                              '\n'
                                                                                                                              '3. '
                                                                                                                              'Create '
                                                                                                                              'the '
                                                                                                                              'required '
                                                                                                                              'plist '
                                                                                                                              'file '
                                                                                                                              'in '
                                                                                                                              'the '
                                                                                                                              'target '
                                                                                                                              "user's "
                                                                                                                              'Preferences '
                                                                                                                              'directory\n'
                                                                                                                              '\n'
                                                                                                                              '\t  '
                                                                                                                              'touch '
                                                                                                                              '/Users/$USER/Library/Preferences/com.apple.loginwindow.plist\n'
                                                                                                                              '\n'
                                                                                                                              '4. '
                                                                                                                              'Populate '
                                                                                                                              'the '
                                                                                                                              'plist '
                                                                                                                              'with '
                                                                                                                              'the '
                                                                                                                              'location '
                                                                                                                              'of '
                                                                                                                              'your '
                                                                                                                              'shell '
                                                                                                                              'script\n'
                                                                                                                              '\n'
                                                                                                                              '\t  '
                                                                                                                              'defaults '
                                                                                                                              'write '
                                                                                                                              'com.apple.loginwindow '
                                                                                                                              'LoginHook '
                                                                                                                              '/Library/Scripts/AtomicRedTeam.sh\n'},
                                                                                                        'name': 'Logon '
                                                                                                                'Scripts '
                                                                                                                '- '
                                                                                                                'Mac',
                                                                                                        'supported_platforms': ['macos']}],
                                                                                      'attack_technique': 'T1037.002',
                                                                                      'display_name': 'Boot '
                                                                                                      'or '
                                                                                                      'Logon '
                                                                                                      'Initialization '
                                                                                                      'Scripts: '
                                                                                                      'Logon '
                                                                                                      'Script '
                                                                                                      '(Mac)'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)


# Actors

None
