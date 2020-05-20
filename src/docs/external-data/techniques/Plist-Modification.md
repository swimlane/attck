
# Plist Modification

## Description

### MITRE Description

> Property list (plist) files contain all of the information that macOS and OS X uses to configure applications and services. These files are UTF-8 encoded and formatted like XML documents via a series of keys surrounded by < >. They detail when programs should execute, file paths to the executables, program arguments, required OS permissions, and many others. plists are located in certain locations depending on their purpose such as <code>/Library/Preferences</code> (which execute with elevated privileges) and <code>~/Library/Preferences</code> (which execute with a user's privileges). 
Adversaries can modify these plist files to point to their own code, can use them to execute their code in the context of another user, bypass whitelisting procedures, or even use them as a persistence mechanism. (Citation: Sofacy Komplex Trojan)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application whitelisting', 'Process whitelisting', 'Whitelisting by file name or path']
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1150

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
[{'Atomic Red Team Test - Plist Modification': {'atomic_tests': [{'auto_generated_guid': '394a538e-09bb-4a4a-95d1-b93cf12682a8',
                                                                  'description': 'Modify '
                                                                                 'MacOS '
                                                                                 'plist '
                                                                                 'file '
                                                                                 'in '
                                                                                 'one '
                                                                                 'of '
                                                                                 'two '
                                                                                 'directories\n',
                                                                  'executor': {'name': 'manual',
                                                                               'steps': '1. '
                                                                                        'Modify '
                                                                                        'a '
                                                                                        '.plist '
                                                                                        'in\n'
                                                                                        '\n'
                                                                                        '    '
                                                                                        '/Library/Preferences\n'
                                                                                        '\n'
                                                                                        '    '
                                                                                        'OR\n'
                                                                                        '\n'
                                                                                        '    '
                                                                                        '~/Library/Preferences\n'
                                                                                        '\n'
                                                                                        '2. '
                                                                                        'Subsequently, '
                                                                                        'follow '
                                                                                        'the '
                                                                                        'steps '
                                                                                        'for '
                                                                                        'adding '
                                                                                        'and '
                                                                                        'running '
                                                                                        'via '
                                                                                        '[Launch '
                                                                                        'Agent](Persistence/Launch_Agent.md)\n'},
                                                                  'name': 'Plist '
                                                                          'Modification',
                                                                  'supported_platforms': ['macos']}],
                                                'attack_technique': 'T1150',
                                                'display_name': 'Plist '
                                                                'Modification'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors

None
