
# Space after Filename

## Description

### MITRE Description

> Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the operating system.

For example, if there is a Mach-O executable file called <code>evil.bin</code>, when it is double clicked by a user, it will launch Terminal.app and execute. If this file is renamed to <code>evil.txt</code>, then when double clicked by a user, it will launch with the default text editing application (not executing the binary). However, if the file is renamed to <code>evil.txt </code> (note the space at the end), then when double clicked by a user, the true file type is determined by the OS and handled appropriately and the binary will be executed (Citation: Mac Backdoors are back).

Adversaries can use this feature to trick users into double clicking benign-looking files of any format and ultimately executing something malicious.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1036/006

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
[{'Atomic Red Team Test - Masquerading: Space after Filename': {'atomic_tests': [{'auto_generated_guid': '89a7dd26-e510-4c9f-9b15-f3bae333360f',
                                                                                  'description': 'Space '
                                                                                                 'After '
                                                                                                 'Filename\n',
                                                                                  'executor': {'name': 'manual',
                                                                                               'steps': '1. '
                                                                                                        '1. '
                                                                                                        'echo '
                                                                                                        "'#!/bin/bash\\necho "
                                                                                                        '"print '
                                                                                                        '\\"hello, '
                                                                                                        'world!\\"" '
                                                                                                        '| '
                                                                                                        "/usr/bin/python\\nexit' "
                                                                                                        '> '
                                                                                                        'execute.txt '
                                                                                                        '&& '
                                                                                                        'chmod '
                                                                                                        '+x '
                                                                                                        'execute.txt\n'
                                                                                                        '\n'
                                                                                                        '2. '
                                                                                                        'mv '
                                                                                                        'execute.txt '
                                                                                                        '"execute.txt '
                                                                                                        '"\n'
                                                                                                        '\n'
                                                                                                        '3. '
                                                                                                        './execute.txt\\ \n'},
                                                                                  'name': 'Space '
                                                                                          'After '
                                                                                          'Filename',
                                                                                  'supported_platforms': ['macos']}],
                                                                'attack_technique': 'T1036.006',
                                                                'display_name': 'Masquerading: '
                                                                                'Space '
                                                                                'after '
                                                                                'Filename'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors

None
