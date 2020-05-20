
# Rc.common

## Description

### MITRE Description

> During the boot process, macOS executes <code>source /etc/rc.common</code>, which is a shell script containing various utility functions. This file also defines routines for processing command-line arguments and for gathering system settings, and is thus recommended to include in the start of Startup Item Scripts (Citation: Startup Items). In macOS and OS X, this is now a deprecated technique in favor of launch agents and launch daemons, but is currently still used.

Adversaries can use the rc.common file as a way to hide code for persistence that will execute on each reboot as the root user (Citation: Methods of Mac Malware Persistence).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['root']
* Platforms: ['macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1163

## Potential Commands

```
echo osascript -e 'tell app "Finder" to display dialog "Hello World"' >> /etc/rc.common

```

## Commands Dataset

```
[{'command': 'echo osascript -e \'tell app "Finder" to display dialog "Hello '
             'World"\' >> /etc/rc.common\n',
  'name': None,
  'source': 'atomics/T1163/T1163.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - rc.common': {'atomic_tests': [{'auto_generated_guid': '97a48daa-8bca-4bc0-b1a9-c1d163e762de',
                                                         'description': 'Modify '
                                                                        'rc.common\n'
                                                                        '\n'
                                                                        '[Reference](https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/StartupItems.html)\n',
                                                         'executor': {'command': 'echo '
                                                                                 'osascript '
                                                                                 '-e '
                                                                                 "'tell "
                                                                                 'app '
                                                                                 '"Finder" '
                                                                                 'to '
                                                                                 'display '
                                                                                 'dialog '
                                                                                 '"Hello '
                                                                                 'World"\' '
                                                                                 '>> '
                                                                                 '/etc/rc.common\n',
                                                                      'name': 'sh'},
                                                         'name': 'rc.common',
                                                         'supported_platforms': ['macos']}],
                                       'attack_technique': 'T1163',
                                       'display_name': 'rc.common'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors

None
