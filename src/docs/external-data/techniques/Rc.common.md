
# Rc.common

## Description

### MITRE Description

> Adversaries may use rc.common automatically executed at boot initialization to establish persistence. During the boot process, macOS executes <code>source /etc/rc.common</code>, which is a shell script containing various utility functions. This file also defines routines for processing command-line arguments and for gathering system settings and is thus recommended to include in the start of Startup Item Scripts (Citation: Startup Items). In macOS and OS X, this is now a deprecated mechanism in favor of [Launch Agent](https://attack.mitre.org/techniques/T1543/001) and [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) but is currently still used.

Adversaries can use the rc.common file as a way to hide code for persistence that will execute on each reboot as the root user. (Citation: Methods of Mac Malware Persistence)

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
* Wiki: https://attack.mitre.org/techniques/T1037/004

## Potential Commands

```
sudo echo osascript -e 'tell app "Finder" to display dialog "Hello World"' >> /etc/rc.common
```

## Commands Dataset

```
[{'command': 'sudo echo osascript -e \'tell app "Finder" to display dialog '
             '"Hello World"\' >> /etc/rc.common\n',
  'name': None,
  'source': 'atomics/T1037.004/T1037.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Boot or Logon Initialization Scripts: Rc.common': {'atomic_tests': [{'auto_generated_guid': '97a48daa-8bca-4bc0-b1a9-c1d163e762de',
                                                                                               'description': 'Modify '
                                                                                                              'rc.common\n'
                                                                                                              '\n'
                                                                                                              '[Reference](https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/StartupItems.html)\n',
                                                                                               'executor': {'command': 'sudo '
                                                                                                                       'echo '
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
                                                                                                            'elevation_required': True,
                                                                                                            'name': 'bash'},
                                                                                               'name': 'rc.common',
                                                                                               'supported_platforms': ['macos']}],
                                                                             'attack_technique': 'T1037.004',
                                                                             'display_name': 'Boot '
                                                                                             'or '
                                                                                             'Logon '
                                                                                             'Initialization '
                                                                                             'Scripts: '
                                                                                             'Rc.common'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)


# Actors

None
