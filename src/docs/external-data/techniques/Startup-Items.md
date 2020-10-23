
# Startup Items

## Description

### MITRE Description

> Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items. (Citation: Startup Items)

This is technically a deprecated technology (superseded by [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)), and thus the appropriate folder, <code>/Library/StartupItems</code> isn’t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra. A startup item is a directory whose executable and configuration property list (plist), <code>StartupParameters.plist</code>, reside in the top-level directory. 

An adversary can create the appropriate folders/files in the StartupItems directory to register their own persistence mechanism (Citation: Methods of Mac Malware Persistence). Additionally, since StartupItems run during the bootup phase of macOS, they will run as the elevated root user.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1037/005

## Potential Commands

```
sudo touch /Library/StartupItems/EvilStartup.plist
```

## Commands Dataset

```
[{'command': 'sudo touch /Library/StartupItems/EvilStartup.plist\n',
  'name': None,
  'source': 'atomics/T1037.005/T1037.005.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Boot or Logon Initialization Scripts: Startup Items': {'atomic_tests': [{'auto_generated_guid': '134627c3-75db-410e-bff8-7a920075f198',
                                                                                                   'description': 'Modify '
                                                                                                                  'or '
                                                                                                                  'create '
                                                                                                                  'an '
                                                                                                                  'file '
                                                                                                                  'in '
                                                                                                                  '/Library/StartupItems\n'
                                                                                                                  '\n'
                                                                                                                  '[Reference](https://www.alienvault.com/blogs/labs-research/diversity-in-recent-mac-malware)\n',
                                                                                                   'executor': {'cleanup_command': 'sudo '
                                                                                                                                   'rm '
                                                                                                                                   '/Library/StartupItems/EvilStartup.plist\n',
                                                                                                                'command': 'sudo '
                                                                                                                           'touch '
                                                                                                                           '/Library/StartupItems/EvilStartup.plist\n',
                                                                                                                'elevation_required': True,
                                                                                                                'name': 'sh'},
                                                                                                   'name': 'Add '
                                                                                                           'file '
                                                                                                           'to '
                                                                                                           'Local '
                                                                                                           'Library '
                                                                                                           'StartupItems',
                                                                                                   'supported_platforms': ['macos']}],
                                                                                 'attack_technique': 'T1037.005',
                                                                                 'display_name': 'Boot '
                                                                                                 'or '
                                                                                                 'Logon '
                                                                                                 'Initialization '
                                                                                                 'Scripts: '
                                                                                                 'Startup '
                                                                                                 'Items'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)


# Actors

None
