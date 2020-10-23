
# Launchd

## Description

### MITRE Description

> Adversaries may abuse the <code>Launchd</code> daemon to perform task scheduling for initial or recurring execution of malicious code. The <code>launchd</code> daemon, native to macOS, is responsible for loading and maintaining services within the operating system. This process loads the parameters for each launch-on-demand system-level daemon from the property list (plist) files found in <code>/System/Library/LaunchDaemons</code> and <code>/Library/LaunchDaemons</code> (Citation: AppleDocs Launch Agent Daemons). These LaunchDaemons have property list files which point to the executables that will be launched (Citation: Methods of Mac Malware Persistence).

An adversary may use the <code>launchd</code> daemon in macOS environments to schedule new executables to run at system startup or on a scheduled basis for persistence. <code>launchd</code> can also be abused to run a process under the context of a specified account. Daemons, such as <code>launchd</code>, run with the permissions of the root user account, and will operate regardless of which user account is logged in.

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
* Wiki: https://attack.mitre.org/techniques/T1053/004

## Potential Commands

```
sudo cp $PathToAtomicsFolder/T1053.004/src/atomicredteam_T1053_004.plist #{script_destination}
sudo touch /private/var/db/emondClients/#{empty_file}
sudo cp #{script_location} /etc/emond.d/rules/atomicredteam_T1053_004.plist
sudo touch /private/var/db/emondClients/#{empty_file}
sudo cp #{script_location} #{script_destination}
sudo touch /private/var/db/emondClients/randomflag
```

## Commands Dataset

```
[{'command': 'sudo cp '
             '$PathToAtomicsFolder/T1053.004/src/atomicredteam_T1053_004.plist '
             '#{script_destination}\n'
             'sudo touch /private/var/db/emondClients/#{empty_file}\n',
  'name': None,
  'source': 'atomics/T1053.004/T1053.004.yaml'},
 {'command': 'sudo cp #{script_location} '
             '/etc/emond.d/rules/atomicredteam_T1053_004.plist\n'
             'sudo touch /private/var/db/emondClients/#{empty_file}\n',
  'name': None,
  'source': 'atomics/T1053.004/T1053.004.yaml'},
 {'command': 'sudo cp #{script_location} #{script_destination}\n'
             'sudo touch /private/var/db/emondClients/randomflag\n',
  'name': None,
  'source': 'atomics/T1053.004/T1053.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Scheduled Task/Job: Launchd': {'atomic_tests': [{'auto_generated_guid': '11979f23-9b9d-482a-9935-6fc9cd022c3e',
                                                                           'description': 'This '
                                                                                          'test '
                                                                                          'adds '
                                                                                          'persistence '
                                                                                          'via '
                                                                                          'a '
                                                                                          'plist '
                                                                                          'to '
                                                                                          'execute '
                                                                                          'via '
                                                                                          'the '
                                                                                          'macOS '
                                                                                          'Event '
                                                                                          'Monitor '
                                                                                          'Daemon. \n',
                                                                           'executor': {'cleanup_command': 'sudo '
                                                                                                           'rm '
                                                                                                           '#{script_destination}\n'
                                                                                                           'sudo '
                                                                                                           'rm '
                                                                                                           '/private/var/db/emondClients/#{empty_file}\n',
                                                                                        'command': 'sudo '
                                                                                                   'cp '
                                                                                                   '#{script_location} '
                                                                                                   '#{script_destination}\n'
                                                                                                   'sudo '
                                                                                                   'touch '
                                                                                                   '/private/var/db/emondClients/#{empty_file}\n',
                                                                                        'elevation_required': True,
                                                                                        'name': 'bash'},
                                                                           'input_arguments': {'empty_file': {'default': 'randomflag',
                                                                                                              'description': 'Random '
                                                                                                                             'name '
                                                                                                                             'of '
                                                                                                                             'the '
                                                                                                                             'empty '
                                                                                                                             'file '
                                                                                                                             'used '
                                                                                                                             'to '
                                                                                                                             'trigger '
                                                                                                                             'emond '
                                                                                                                             'service',
                                                                                                              'type': 'string'},
                                                                                               'script_destination': {'default': '/etc/emond.d/rules/atomicredteam_T1053_004.plist',
                                                                                                                      'description': 'Path '
                                                                                                                                     'where '
                                                                                                                                     'to '
                                                                                                                                     'move '
                                                                                                                                     'the '
                                                                                                                                     'evil '
                                                                                                                                     'plist',
                                                                                                                      'type': 'path'},
                                                                                               'script_location': {'default': '$PathToAtomicsFolder/T1053.004/src/atomicredteam_T1053_004.plist',
                                                                                                                   'description': 'evil '
                                                                                                                                  'plist '
                                                                                                                                  'location',
                                                                                                                   'type': 'path'}},
                                                                           'name': 'Event '
                                                                                   'Monitor '
                                                                                   'Daemon '
                                                                                   'Persistence',
                                                                           'supported_platforms': ['macos']}],
                                                         'attack_technique': 'T1053.004',
                                                         'display_name': 'Scheduled '
                                                                         'Task/Job: '
                                                                         'Launchd'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)

* [Launch Daemon Mitigation](../mitigations/Launch-Daemon-Mitigation.md)
    
* [Audit](../mitigations/Audit.md)
    

# Actors

None
