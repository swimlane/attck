
# Launch Daemon

## Description

### MITRE Description

> Adversaries may create or modify launch daemons to repeatedly execute malicious payloads as part of persistence. Per Apple’s developer documentation, when macOS and OS X boot up, launchd is run to finish system initialization. This process loads the parameters for each launch-on-demand system-level daemon from the property list (plist) files found in <code>/System/Library/LaunchDaemons</code> and <code>/Library/LaunchDaemons</code> (Citation: AppleDocs Launch Agent Daemons). These LaunchDaemons have property list files which point to the executables that will be launched (Citation: Methods of Mac Malware Persistence). 

Adversaries may install a new launch daemon that can be configured to execute at startup by using launchd or launchctl to load a plist into the appropriate directories  (Citation: OSX Malware Detection). The daemon name may be disguised by using a name from a related operating system or benign software (Citation: WireLurker). Launch Daemons may be created with administrator privileges, but are executed under root privileges, so an adversary may also use a service to escalate privileges from administrator to root. 

The plist file permissions must be root:wheel, but the script or program that it points to has no such requirement. So, it is possible for poor configurations to allow an adversary to modify a current Launch Daemon’s executable and gain persistence or Privilege Escalation. 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: ['root']
* Network: None
* Permissions: ['Administrator']
* Platforms: ['macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1543/004

## Potential Commands

```
sudo cp $PathToAtomicsFolder/T1543.004/src/atomicredteam_T1543_004.plist /Library/LaunchDaemons/#{plist_filename}
sudo launchctl load -w /Library/LaunchDaemons/#{plist_filename}
sudo cp #{path_malicious_plist} /Library/LaunchDaemons/com.atomicredteam.plist
sudo launchctl load -w /Library/LaunchDaemons/com.atomicredteam.plist
```

## Commands Dataset

```
[{'command': 'sudo cp #{path_malicious_plist} '
             '/Library/LaunchDaemons/com.atomicredteam.plist\n'
             'sudo launchctl load -w '
             '/Library/LaunchDaemons/com.atomicredteam.plist\n',
  'name': None,
  'source': 'atomics/T1543.004/T1543.004.yaml'},
 {'command': 'sudo cp '
             '$PathToAtomicsFolder/T1543.004/src/atomicredteam_T1543_004.plist '
             '/Library/LaunchDaemons/#{plist_filename}\n'
             'sudo launchctl load -w '
             '/Library/LaunchDaemons/#{plist_filename}\n',
  'name': None,
  'source': 'atomics/T1543.004/T1543.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Create or Modify System Process: Launch Daemon': {'atomic_tests': [{'auto_generated_guid': '03ab8df5-3a6b-4417-b6bd-bb7a5cfd74cf',
                                                                                              'dependencies': [{'description': 'The '
                                                                                                                               'shared '
                                                                                                                               'library '
                                                                                                                               'must '
                                                                                                                               'exist '
                                                                                                                               'on '
                                                                                                                               'disk '
                                                                                                                               'at '
                                                                                                                               'specified '
                                                                                                                               'location '
                                                                                                                               '(#{path_malicious_plist})\n',
                                                                                                                'get_prereq_command': 'echo '
                                                                                                                                      '"The '
                                                                                                                                      'plist '
                                                                                                                                      'file '
                                                                                                                                      "doesn't "
                                                                                                                                      'exist. '
                                                                                                                                      'Check '
                                                                                                                                      'the '
                                                                                                                                      'path '
                                                                                                                                      'and '
                                                                                                                                      'try '
                                                                                                                                      'again."; '
                                                                                                                                      'exit '
                                                                                                                                      '1;\n',
                                                                                                                'prereq_command': 'if '
                                                                                                                                  '[ '
                                                                                                                                  '-f '
                                                                                                                                  '#{path_malicious_plist} '
                                                                                                                                  ']; '
                                                                                                                                  'then '
                                                                                                                                  'exit '
                                                                                                                                  '0; '
                                                                                                                                  'else '
                                                                                                                                  'exit '
                                                                                                                                  '1; '
                                                                                                                                  'fi;\n'}],
                                                                                              'dependency_executor_name': 'bash',
                                                                                              'description': 'Utilize '
                                                                                                             'LaunchDaemon '
                                                                                                             'to '
                                                                                                             'launch '
                                                                                                             '`Hello '
                                                                                                             'World`\n',
                                                                                              'executor': {'cleanup': 'sudo '
                                                                                                                      'launchctl '
                                                                                                                      'unload '
                                                                                                                      '/Library/LaunchDaemons/#{plist_filename}\n'
                                                                                                                      'sudo '
                                                                                                                      'rm '
                                                                                                                      '/Library/LaunchDaemons/#{plist_filename}\n',
                                                                                                           'command': 'sudo '
                                                                                                                      'cp '
                                                                                                                      '#{path_malicious_plist} '
                                                                                                                      '/Library/LaunchDaemons/#{plist_filename}\n'
                                                                                                                      'sudo '
                                                                                                                      'launchctl '
                                                                                                                      'load '
                                                                                                                      '-w '
                                                                                                                      '/Library/LaunchDaemons/#{plist_filename}\n',
                                                                                                           'elevation_required': True,
                                                                                                           'name': 'bash'},
                                                                                              'input_arguments': {'path_malicious_plist': {'default': '$PathToAtomicsFolder/T1543.004/src/atomicredteam_T1543_004.plist',
                                                                                                                                           'description': 'Name '
                                                                                                                                                          'of '
                                                                                                                                                          'file '
                                                                                                                                                          'to '
                                                                                                                                                          'store '
                                                                                                                                                          'in '
                                                                                                                                                          'cron '
                                                                                                                                                          'folder',
                                                                                                                                           'type': 'string'},
                                                                                                                  'plist_filename': {'default': 'com.atomicredteam.plist',
                                                                                                                                     'description': 'filename',
                                                                                                                                     'type': 'string'}},
                                                                                              'name': 'Launch '
                                                                                                      'Daemon',
                                                                                              'supported_platforms': ['macos']}],
                                                                            'attack_technique': 'T1543.004',
                                                                            'display_name': 'Create '
                                                                                            'or '
                                                                                            'Modify '
                                                                                            'System '
                                                                                            'Process: '
                                                                                            'Launch '
                                                                                            'Daemon'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)


# Actors

None
