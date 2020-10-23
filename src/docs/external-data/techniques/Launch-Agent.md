
# Launch Agent

## Description

### MITRE Description

> Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence. Per Apple’s developer documentation, when a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (plist) files found in <code>/System/Library/LaunchAgents</code>, <code>/Library/LaunchAgents</code>, and <code>$HOME/Library/LaunchAgents</code> (Citation: AppleDocs Launch Agent Daemons) (Citation: OSX Keydnap malware) (Citation: Antiquated Mac Malware). These launch agents have property list files which point to the executables that will be launched (Citation: OSX.Dok Malware).
 
Adversaries may install a new launch agent that can be configured to execute at login by using launchd or launchctl to load a plist into the appropriate directories  (Citation: Sofacy Komplex Trojan)  (Citation: Methods of Mac Malware Persistence). The agent name may be disguised by using a name from a related operating system or benign software. Launch Agents are created with user level privileges and are executed with the privileges of the user when they log in (Citation: OSX Malware Detection) (Citation: OceanLotus for OS X). They can be set up to execute when a specific user logs in (in the specific user’s directory structure) or when any user logs in (which requires administrator privileges).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1543/001

## Potential Commands

```
if [ ! -d ~/Library/LaunchAgents ]; then mkdir ~/Library/LaunchAgents; fi;
sudo cp $PathToAtomicsFolder/T1543.001/src/atomicredteam_T1543_001.plist ~/Library/LaunchAgents/#{plist_filename}
sudo launchctl load -w ~/Library/LaunchAgents/#{plist_filename}
if [ ! -d ~/Library/LaunchAgents ]; then mkdir ~/Library/LaunchAgents; fi;
sudo cp #{path_malicious_plist} ~/Library/LaunchAgents/com.atomicredteam.plist
sudo launchctl load -w ~/Library/LaunchAgents/com.atomicredteam.plist
```

## Commands Dataset

```
[{'command': 'if [ ! -d ~/Library/LaunchAgents ]; then mkdir '
             '~/Library/LaunchAgents; fi;\n'
             'sudo cp #{path_malicious_plist} '
             '~/Library/LaunchAgents/com.atomicredteam.plist\n'
             'sudo launchctl load -w '
             '~/Library/LaunchAgents/com.atomicredteam.plist\n',
  'name': None,
  'source': 'atomics/T1543.001/T1543.001.yaml'},
 {'command': 'if [ ! -d ~/Library/LaunchAgents ]; then mkdir '
             '~/Library/LaunchAgents; fi;\n'
             'sudo cp '
             '$PathToAtomicsFolder/T1543.001/src/atomicredteam_T1543_001.plist '
             '~/Library/LaunchAgents/#{plist_filename}\n'
             'sudo launchctl load -w '
             '~/Library/LaunchAgents/#{plist_filename}\n',
  'name': None,
  'source': 'atomics/T1543.001/T1543.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Create or Modify System Process: Launch Agent': {'atomic_tests': [{'auto_generated_guid': 'a5983dee-bf6c-4eaf-951c-dbc1a7b90900',
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
                                                                                                                                     'shared '
                                                                                                                                     'library '
                                                                                                                                     "doesn't "
                                                                                                                                     'exist. '
                                                                                                                                     'Check '
                                                                                                                                     'the '
                                                                                                                                     'path"; '
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
                                                                                             'description': 'Create '
                                                                                                            'a '
                                                                                                            'plist '
                                                                                                            'and '
                                                                                                            'execute '
                                                                                                            'it\n',
                                                                                             'executor': {'cleanup': 'sudo '
                                                                                                                     'launchctl '
                                                                                                                     'unload '
                                                                                                                     '~/Library/LaunchAgents/#{plist_filename}\n'
                                                                                                                     'sudo '
                                                                                                                     'rm '
                                                                                                                     '~/Library/LaunchAgents/#{plist_filename}\n',
                                                                                                          'command': 'if '
                                                                                                                     '[ '
                                                                                                                     '! '
                                                                                                                     '-d '
                                                                                                                     '~/Library/LaunchAgents '
                                                                                                                     ']; '
                                                                                                                     'then '
                                                                                                                     'mkdir '
                                                                                                                     '~/Library/LaunchAgents; '
                                                                                                                     'fi;\n'
                                                                                                                     'sudo '
                                                                                                                     'cp '
                                                                                                                     '#{path_malicious_plist} '
                                                                                                                     '~/Library/LaunchAgents/#{plist_filename}\n'
                                                                                                                     'sudo '
                                                                                                                     'launchctl '
                                                                                                                     'load '
                                                                                                                     '-w '
                                                                                                                     '~/Library/LaunchAgents/#{plist_filename}\n',
                                                                                                          'elevation_required': True,
                                                                                                          'name': 'bash'},
                                                                                             'input_arguments': {'path_malicious_plist': {'default': '$PathToAtomicsFolder/T1543.001/src/atomicredteam_T1543_001.plist',
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
                                                                                                     'Agent',
                                                                                             'supported_platforms': ['macos']}],
                                                                           'attack_technique': 'T1543.001',
                                                                           'display_name': 'Create '
                                                                                           'or '
                                                                                           'Modify '
                                                                                           'System '
                                                                                           'Process: '
                                                                                           'Launch '
                                                                                           'Agent'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)


# Actors

None
