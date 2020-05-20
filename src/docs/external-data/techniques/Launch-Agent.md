
# Launch Agent

## Description

### MITRE Description

> Per Apple’s developer documentation, when a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (plist) files found in <code>/System/Library/LaunchAgents</code>, <code>/Library/LaunchAgents</code>, and <code>$HOME/Library/LaunchAgents</code> (Citation: AppleDocs Launch Agent Daemons) (Citation: OSX Keydnap malware) (Citation: Antiquated Mac Malware). These launch agents have property list files which point to the executables that will be launched (Citation: OSX.Dok Malware).
 
Adversaries may install a new launch agent that can be configured to execute at login by using launchd or launchctl to load a plist into the appropriate directories  (Citation: Sofacy Komplex Trojan)  (Citation: Methods of Mac Malware Persistence). The agent name may be disguised by using a name from a related operating system or benign software. Launch Agents are created with user level privileges and are executed with the privileges of the user when they log in (Citation: OSX Malware Detection) (Citation: OceanLotus for OS X). They can be set up to execute when a specific user logs in (in the specific user’s directory structure) or when any user logs in (which requires administrator privileges).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1159

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
[{'Atomic Red Team Test - Launch Agent': {'atomic_tests': [{'auto_generated_guid': 'a5983dee-bf6c-4eaf-951c-dbc1a7b90900',
                                                            'description': 'Create '
                                                                           'a '
                                                                           'plist '
                                                                           'and '
                                                                           'execute '
                                                                           'it\n',
                                                            'executor': {'name': 'manual',
                                                                         'steps': '1. '
                                                                                  'Create '
                                                                                  'file '
                                                                                  '- '
                                                                                  '.client\n'
                                                                                  '\n'
                                                                                  '2. '
                                                                                  'osascript '
                                                                                  '-e '
                                                                                  "'tell "
                                                                                  'app '
                                                                                  '"Finder" '
                                                                                  'to '
                                                                                  'display '
                                                                                  'dialog '
                                                                                  '"Hello '
                                                                                  'World"\'\n'
                                                                                  '\n'
                                                                                  '3. '
                                                                                  'Place '
                                                                                  'the '
                                                                                  'following '
                                                                                  'in '
                                                                                  'a '
                                                                                  'new '
                                                                                  'file '
                                                                                  'under '
                                                                                  '~/Library/LaunchAgents '
                                                                                  'as '
                                                                                  'com.atomicredteam.plist\n'
                                                                                  '\n'
                                                                                  '4.\n'
                                                                                  '<?xml '
                                                                                  'version="1.0" '
                                                                                  'encoding="UTF-8"?>\n'
                                                                                  '<!DOCTYPE '
                                                                                  'plist '
                                                                                  'PUBLIC '
                                                                                  '"-//Apple//DTD '
                                                                                  'PLIST '
                                                                                  '1.0//EN" '
                                                                                  '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                                                                                  '<plist '
                                                                                  'version="1.0">\n'
                                                                                  '<dict>\n'
                                                                                  ' '
                                                                                  '<key>KeepAlive</key>\n'
                                                                                  ' '
                                                                                  '<true/>\n'
                                                                                  ' '
                                                                                  '<key>Label</key>\n'
                                                                                  ' '
                                                                                  '<string>com.client.client</string>\n'
                                                                                  ' '
                                                                                  '<key>ProgramArguments</key>\n'
                                                                                  ' '
                                                                                  '<array>\n'
                                                                                  ' '
                                                                                  '<string>/Users/<update '
                                                                                  'path '
                                                                                  'to '
                                                                                  '.clent '
                                                                                  'file>/.client</string>\n'
                                                                                  ' '
                                                                                  '</array>\n'
                                                                                  ' '
                                                                                  '<key>RunAtLoad</key>\n'
                                                                                  ' '
                                                                                  '<true/>\n'
                                                                                  ' '
                                                                                  '<key>NSUIElement</key>\n'
                                                                                  ' '
                                                                                  '<string>1</string>\n'
                                                                                  '</dict>\n'
                                                                                  '</plist>\n'
                                                                                  '\n'
                                                                                  '5. '
                                                                                  'launchctl '
                                                                                  'load '
                                                                                  '-w '
                                                                                  '~/Library/LaunchAgents/com.atomicredteam.plist\n'},
                                                            'name': 'Launch '
                                                                    'Agent',
                                                            'supported_platforms': ['macos']}],
                                          'attack_technique': 'T1159',
                                          'display_name': 'Launch Agent'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors

None
