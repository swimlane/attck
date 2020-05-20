
# Launch Daemon

## Description

### MITRE Description

> Per Apple’s developer documentation, when macOS and OS X boot up, launchd is run to finish system initialization. This process loads the parameters for each launch-on-demand system-level daemon from the property list (plist) files found in <code>/System/Library/LaunchDaemons</code> and <code>/Library/LaunchDaemons</code> (Citation: AppleDocs Launch Agent Daemons). These LaunchDaemons have property list files which point to the executables that will be launched (Citation: Methods of Mac Malware Persistence).
 
Adversaries may install a new launch daemon that can be configured to execute at startup by using launchd or launchctl to load a plist into the appropriate directories (Citation: OSX Malware Detection). The daemon name may be disguised by using a name from a related operating system or benign software  (Citation: WireLurker). Launch Daemons may be created with administrator privileges, but are executed under root privileges, so an adversary may also use a service to escalate privileges from administrator to root.
 
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
* Wiki: https://attack.mitre.org/techniques/T1160

## Potential Commands

```
python/persistence/osx/launchdaemonexecutable
python/persistence/osx/launchdaemonexecutable
```

## Commands Dataset

```
[{'command': 'python/persistence/osx/launchdaemonexecutable',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/persistence/osx/launchdaemonexecutable',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Launch Daemon': {'atomic_tests': [{'auto_generated_guid': '03ab8df5-3a6b-4417-b6bd-bb7a5cfd74cf',
                                                             'description': 'Utilize '
                                                                            'LaunchDaemon '
                                                                            'to '
                                                                            'launch '
                                                                            '`Hello '
                                                                            'World`\n',
                                                             'executor': {'name': 'manual',
                                                                          'steps': '1. '
                                                                                   'Place '
                                                                                   'the '
                                                                                   'following '
                                                                                   'file '
                                                                                   '(com.example.hello) '
                                                                                   'in '
                                                                                   '/System/Library/LaunchDaemons '
                                                                                   'or '
                                                                                   '/Library/LaunchDaemons\n'
                                                                                   '2.\n'
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
                                                                                   '    '
                                                                                   '<key>Label</key>\n'
                                                                                   '    '
                                                                                   '<string>com.example.hello</string>\n'
                                                                                   '    '
                                                                                   '<key>ProgramArguments</key>\n'
                                                                                   '    '
                                                                                   '<array>\n'
                                                                                   '        '
                                                                                   '<string>hello</string>\n'
                                                                                   '        '
                                                                                   '<string>world</string>\n'
                                                                                   '    '
                                                                                   '</array>\n'
                                                                                   '    '
                                                                                   '<key>KeepAlive</key>\n'
                                                                                   '    '
                                                                                   '<true/>\n'
                                                                                   '</dict>\n'
                                                                                   '</plist>\n'},
                                                             'name': 'Launch '
                                                                     'Daemon',
                                                             'supported_platforms': ['macos']}],
                                           'attack_technique': 'T1160',
                                           'display_name': 'Launch Daemon'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1160',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/persistence/osx/launchdaemonexecutable":  '
                                                                                 '["T1160"],',
                                            'Empire Module': 'python/persistence/osx/launchdaemonexecutable',
                                            'Technique': 'Launch Daemon'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors

None
