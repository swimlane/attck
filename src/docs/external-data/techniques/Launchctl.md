
# Launchctl

## Description

### MITRE Description

> Adversaries may abuse launchctl to execute commands or programs. Launchctl controls the macOS launchd process, which handles things like [Launch Agent](https://attack.mitre.org/techniques/T1543/001)s and [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)s, but can execute other commands or programs itself. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input.(Citation: Launchctl Man)

By loading or reloading [Launch Agent](https://attack.mitre.org/techniques/T1543/001)s or [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)s, adversaries can install persistence or execute changes they made.(Citation: Sofacy Komplex Trojan)

Running a command from launchctl is as simple as <code>launchctl submit -l <labelName> -- /Path/to/thing/to/execute "arg" "arg" "arg"</code>. Adversaries can abuse this functionality to execute code or even bypass application control if launchctl is an allowed process.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'root']
* Platforms: ['macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1569/001

## Potential Commands

```
launchctl submit -l #{label_name} -- /System/Applications/Calculator.app/Contents/MacOS/Calculator
launchctl submit -l evil -- #{executable_path}
```

## Commands Dataset

```
[{'command': 'launchctl submit -l #{label_name} -- '
             '/System/Applications/Calculator.app/Contents/MacOS/Calculator\n',
  'name': None,
  'source': 'atomics/T1569.001/T1569.001.yaml'},
 {'command': 'launchctl submit -l evil -- #{executable_path}\n',
  'name': None,
  'source': 'atomics/T1569.001/T1569.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - System Services: Launchctl': {'atomic_tests': [{'auto_generated_guid': '6fb61988-724e-4755-a595-07743749d4e2',
                                                                          'description': 'Utilize '
                                                                                         'launchctl\n',
                                                                          'executor': {'cleanup_command': 'launchctl '
                                                                                                          'remove '
                                                                                                          '#{label_name}\n',
                                                                                       'command': 'launchctl '
                                                                                                  'submit '
                                                                                                  '-l '
                                                                                                  '#{label_name} '
                                                                                                  '-- '
                                                                                                  '#{executable_path}\n',
                                                                                       'name': 'bash'},
                                                                          'input_arguments': {'executable_path': {'default': '/System/Applications/Calculator.app/Contents/MacOS/Calculator',
                                                                                                                  'description': 'Path '
                                                                                                                                 'of '
                                                                                                                                 'the '
                                                                                                                                 'executable '
                                                                                                                                 'to '
                                                                                                                                 'run.',
                                                                                                                  'type': 'path'},
                                                                                              'label_name': {'default': 'evil',
                                                                                                             'description': 'Path '
                                                                                                                            'of '
                                                                                                                            'the '
                                                                                                                            'executable '
                                                                                                                            'to '
                                                                                                                            'run.',
                                                                                                             'type': 'string'}},
                                                                          'name': 'Launchctl',
                                                                          'supported_platforms': ['macos']}],
                                                        'attack_technique': 'T1569.001',
                                                        'display_name': 'System '
                                                                        'Services: '
                                                                        'Launchctl'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)


# Actors

None
