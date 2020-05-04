
# Launchctl

## Description

### MITRE Description

> Launchctl controls the macOS launchd process which handles things like launch agents and launch daemons, but can execute other commands or programs itself. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input. By loading or reloading launch agents or launch daemons, adversaries can install persistence or execute changes they made  (Citation: Sofacy Komplex Trojan). Running a command from launchctl is as simple as <code>launchctl submit -l <labelName> -- /Path/to/thing/to/execute "arg" "arg" "arg"</code>. Loading, unloading, or reloading launch agents or launch daemons can require elevated privileges. 

Adversaries can abuse this functionality to execute code or even bypass whitelisting if launchctl is an allowed process.

## Additional Attributes

* Bypass: ['Application whitelisting', 'Process whitelisting', 'Whitelisting by file name or path']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1152

## Potential Commands

```
launchctl submit -l evil -- /Applications/Calculator.app/Contents/MacOS/Calculator

```

## Commands Dataset

```
[{'command': 'launchctl submit -l evil -- '
             '/Applications/Calculator.app/Contents/MacOS/Calculator\n',
  'name': None,
  'source': 'atomics/T1152/T1152.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Launchctl': {'atomic_tests': [{'description': 'Utilize '
                                                                        'launchctl\n',
                                                         'executor': {'command': 'launchctl '
                                                                                 'submit '
                                                                                 '-l '
                                                                                 'evil '
                                                                                 '-- '
                                                                                 '/Applications/Calculator.app/Contents/MacOS/Calculator\n',
                                                                      'name': 'sh'},
                                                         'name': 'Launchctl',
                                                         'supported_platforms': ['macos']}],
                                       'attack_technique': 'T1152',
                                       'display_name': 'Launchctl'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Execution](../tactics/Execution.md)
    
* [Persistence](../tactics/Persistence.md)
    

# Mitigations

None

# Actors

None
