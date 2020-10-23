
# Trap

## Description

### MITRE Description

> Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The <code>trap</code> command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like <code>ctrl+c</code> and <code>ctrl+d</code>.

Adversaries can use this to register code to be executed when the shell encounters specific interrupts as a persistence mechanism. Trap commands are of the following format <code>trap 'command list' signals</code> where "command list" will be executed when "signals" are received.(Citation: Trap Manual)(Citation: Cyberciti Trap Statements)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['macOS', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1546/005

## Potential Commands

```
trap "nohup sh $PathToAtomicsFolder/T1546.005/src/echo-art-fish.sh | bash" EXIT
exit
trap "nohup sh $PathToAtomicsFolder/T1546.005/src/echo-art-fish.sh | bash" SIGINt
```

## Commands Dataset

```
[{'command': 'trap "nohup sh '
             '$PathToAtomicsFolder/T1546.005/src/echo-art-fish.sh | bash" '
             'EXIT\n'
             'exit\n'
             'trap "nohup sh '
             '$PathToAtomicsFolder/T1546.005/src/echo-art-fish.sh | bash" '
             'SIGINt\n',
  'name': None,
  'source': 'atomics/T1546.005/T1546.005.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Event Triggered Execution: Trap': {'atomic_tests': [{'auto_generated_guid': 'a74b2e07-5952-4c03-8b56-56274b076b61',
                                                                               'description': 'After '
                                                                                              'exiting '
                                                                                              'the '
                                                                                              'shell, '
                                                                                              'the '
                                                                                              'script '
                                                                                              'will '
                                                                                              'download '
                                                                                              'and '
                                                                                              'execute.\n'
                                                                                              'After '
                                                                                              'sending '
                                                                                              'a '
                                                                                              'keyboard '
                                                                                              'interrupt '
                                                                                              '(CTRL+C) '
                                                                                              'the '
                                                                                              'script '
                                                                                              'will '
                                                                                              'download '
                                                                                              'and '
                                                                                              'execute.\n',
                                                                               'executor': {'command': 'trap '
                                                                                                       '"nohup '
                                                                                                       'sh '
                                                                                                       '$PathToAtomicsFolder/T1546.005/src/echo-art-fish.sh '
                                                                                                       '| '
                                                                                                       'bash" '
                                                                                                       'EXIT\n'
                                                                                                       'exit\n'
                                                                                                       'trap '
                                                                                                       '"nohup '
                                                                                                       'sh '
                                                                                                       '$PathToAtomicsFolder/T1546.005/src/echo-art-fish.sh '
                                                                                                       '| '
                                                                                                       'bash" '
                                                                                                       'SIGINt\n',
                                                                                            'name': 'sh'},
                                                                               'name': 'Trap',
                                                                               'supported_platforms': ['macos',
                                                                                                       'linux']}],
                                                             'attack_technique': 'T1546.005',
                                                             'display_name': 'Event '
                                                                             'Triggered '
                                                                             'Execution: '
                                                                             'Trap'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors

None
