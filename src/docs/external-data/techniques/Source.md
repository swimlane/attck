
# Source

## Description

### MITRE Description

> The <code>source</code> command loads functions into the current shell or executes files in the current context. This built-in command can be run in two different ways <code>source /path/to/filename [arguments]</code> or <code>. /path/to/filename [arguments]</code>. Take note of the space after the ".". Without a space, a new shell is created that runs the program instead of running the program within the current context. This is often used to make certain features or functions available to a shell or to update a specific shell's environment.(Citation: Source Manual)

Adversaries can abuse this functionality to execute programs. The file executed with this technique does not need to be marked executable beforehand.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1153

## Potential Commands

```
sh -c "echo 'echo Hello from the Atomic Red Team' > /tmp/art.sh"
chmod +x /tmp/art.sh
source /tmp/art.sh

sh -c "echo 'echo Hello from the Atomic Red Team' > /tmp/art.sh"
chmod +x /tmp/art.sh
. /tmp/art.sh

```

## Commands Dataset

```
[{'command': 'sh -c "echo \'echo Hello from the Atomic Red Team\' > '
             '/tmp/art.sh"\n'
             'chmod +x /tmp/art.sh\n'
             'source /tmp/art.sh\n',
  'name': None,
  'source': 'atomics/T1153/T1153.yaml'},
 {'command': 'sh -c "echo \'echo Hello from the Atomic Red Team\' > '
             '/tmp/art.sh"\n'
             'chmod +x /tmp/art.sh\n'
             '. /tmp/art.sh\n',
  'name': None,
  'source': 'atomics/T1153/T1153.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Source': {'atomic_tests': [{'description': 'Creates '
                                                                     'a script '
                                                                     'and '
                                                                     'executes '
                                                                     'it using '
                                                                     'the '
                                                                     'source '
                                                                     'command\n',
                                                      'executor': {'command': 'sh '
                                                                              '-c '
                                                                              '"echo '
                                                                              "'echo "
                                                                              'Hello '
                                                                              'from '
                                                                              'the '
                                                                              'Atomic '
                                                                              'Red '
                                                                              "Team' "
                                                                              '> '
                                                                              '/tmp/art.sh"\n'
                                                                              'chmod '
                                                                              '+x '
                                                                              '/tmp/art.sh\n'
                                                                              'source '
                                                                              '/tmp/art.sh\n',
                                                                   'name': 'sh'},
                                                      'name': 'Execute Script '
                                                              'using Source',
                                                      'supported_platforms': ['macos',
                                                                              'linux']},
                                                     {'description': 'Creates '
                                                                     'a script '
                                                                     'and '
                                                                     'executes '
                                                                     'it using '
                                                                     'the '
                                                                     'source '
                                                                     "command's "
                                                                     'dot '
                                                                     'alias\n',
                                                      'executor': {'command': 'sh '
                                                                              '-c '
                                                                              '"echo '
                                                                              "'echo "
                                                                              'Hello '
                                                                              'from '
                                                                              'the '
                                                                              'Atomic '
                                                                              'Red '
                                                                              "Team' "
                                                                              '> '
                                                                              '/tmp/art.sh"\n'
                                                                              'chmod '
                                                                              '+x '
                                                                              '/tmp/art.sh\n'
                                                                              '. '
                                                                              '/tmp/art.sh\n',
                                                                   'name': 'sh'},
                                                      'name': 'Execute Script '
                                                              'using Source '
                                                              'Alias',
                                                      'supported_platforms': ['macos',
                                                                              'linux']}],
                                    'attack_technique': 'T1153',
                                    'display_name': 'Source'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations

None

# Actors

None
