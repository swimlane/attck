
# Bash History

## Description

### MITRE Description

> Adversaries may search the bash command history on compromised systems for insecurely stored credentials. Bash keeps track of the commands users type on the command-line with the "history" utility. Once a user logs out, the history is flushed to the user’s <code>.bash_history</code> file. For each user, this file resides at the same location: <code>~/.bash_history</code>. Typically, this file keeps track of the user’s last 500 commands. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out. Attackers can abuse this by looking through the file for potential credentials. (Citation: External to DA, the OS X Way)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1552/003

## Potential Commands

```
cat #{bash_history_filename} | grep #{bash_history_grep_args} > ~/loot.txt
cat #{bash_history_filename} | grep -e '-p ' -e 'pass' -e 'ssh' > #{output_file}
cat ~/.bash_history | grep #{bash_history_grep_args} > #{output_file}
```

## Commands Dataset

```
[{'command': 'cat #{bash_history_filename} | grep #{bash_history_grep_args} > '
             '~/loot.txt\n',
  'name': None,
  'source': 'atomics/T1552.003/T1552.003.yaml'},
 {'command': "cat #{bash_history_filename} | grep -e '-p ' -e 'pass' -e 'ssh' "
             '> #{output_file}\n',
  'name': None,
  'source': 'atomics/T1552.003/T1552.003.yaml'},
 {'command': 'cat ~/.bash_history | grep #{bash_history_grep_args} > '
             '#{output_file}\n',
  'name': None,
  'source': 'atomics/T1552.003/T1552.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Unsecured Credentials: Bash History': {'atomic_tests': [{'auto_generated_guid': '3cfde62b-7c33-4b26-a61e-755d6131c8ce',
                                                                                   'description': 'Search '
                                                                                                  'through '
                                                                                                  'bash '
                                                                                                  'history '
                                                                                                  'for '
                                                                                                  'specifice '
                                                                                                  'commands '
                                                                                                  'we '
                                                                                                  'want '
                                                                                                  'to '
                                                                                                  'capture\n',
                                                                                   'executor': {'command': 'cat '
                                                                                                           '#{bash_history_filename} '
                                                                                                           '| '
                                                                                                           'grep '
                                                                                                           '#{bash_history_grep_args} '
                                                                                                           '> '
                                                                                                           '#{output_file}\n',
                                                                                                'name': 'sh'},
                                                                                   'input_arguments': {'bash_history_filename': {'default': '~/.bash_history',
                                                                                                                                 'description': 'Path '
                                                                                                                                                'of '
                                                                                                                                                'the '
                                                                                                                                                'bash '
                                                                                                                                                'history '
                                                                                                                                                'file '
                                                                                                                                                'to '
                                                                                                                                                'capture',
                                                                                                                                 'type': 'Path'},
                                                                                                       'bash_history_grep_args': {'default': '-e '
                                                                                                                                             "'-p "
                                                                                                                                             "' "
                                                                                                                                             '-e '
                                                                                                                                             "'pass' "
                                                                                                                                             '-e '
                                                                                                                                             "'ssh'",
                                                                                                                                  'description': 'grep '
                                                                                                                                                 'arguments '
                                                                                                                                                 'that '
                                                                                                                                                 'filter '
                                                                                                                                                 'out '
                                                                                                                                                 'specific '
                                                                                                                                                 'commands '
                                                                                                                                                 'we '
                                                                                                                                                 'want '
                                                                                                                                                 'to '
                                                                                                                                                 'capture',
                                                                                                                                  'type': 'Path'},
                                                                                                       'output_file': {'default': '~/loot.txt',
                                                                                                                       'description': 'Path '
                                                                                                                                      'where '
                                                                                                                                      'captured '
                                                                                                                                      'results '
                                                                                                                                      'will '
                                                                                                                                      'be '
                                                                                                                                      'placed',
                                                                                                                       'type': 'Path'}},
                                                                                   'name': 'Search '
                                                                                           'Through '
                                                                                           'Bash '
                                                                                           'History',
                                                                                   'supported_platforms': ['linux',
                                                                                                           'macos']}],
                                                                 'attack_technique': 'T1552.003',
                                                                 'display_name': 'Unsecured '
                                                                                 'Credentials: '
                                                                                 'Bash '
                                                                                 'History'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)

* [Bash History Mitigation](../mitigations/Bash-History-Mitigation.md)
    

# Actors

None
