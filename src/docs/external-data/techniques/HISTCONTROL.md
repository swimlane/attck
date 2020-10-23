
# HISTCONTROL

## Description

### MITRE Description

> Adversaries may configure <code>HISTCONTROL</code> to not log all command history. The <code>HISTCONTROL</code> environment variable keeps track of what should be saved by the <code>history</code> command and eventually into the <code>~/.bash_history</code> file when a user logs out. <code>HISTCONTROL</code> does not exist by default on macOS, but can be set by the user and will be respected.

This setting can be configured to ignore commands that start with a space by simply setting it to "ignorespace". <code>HISTCONTROL</code> can also be set to ignore duplicate commands by setting it to "ignoredups". In some Linux systems, this is set by default to "ignoreboth" which covers both of the previous examples. This means that “ ls” will not be saved, but “ls” would be saved by history.

 Adversaries can abuse this to operate without leaving traces by simply prepending a space to all of their terminal commands.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Host forensic analysis', 'Log analysis']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1562/003

## Potential Commands

```
export HISTCONTROL=ignoreboth
whoami
```

## Commands Dataset

```
[{'command': 'export HISTCONTROL=ignoreboth\nwhoami\n',
  'name': None,
  'source': 'atomics/T1562.003/T1562.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Impair Defenses: HISTCONTROL': {'atomic_tests': [{'auto_generated_guid': '4eafdb45-0f79-4d66-aa86-a3e2c08791f5',
                                                                            'description': 'Disables '
                                                                                           'history '
                                                                                           'collection '
                                                                                           'in '
                                                                                           'shells\n',
                                                                            'executor': {'command': 'export '
                                                                                                    'HISTCONTROL=ignoreboth\n'
                                                                                                    '#{evil_command}\n',
                                                                                         'name': 'sh'},
                                                                            'input_arguments': {'evil_command': {'default': 'whoami',
                                                                                                                 'description': 'Command '
                                                                                                                                'to '
                                                                                                                                'run '
                                                                                                                                'after '
                                                                                                                                'shell '
                                                                                                                                'history '
                                                                                                                                'collection '
                                                                                                                                'is '
                                                                                                                                'disabled',
                                                                                                                 'type': 'String'}},
                                                                            'name': 'Disable '
                                                                                    'history '
                                                                                    'collection',
                                                                            'supported_platforms': ['linux',
                                                                                                    'macos']},
                                                                           {'auto_generated_guid': '468566d5-83e5-40c1-b338-511e1659628d',
                                                                            'description': 'The '
                                                                                           'HISTCONTROL '
                                                                                           'variable '
                                                                                           'is '
                                                                                           'set '
                                                                                           'to '
                                                                                           'ignore '
                                                                                           '(not '
                                                                                           'write '
                                                                                           'to '
                                                                                           'the '
                                                                                           'history '
                                                                                           'file) '
                                                                                           'command '
                                                                                           'that '
                                                                                           'are '
                                                                                           'a '
                                                                                           'duplicate '
                                                                                           'of '
                                                                                           'something '
                                                                                           'already '
                                                                                           'in '
                                                                                           'the '
                                                                                           'history \n'
                                                                                           'and '
                                                                                           'commands '
                                                                                           'that '
                                                                                           'start '
                                                                                           'with '
                                                                                           'a '
                                                                                           'space. '
                                                                                           'This '
                                                                                           'atomic '
                                                                                           'sets '
                                                                                           'this '
                                                                                           'variable '
                                                                                           'in '
                                                                                           'the '
                                                                                           'current '
                                                                                           'session '
                                                                                           'and '
                                                                                           'also '
                                                                                           'writes '
                                                                                           'it '
                                                                                           'to '
                                                                                           'the '
                                                                                           'current '
                                                                                           "user's "
                                                                                           '~/.bash_profile \n'
                                                                                           'so '
                                                                                           'that '
                                                                                           'it '
                                                                                           'will '
                                                                                           'apply '
                                                                                           'to '
                                                                                           'all '
                                                                                           'future '
                                                                                           'settings '
                                                                                           'as '
                                                                                           'well.\n'
                                                                                           'https://www.linuxjournal.com/content/using-bash-history-more-efficiently-histcontrol\n',
                                                                            'executor': {'name': 'manual',
                                                                                         'steps': '1. '
                                                                                                  'export '
                                                                                                  'HISTCONTROL=ignoreboth\n'
                                                                                                  '2. '
                                                                                                  'echo '
                                                                                                  'export '
                                                                                                  '"HISTCONTROL=ignoreboth" '
                                                                                                  '>> '
                                                                                                  '~/.bash_profile\n'
                                                                                                  '3. '
                                                                                                  'ls\n'
                                                                                                  '4. '
                                                                                                  'whoami '
                                                                                                  '> '
                                                                                                  'recon.txt\n'},
                                                                            'name': 'Mac '
                                                                                    'HISTCONTROL',
                                                                            'supported_platforms': ['macos',
                                                                                                    'linux']}],
                                                          'attack_technique': 'T1562.003',
                                                          'display_name': 'Impair '
                                                                          'Defenses: '
                                                                          'HISTCONTROL'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)

* [Environment Variable Permissions](../mitigations/Environment-Variable-Permissions.md)
    

# Actors

None
