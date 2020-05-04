
# HISTCONTROL

## Description

### MITRE Description

> The <code>HISTCONTROL</code> environment variable keeps track of what should be saved by the <code>history</code> command and eventually into the <code>~/.bash_history</code> file when a user logs out. This setting can be configured to ignore commands that start with a space by simply setting it to "ignorespace". <code>HISTCONTROL</code> can also be set to ignore duplicate commands by setting it to "ignoredups". In some Linux systems, this is set by default to "ignoreboth" which covers both of the previous examples. This means that “ ls” will not be saved, but “ls” would be saved by history. <code>HISTCONTROL</code> does not exist by default on macOS, but can be set by the user and will be respected. Adversaries can use this to operate without leaving traces by simply prepending a space to all of their terminal commands.

## Additional Attributes

* Bypass: ['Log analysis', 'Host forensic analysis']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1148

## Potential Commands

```
export HISTCONTROL=ignoreboth
ls whoami

bash sudo spctl --master-disable
```

## Commands Dataset

```
[{'command': 'export HISTCONTROL=ignoreboth\nls whoami\n',
  'name': None,
  'source': 'atomics/T1148/T1148.yaml'},
 {'command': 'bash sudo spctl --master-disable',
  'name': None,
  'source': 'Threat Hunting Tables'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - HISTCONTROL': {'atomic_tests': [{'description': 'Disables '
                                                                          'history '
                                                                          'collection '
                                                                          'in '
                                                                          'shells\n',
                                                           'executor': {'command': 'export '
                                                                                   'HISTCONTROL=ignoreboth\n'
                                                                                   'ls '
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
                                                          {'description': '',
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
                                         'attack_technique': 'T1148',
                                         'display_name': 'HISTCONTROL'}},
 {'Threat Hunting Tables': {'chain_id': '100197',
                            'commandline_string': 'sudo spctl --master-disable',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1148',
                            'mitre_caption': 'defense_evasion',
                            'os': 'mac',
                            'parent_process': 'bash',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors

None
