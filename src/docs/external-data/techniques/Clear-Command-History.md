
# Clear Command History

## Description

### MITRE Description

> macOS and Linux both keep track of the commands users type in their terminal so that users can easily remember what they've done. These logs can be accessed in a few different ways. While logged in, this command history is tracked in a file pointed to by the environment variable <code>HISTFILE</code>. When a user logs off a system, this information is flushed to a file in the user's home directory called <code>~/.bash_history</code>. The benefit of this is that it allows users to go back to commands they've used before in different sessions. Since everything typed on the command-line is saved, passwords passed in on the command line are also saved. Adversaries can abuse this by searching these files for cleartext passwords. Additionally, adversaries can use a variety of methods to prevent their own commands from appear in these logs such as <code>unset HISTFILE</code>, <code>export HISTFILESIZE=0</code>, <code>history -c</code>, <code>rm ~/.bash_history</code>.

## Additional Attributes

* Bypass: ['Log analysis', 'Host forensic analysis']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1146

## Potential Commands

```
rm ~/.bash_history

echo "" > ~/.bash_history

cat /dev/null > ~/.bash_history

ln -sf /dev/null ~/.bash_history

truncate -s0 ~/.bash_history

unset HISTFILE
export HISTFILESIZE=0
history -c

bash unset HISTFILE
bash export HISTFILESIZE=0
bash history -c
bash rm ~/.bash_history
bash cat /dev/null > ~/.bash_history
```

## Commands Dataset

```
[{'command': 'rm ~/.bash_history\n',
  'name': None,
  'source': 'atomics/T1146/T1146.yaml'},
 {'command': 'echo "" > ~/.bash_history\n',
  'name': None,
  'source': 'atomics/T1146/T1146.yaml'},
 {'command': 'cat /dev/null > ~/.bash_history\n',
  'name': None,
  'source': 'atomics/T1146/T1146.yaml'},
 {'command': 'ln -sf /dev/null ~/.bash_history\n',
  'name': None,
  'source': 'atomics/T1146/T1146.yaml'},
 {'command': 'truncate -s0 ~/.bash_history\n',
  'name': None,
  'source': 'atomics/T1146/T1146.yaml'},
 {'command': 'unset HISTFILE\nexport HISTFILESIZE=0\nhistory -c\n',
  'name': None,
  'source': 'atomics/T1146/T1146.yaml'},
 {'command': 'bash unset HISTFILE',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'bash export HISTFILESIZE=0',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'bash history -c',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'bash rm ~/.bash_history',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'bash cat /dev/null > ~/.bash_history',
  'name': None,
  'source': 'Threat Hunting Tables'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Clear Command History',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_command_line contains "*rm '
           '(Get-PSReadlineOption).HistorySavePath*"or process_command_line '
           'contains "*del (Get-PSReadlineOption).HistorySavePath*"or '
           'process_command_line contains "*Set-PSReadlineOption '
           '–HistorySaveStyle SaveNothing*"or process_command_line contains '
           '"*Remove-Item (Get-PSReadlineOption).HistorySavePath*")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Clear Command History': {'atomic_tests': [{'description': 'Clears '
                                                                                    'bash '
                                                                                    'history '
                                                                                    'via '
                                                                                    'rm\n',
                                                                     'executor': {'command': 'rm '
                                                                                             '~/.bash_history\n',
                                                                                  'name': 'sh'},
                                                                     'name': 'Clear '
                                                                             'Bash '
                                                                             'history '
                                                                             '(rm)',
                                                                     'supported_platforms': ['linux',
                                                                                             'macos']},
                                                                    {'description': 'Clears '
                                                                                    'bash '
                                                                                    'history '
                                                                                    'via '
                                                                                    'rm\n',
                                                                     'executor': {'command': 'echo '
                                                                                             '"" '
                                                                                             '> '
                                                                                             '~/.bash_history\n',
                                                                                  'name': 'sh'},
                                                                     'name': 'Clear '
                                                                             'Bash '
                                                                             'history '
                                                                             '(echo)',
                                                                     'supported_platforms': ['linux',
                                                                                             'macos']},
                                                                    {'description': 'Clears '
                                                                                    'bash '
                                                                                    'history '
                                                                                    'via '
                                                                                    'cat '
                                                                                    '/dev/null\n',
                                                                     'executor': {'command': 'cat '
                                                                                             '/dev/null '
                                                                                             '> '
                                                                                             '~/.bash_history\n',
                                                                                  'name': 'sh'},
                                                                     'name': 'Clear '
                                                                             'Bash '
                                                                             'history '
                                                                             '(cat '
                                                                             'dev/null)',
                                                                     'supported_platforms': ['linux',
                                                                                             'macos']},
                                                                    {'description': 'Clears '
                                                                                    'bash '
                                                                                    'history '
                                                                                    'via '
                                                                                    'a '
                                                                                    'symlink '
                                                                                    'to '
                                                                                    '/dev/null\n',
                                                                     'executor': {'command': 'ln '
                                                                                             '-sf '
                                                                                             '/dev/null '
                                                                                             '~/.bash_history\n',
                                                                                  'name': 'sh'},
                                                                     'name': 'Clear '
                                                                             'Bash '
                                                                             'history '
                                                                             '(ln '
                                                                             'dev/null)',
                                                                     'supported_platforms': ['linux',
                                                                                             'macos']},
                                                                    {'description': 'Clears '
                                                                                    'bash '
                                                                                    'history '
                                                                                    'via '
                                                                                    'truncate\n',
                                                                     'executor': {'command': 'truncate '
                                                                                             '-s0 '
                                                                                             '~/.bash_history\n',
                                                                                  'name': 'sh'},
                                                                     'name': 'Clear '
                                                                             'Bash '
                                                                             'history '
                                                                             '(truncate)',
                                                                     'supported_platforms': ['linux']},
                                                                    {'description': 'Clears '
                                                                                    'the '
                                                                                    'history '
                                                                                    'of '
                                                                                    'a '
                                                                                    'bunch '
                                                                                    'of '
                                                                                    'different '
                                                                                    'shell '
                                                                                    'types '
                                                                                    'by '
                                                                                    'setting '
                                                                                    'the '
                                                                                    'history '
                                                                                    'size '
                                                                                    'to '
                                                                                    'zero\n',
                                                                     'executor': {'command': 'unset '
                                                                                             'HISTFILE\n'
                                                                                             'export '
                                                                                             'HISTFILESIZE=0\n'
                                                                                             'history '
                                                                                             '-c\n',
                                                                                  'name': 'sh'},
                                                                     'name': 'Clear '
                                                                             'history '
                                                                             'of '
                                                                             'a '
                                                                             'bunch '
                                                                             'of '
                                                                             'shells',
                                                                     'supported_platforms': ['linux',
                                                                                             'macos']}],
                                                   'attack_technique': 'T1146',
                                                   'display_name': 'Clear '
                                                                   'Command '
                                                                   'History'}},
 {'Threat Hunting Tables': {'chain_id': '100191',
                            'commandline_string': 'unset HISTFILE',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1146',
                            'mitre_caption': 'defense_evasion',
                            'os': 'mac',
                            'parent_process': 'bash',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100192',
                            'commandline_string': 'export HISTFILESIZE=0',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1146',
                            'mitre_caption': 'defense_evasion',
                            'os': 'mac',
                            'parent_process': 'bash',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100193',
                            'commandline_string': 'history -c',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1146',
                            'mitre_caption': 'defense_evasion',
                            'os': 'mac',
                            'parent_process': 'bash',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100194',
                            'commandline_string': 'rm ~/.bash_history',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1146',
                            'mitre_caption': 'defense_evasion',
                            'os': 'mac',
                            'parent_process': 'bash',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100195',
                            'commandline_string': 'cat /dev/null > '
                                                  '~/.bash_history',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1146',
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


* [APT41](../actors/APT41.md)

