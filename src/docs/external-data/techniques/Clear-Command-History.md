
# Clear Command History

## Description

### MITRE Description

> In addition to clearing system logs, an adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion. macOS and Linux both keep track of the commands users type in their terminal so that users can retrace what they've done.

These logs can be accessed in a few different ways. While logged in, this command history is tracked in a file pointed to by the environment variable <code>HISTFILE</code>. When a user logs off a system, this information is flushed to a file in the user's home directory called <code>~/.bash_history</code>. The benefit of this is that it allows users to go back to commands they've used before in different sessions.

Adversaries can use a variety of methods to prevent their own commands from appear in these logs, such as clearing the history environment variable (<code>unset HISTFILE</code>), setting the command history size to zero (<code>export HISTFILESIZE=0</code>), manually clearing the history (<code>history -c</code>), or deleting the bash history file <code>rm ~/.bash_history</code>.

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
* Wiki: https://attack.mitre.org/techniques/T1070/003

## Potential Commands

```
hostname
whoami
ln -sf /dev/null ~/.bash_history
cat /dev/null > ~/.bash_history
rm ~/.bash_history
Set-PSReadlineOption HistorySaveStyle SaveNothing
unset HISTFILE
export HISTFILESIZE=0
history -c
set +o history
echo 'set +o history' >> ~/.bashrc
. ~/.bashrc
history -c
echo "" > ~/.bash_history
truncate -s0 ~/.bash_history
Remove-Item (Get-PSReadlineOption).HistorySavePath
```

## Commands Dataset

```
[{'command': 'rm ~/.bash_history\n',
  'name': None,
  'source': 'atomics/T1070.003/T1070.003.yaml'},
 {'command': 'echo "" > ~/.bash_history\n',
  'name': None,
  'source': 'atomics/T1070.003/T1070.003.yaml'},
 {'command': 'cat /dev/null > ~/.bash_history\n',
  'name': None,
  'source': 'atomics/T1070.003/T1070.003.yaml'},
 {'command': 'ln -sf /dev/null ~/.bash_history\n',
  'name': None,
  'source': 'atomics/T1070.003/T1070.003.yaml'},
 {'command': 'truncate -s0 ~/.bash_history\n',
  'name': None,
  'source': 'atomics/T1070.003/T1070.003.yaml'},
 {'command': 'unset HISTFILE\nexport HISTFILESIZE=0\nhistory -c\n',
  'name': None,
  'source': 'atomics/T1070.003/T1070.003.yaml'},
 {'command': 'set +o history\n'
             "echo 'set +o history' >> ~/.bashrc\n"
             '. ~/.bashrc\n'
             'history -c\n',
  'name': None,
  'source': 'atomics/T1070.003/T1070.003.yaml'},
 {'command': 'hostname\nwhoami\n',
  'name': None,
  'source': 'atomics/T1070.003/T1070.003.yaml'},
 {'command': 'Set-PSReadlineOption HistorySaveStyle SaveNothing\n',
  'name': None,
  'source': 'atomics/T1070.003/T1070.003.yaml'},
 {'command': 'Remove-Item (Get-PSReadlineOption).HistorySavePath\n',
  'name': None,
  'source': 'atomics/T1070.003/T1070.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Indicator Removal on Host: Clear Command History': {'atomic_tests': [{'auto_generated_guid': 'a934276e-2be5-4a36-93fd-98adbb5bd4fc',
                                                                                                'description': 'Clears '
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
                                                                                               {'auto_generated_guid': 'cbf506a5-dd78-43e5-be7e-a46b7c7a0a11',
                                                                                                'description': 'Clears '
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
                                                                                               {'auto_generated_guid': 'b1251c35-dcd3-4ea1-86da-36d27b54f31f',
                                                                                                'description': 'Clears '
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
                                                                                               {'auto_generated_guid': '23d348f3-cc5c-4ba9-bd0a-ae09069f0914',
                                                                                                'description': 'Clears '
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
                                                                                               {'auto_generated_guid': '47966a1d-df4f-4078-af65-db6d9aa20739',
                                                                                                'description': 'Clears '
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
                                                                                               {'auto_generated_guid': '7e6721df-5f08-4370-9255-f06d8a77af4c',
                                                                                                'description': 'Clears '
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
                                                                                                                        'macos']},
                                                                                               {'auto_generated_guid': '784e4011-bd1a-4ecd-a63a-8feb278512e6',
                                                                                                'description': 'Clears '
                                                                                                               'the '
                                                                                                               'history '
                                                                                                               'and '
                                                                                                               'disable '
                                                                                                               'bash '
                                                                                                               'history '
                                                                                                               'logging '
                                                                                                               'of '
                                                                                                               'the '
                                                                                                               'current '
                                                                                                               'shell '
                                                                                                               'and '
                                                                                                               'future '
                                                                                                               'shell '
                                                                                                               'sessions\n',
                                                                                                'executor': {'command': 'set '
                                                                                                                        '+o '
                                                                                                                        'history\n'
                                                                                                                        'echo '
                                                                                                                        "'set "
                                                                                                                        '+o '
                                                                                                                        "history' "
                                                                                                                        '>> '
                                                                                                                        '~/.bashrc\n'
                                                                                                                        '. '
                                                                                                                        '~/.bashrc\n'
                                                                                                                        'history '
                                                                                                                        '-c\n',
                                                                                                             'name': 'sh'},
                                                                                                'name': 'Clear '
                                                                                                        'and '
                                                                                                        'Disable '
                                                                                                        'Bash '
                                                                                                        'History '
                                                                                                        'Logging',
                                                                                                'supported_platforms': ['linux',
                                                                                                                        'macos']},
                                                                                               {'auto_generated_guid': '53b03a54-4529-4992-852d-a00b4b7215a6',
                                                                                                'description': 'Using '
                                                                                                               'a '
                                                                                                               'space '
                                                                                                               'before '
                                                                                                               'a '
                                                                                                               'command '
                                                                                                               'causes '
                                                                                                               'the '
                                                                                                               'command '
                                                                                                               'to '
                                                                                                               'not '
                                                                                                               'be '
                                                                                                               'logged '
                                                                                                               'in '
                                                                                                               'the '
                                                                                                               'Bash '
                                                                                                               'History '
                                                                                                               'file\n',
                                                                                                'executor': {'command': 'hostname\n'
                                                                                                                        'whoami\n',
                                                                                                             'name': 'sh'},
                                                                                                'name': 'Use '
                                                                                                        'Space '
                                                                                                        'Before '
                                                                                                        'Command '
                                                                                                        'to '
                                                                                                        'Avoid '
                                                                                                        'Logging '
                                                                                                        'to '
                                                                                                        'History',
                                                                                                'supported_platforms': ['linux',
                                                                                                                        'macos']},
                                                                                               {'auto_generated_guid': '2f898b81-3e97-4abb-bc3f-a95138988370',
                                                                                                'description': 'Prevents '
                                                                                                               'Powershell '
                                                                                                               'history\n',
                                                                                                'executor': {'cleanup_command': 'Set-PSReadlineOption '
                                                                                                                                '–HistorySaveStyle '
                                                                                                                                'SaveIncrementally',
                                                                                                             'command': 'Set-PSReadlineOption '
                                                                                                                        '–HistorySaveStyle '
                                                                                                                        'SaveNothing\n',
                                                                                                             'name': 'powershell'},
                                                                                                'name': 'Prevent '
                                                                                                        'Powershell '
                                                                                                        'History '
                                                                                                        'Logging',
                                                                                                'supported_platforms': ['windows']},
                                                                                               {'auto_generated_guid': 'da75ae8d-26d6-4483-b0fe-700e4df4f037',
                                                                                                'description': 'Clears '
                                                                                                               'Powershell '
                                                                                                               'history\n',
                                                                                                'executor': {'command': 'Remove-Item '
                                                                                                                        '(Get-PSReadlineOption).HistorySavePath\n',
                                                                                                             'name': 'powershell'},
                                                                                                'name': 'Clear '
                                                                                                        'Powershell '
                                                                                                        'History '
                                                                                                        'by '
                                                                                                        'Deleting '
                                                                                                        'History '
                                                                                                        'File',
                                                                                                'supported_platforms': ['windows']}],
                                                                              'attack_technique': 'T1070.003',
                                                                              'display_name': 'Indicator '
                                                                                              'Removal '
                                                                                              'on '
                                                                                              'Host: '
                                                                                              'Clear '
                                                                                              'Command '
                                                                                              'History'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Environment Variable Permissions](../mitigations/Environment-Variable-Permissions.md)

* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    
* [Clear Command History Mitigation](../mitigations/Clear-Command-History-Mitigation.md)
    

# Actors


* [APT41](../actors/APT41.md)

