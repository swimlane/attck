
# Bash History

## Description

### MITRE Description

> Bash keeps track of the commands users type on the command-line with the "history" utility. Once a user logs out, the history is flushed to the user’s <code>.bash_history</code> file. For each user, this file resides at the same location: <code>~/.bash_history</code>. Typically, this file keeps track of the user’s last 500 commands. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out. Attackers can abuse this by looking through the file for potential credentials. (Citation: External to DA, the OS X Way)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1139

## Potential Commands

```
cat ~/.bash_history | grep #{bash_history_grep_args} > #{output_file}

cat #{bash_history_filename} | grep -e '-p ' -e 'pass' -e 'ssh' > #{output_file}

cat #{bash_history_filename} | grep #{bash_history_grep_args} > ~/loot.txt

{'darwin': {'sh': {'command': "find ~/.bash_sessions -name '*' -exec cat {} \\; 2>/dev/null", 'parsers': {'plugins.stockpile.app.parsers.ssh': [{'source': 'remote.ssh.cmd'}]}}}, 'linux': {'sh': {'command': 'cat ~/.bash_history', 'parsers': {'plugins.stockpile.app.parsers.ssh': [{'source': 'remote.ssh.cmd'}]}}}}
bash cat ~/.bash_history | grep -e '-p ' -e 'pass' -e 'ssh' > loot.txt
bash cat ~/.bash_history | grep -e '-p ' -e 'pass' -e 'ssh' > out.txt
python/collection/linux/pillage_user
python/collection/linux/pillage_user
python/collection/osx/pillage_user
python/collection/osx/pillage_user
```

## Commands Dataset

```
[{'command': 'cat ~/.bash_history | grep #{bash_history_grep_args} > '
             '#{output_file}\n',
  'name': None,
  'source': 'atomics/T1139/T1139.yaml'},
 {'command': "cat #{bash_history_filename} | grep -e '-p ' -e 'pass' -e 'ssh' "
             '> #{output_file}\n',
  'name': None,
  'source': 'atomics/T1139/T1139.yaml'},
 {'command': 'cat #{bash_history_filename} | grep #{bash_history_grep_args} > '
             '~/loot.txt\n',
  'name': None,
  'source': 'atomics/T1139/T1139.yaml'},
 {'command': {'darwin': {'sh': {'command': "find ~/.bash_sessions -name '*' "
                                           '-exec cat {} \\; 2>/dev/null',
                                'parsers': {'plugins.stockpile.app.parsers.ssh': [{'source': 'remote.ssh.cmd'}]}}},
              'linux': {'sh': {'command': 'cat ~/.bash_history',
                               'parsers': {'plugins.stockpile.app.parsers.ssh': [{'source': 'remote.ssh.cmd'}]}}}},
  'name': 'Get contents of bash history',
  'source': 'data/abilities/credential-access/422526ec-27e9-429a-995b-c686a29561a4.yml'},
 {'command': "bash cat ~/.bash_history | grep -e '-p ' -e 'pass' -e 'ssh' > "
             'loot.txt',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': "bash cat ~/.bash_history | grep -e '-p ' -e 'pass' -e 'ssh' > "
             'out.txt',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'python/collection/linux/pillage_user',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/pillage_user',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/pillage_user',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/pillage_user',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Bash History': {'atomic_tests': [{'description': 'Search '
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
                                          'attack_technique': 'T1139',
                                          'display_name': 'Bash History'}},
 {'Mitre Stockpile - Get contents of bash history': {'description': 'Get '
                                                                    'contents '
                                                                    'of bash '
                                                                    'history',
                                                     'id': '422526ec-27e9-429a-995b-c686a29561a4',
                                                     'name': 'Dump history',
                                                     'platforms': {'darwin': {'sh': {'command': 'find '
                                                                                                '~/.bash_sessions '
                                                                                                '-name '
                                                                                                "'*' "
                                                                                                '-exec '
                                                                                                'cat '
                                                                                                '{} '
                                                                                                '\\; '
                                                                                                '2>/dev/null',
                                                                                     'parsers': {'plugins.stockpile.app.parsers.ssh': [{'source': 'remote.ssh.cmd'}]}}},
                                                                   'linux': {'sh': {'command': 'cat '
                                                                                               '~/.bash_history',
                                                                                    'parsers': {'plugins.stockpile.app.parsers.ssh': [{'source': 'remote.ssh.cmd'}]}}}},
                                                     'tactic': 'credential-access',
                                                     'technique': {'attack_id': 'T1139',
                                                                   'name': 'Bash '
                                                                           'History'}}},
 {'Threat Hunting Tables': {'chain_id': '100190',
                            'commandline_string': 'cat ~/.bash_history | grep '
                                                  "-e '-p ' -e 'pass' -e 'ssh' "
                                                  '> loot.txt',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1139',
                            'mitre_caption': 'bash_history',
                            'os': 'mac',
                            'parent_process': 'bash',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100201',
                            'commandline_string': 'cat ~/.bash_history | grep '
                                                  "-e '-p ' -e 'pass' -e 'ssh' "
                                                  '> out.txt',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1139',
                            'mitre_caption': 'bash_history',
                            'os': 'linux',
                            'parent_process': 'bash',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1139',
                                            'ATT&CK Technique #2': 'T1212',
                                            'Concatenate for Python Dictionary': '"python/collection/linux/pillage_user":  '
                                                                                 '["T1139","T1212"],',
                                            'Empire Module': 'python/collection/linux/pillage_user',
                                            'Technique': 'Bash History'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1139',
                                            'ATT&CK Technique #2': 'T1033',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/pillage_user":  '
                                                                                 '["T1139","T1033"],',
                                            'Empire Module': 'python/collection/osx/pillage_user',
                                            'Technique': 'Bash History'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations

None

# Actors

None
