
# Clear Command History

## Description

### MITRE Description

> macOS and Linux both keep track of the commands users type in their terminal so that users can easily remember what they've done. These logs can be accessed in a few different ways. While logged in, this command history is tracked in a file pointed to by the environment variable <code>HISTFILE</code>. When a user logs off a system, this information is flushed to a file in the user's home directory called <code>~/.bash_history</code>. The benefit of this is that it allows users to go back to commands they've used before in different sessions. Since everything typed on the command-line is saved, passwords passed in on the command line are also saved. Adversaries can abuse this by searching these files for cleartext passwords. Additionally, adversaries can use a variety of methods to prevent their own commands from appear in these logs such as <code>unset HISTFILE</code>, <code>export HISTFILESIZE=0</code>, <code>history -c</code>, <code>rm ~/.bash_history</code>.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Log analysis', 'Host forensic analysis']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS']
* Remote: None
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
rm ~/.bash_history
```
```
echo " " > .bash_history
```
```
cat /dev/null > ~/.bash_history
```
```
ln -sf /dev/null ~/.bash_history
```
```
truncate -s0 ~/.bash_history
```
```
unset HISTFILE
```
```
export HISTFILESIZE=0
```
```
history -c
```
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
  'source': 'Threat Hunting Tables'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'rm ~/.bash_history',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'echo " " > .bash_history',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'cat /dev/null > ~/.bash_history',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'ln -sf /dev/null ~/.bash_history',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'truncate -s0 ~/.bash_history',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'unset HISTFILE', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'export HISTFILESIZE=0',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'history -c', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'}]
```

## Potential Detections

```json
[{'data_source': 'auditlogs (audit.rules)'},
 {'data_source': 'bash_history logs'},
 {'data_source': {'author': 'Patrick Bareiss',
                  'date': '2019/03/24',
                  'description': 'Clear command history in linux which is used '
                                 'for defense evasion.',
                  'detection': {'condition': 'keywords',
                                'keywords': ['rm *bash_history',
                                             'echo "" > *bash_history',
                                             'cat /dev/null > *bash_history',
                                             'ln -sf /dev/null *bash_history',
                                             'truncate -s0 *bash_history',
                                             'export HISTFILESIZE=0',
                                             'history -c',
                                             'history -w',
                                             'shred *bash_history']},
                  'falsepositives': ['Unknown'],
                  'id': 'fdc88d25-96fb-4b7c-9633-c0e417fdbd4e',
                  'level': 'high',
                  'logsource': {'product': 'linux'},
                  'references': ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml',
                                 'https://attack.mitre.org/techniques/T1146/',
                                 'https://www.hackers-arise.com/single-post/2016/06/20/Covering-your-BASH-Shell-Tracks-AntiForensics'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion', 'attack.t1146'],
                  'title': 'Clear Command History'}}]
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
           '"*Remove-Item (Get-PSReadlineOption).HistorySavePath*")'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=linux_audit syscall=263 | table '
           'time,host,auid,uid,euid,exe,key'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=linux_audit type=PATH name=.bash_history '
           'nametype=delete | table time,name,nametype'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype="linux_audit" bash_history_changes '
           'exe!=/home/ec2-user/splunk/bin/splunkd syscall=257 a2!=0 AND a3!=0 '
           '| table host,syscall,syscall_name,exe,auid'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'a2!=0 and a3!=0 are added in to the query to distinuish echo and '
           'cat - both logs Systemcall 257 (openat). Morover, when a user '
           'logsin through ssh - SYSCALL 257 is used with exe=/usr/bin/bash (2 '
           'events generated)for /home/$USER/.bash_history; however in that '
           'case the command arguments a2=0 and a3=0 ; when we use command '
           '"echo " "> .bash_history"  the same systemcall (257) and the same '
           'exe = /usr/bin/bash is used however command arguments a2!=0 and '
           'a3!=0.'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype="linux_audit" bash_history_changes '
           'exe!=/home/ec2-user/splunk/bin/splunkd syscall=257 '
           'exe=/usr/bin/bash a2!=0 AND a3!=0| table '
           'host,syscall,syscall_name,exe,auid'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': '-a always,exit -F arch=b64 -F PATH=/home/ec2-user/.bash_history -S '
           'unlinkat -F auid>=1000 -F auid!=4294967295 -F '
           'key=delete_bash_history'},
 {'name': None,
  'product': 'Splunk',
  'query': '-w /home/ec2-user/.bash_history -p rwa -k bash_history_changes'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype="bash_history"  "rm * .bash_history"'},
 {'name': None, 'product': 'Splunk', 'query': '```'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Clear Command History': {'atomic_tests': [{'auto_generated_guid': 'a934276e-2be5-4a36-93fd-98adbb5bd4fc',
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

