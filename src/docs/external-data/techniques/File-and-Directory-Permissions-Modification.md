
# File and Directory Permissions Modification

## Description

### MITRE Description

> File and directory permissions are commonly managed by discretionary access control lists (DACLs) specified by the file or directory owner. File and directory DACL implementations may vary by platform, but generally explicitly designate which users/groups can perform which actions (ex: read, write, execute, etc.). (Citation: Microsoft DACL May 2018) (Citation: Microsoft File Rights May 2018) (Citation: Unix File Permissions)

Adversaries may modify file or directory permissions/attributes to evade intended DACLs. (Citation: Hybrid Analysis Icacls1 June 2018) (Citation: Hybrid Analysis Icacls2 May 2018) Modifications may include changing specific access rights, which may require taking ownership of a file or directory and/or elevated permissions such as Administrator/root depending on the file or directory's existing permissions to enable malicious activity such as modifying, replacing, or deleting specific files/directories. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via [Accessibility Features](https://attack.mitre.org/techniques/T1015), [Logon Scripts](https://attack.mitre.org/techniques/T1037), or tainting/hijacking other instrumental binary/configuration files.

## Additional Attributes

* Bypass: ['File system access controls']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator', 'SYSTEM', 'root']
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1222

## Potential Commands

```
takeown.exe /f %temp%\T1222_takeown_folder /r

Icacls.exe %temp%\T1222_cacls /grant #{user_or_group}:F

Icacls.exe #{file_or_folder} /grant Everyone:F

attrib.exe -r %temp%\T1222_attrib\*.* /s

chmod #{numeric_mode} /tmp/AtomicRedTeam/atomics/T1222

None
chmod #{symbolic_mode} /tmp/AtomicRedTeam/atomics/T1222

chmod a+w #{file_or_folder}

chmod #{numeric_mode} /tmp/AtomicRedTeam/atomics/T1222 -R

None
chmod #{symbolic_mode} /tmp/AtomicRedTeam/atomics/T1222 -R

chmod a+w #{file_or_folder} -R

chown #{owner}:#{group} /tmp/AtomicRedTeam/atomics/T1222/T1222.yaml

chown root:#{group} #{file_or_folder}

chown #{owner}:root #{file_or_folder}

chown #{owner}:#{group} /tmp/AtomicRedTeam/atomics/T1222 -R

chown root:#{group} #{file_or_folder} -R

chown #{owner}:root #{file_or_folder} -R

chown #{owner} /tmp/AtomicRedTeam/atomics/T1222/T1222.yaml

chown root #{file_or_folder}

chown #{owner} /tmp/AtomicRedTeam/atomics/T1222 -R

chown root #{file_or_folder} -R

chattr -i /var/spool/cron/root

```
chmod 766 test1.txt
chmod u+x test1.txt
chmod o-x test1.txt
```
```
chown ec2-user:ec2-user test1.txt
```
```

## Commands Dataset

```
[{'command': 'takeown.exe /f %temp%\\T1222_takeown_folder /r\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'Icacls.exe %temp%\\T1222_cacls /grant #{user_or_group}:F\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'Icacls.exe #{file_or_folder} /grant Everyone:F\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'attrib.exe -r %temp%\\T1222_attrib\\*.* /s\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chmod #{numeric_mode} /tmp/AtomicRedTeam/atomics/T1222\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chmod #{symbolic_mode} /tmp/AtomicRedTeam/atomics/T1222\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chmod a+w #{file_or_folder}\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chmod #{numeric_mode} /tmp/AtomicRedTeam/atomics/T1222 -R\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chmod #{symbolic_mode} /tmp/AtomicRedTeam/atomics/T1222 -R\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chmod a+w #{file_or_folder} -R\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chown #{owner}:#{group} '
             '/tmp/AtomicRedTeam/atomics/T1222/T1222.yaml\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chown root:#{group} #{file_or_folder}\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chown #{owner}:root #{file_or_folder}\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chown #{owner}:#{group} /tmp/AtomicRedTeam/atomics/T1222 -R\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chown root:#{group} #{file_or_folder} -R\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chown #{owner}:root #{file_or_folder} -R\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chown #{owner} /tmp/AtomicRedTeam/atomics/T1222/T1222.yaml\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chown root #{file_or_folder}\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chown #{owner} /tmp/AtomicRedTeam/atomics/T1222 -R\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chown root #{file_or_folder} -R\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': 'chattr -i /var/spool/cron/root\n',
  'name': None,
  'source': 'atomics/T1222/T1222.yaml'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'chmod 766 test1.txt',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'chmod u+x test1.txt',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'chmod o-x test1.txt',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'chown ec2-user:ec2-user test1.txt',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'}]
```

## Potential Detections

```json
[{'data_source': 'auditlogs (audit.rules)'},
 {'data_source': 'bash_history logs'}]
```

## Potential Queries

```json
[{'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=linux_audit syscall=90 OR syscall=91 OR '
           'sycall=268 | table msg,syscall,syscall_name,success,auid,comm,exe'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=linux_audit syscall=92 OR syscall=93 OR '
           'syscall=94 OR syscall=260 comm!=splunkd | table'},
 {'name': None,
  'product': 'Splunk',
  'query': 'msg,syscall,syscall_name,success,auid,comm,exe'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 '
           '-F auid!=-1 -F key=perm_mod'},
 {'name': None,
  'product': 'Splunk',
  'query': '-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F '
           'auid>=1000 -F auid!=-1 -F key=perm_mod'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype="bash_history" bash_command="chmod *" | '
           'table host,user_name,bash_command'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype="bash_history" bash_command="chown *" | '
           'table host,user_name,bash_command'},
 {'name': None, 'product': 'Splunk', 'query': '```'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - File Permissions Modification': {'atomic_tests': [{'dependencies': [{'description': 'Test '
                                                                                                              'requrires '
                                                                                                              'a '
                                                                                                              'file '
                                                                                                              'to '
                                                                                                              'take '
                                                                                                              'ownership '
                                                                                                              'of '
                                                                                                              'to '
                                                                                                              'be '
                                                                                                              'located '
                                                                                                              'at '
                                                                                                              '(#{file_folder_to_own})\n',
                                                                                               'get_prereq_command': 'mkdir '
                                                                                                                     '#{file_folder_to_own}\n'
                                                                                                                     'echo '
                                                                                                                     'T1222_takeown1 '
                                                                                                                     '>> '
                                                                                                                     '#{file_folder_to_own}\\T1222_takeown1.txt\n'
                                                                                                                     'echo '
                                                                                                                     'T1222_takeown2 '
                                                                                                                     '>> '
                                                                                                                     '#{file_folder_to_own}\\T1222_takeown2.txt\n',
                                                                                               'prereq_command': 'IF '
                                                                                                                 'EXIST '
                                                                                                                 '#{file_folder_to_own} '
                                                                                                                 '( '
                                                                                                                 'EXIT '
                                                                                                                 '0 '
                                                                                                                 ') '
                                                                                                                 'ELSE '
                                                                                                                 '( '
                                                                                                                 'EXIT '
                                                                                                                 '1 '
                                                                                                                 ')\n'}],
                                                                             'dependency_executor_name': 'command_prompt',
                                                                             'description': 'Modifies '
                                                                                            'the '
                                                                                            'filesystem '
                                                                                            'permissions '
                                                                                            'of '
                                                                                            'the '
                                                                                            'specified '
                                                                                            'file '
                                                                                            'or '
                                                                                            'folder '
                                                                                            'to '
                                                                                            'take '
                                                                                            'ownership '
                                                                                            'of '
                                                                                            'the '
                                                                                            'object. '
                                                                                            'Upon '
                                                                                            'execution, '
                                                                                            '"SUCCESS" '
                                                                                            'will\n'
                                                                                            'be '
                                                                                            'displayed '
                                                                                            'for '
                                                                                            'the '
                                                                                            'folder '
                                                                                            'and '
                                                                                            'each '
                                                                                            'file '
                                                                                            'inside '
                                                                                            'of '
                                                                                            'it.\n',
                                                                             'executor': {'command': 'takeown.exe '
                                                                                                     '/f '
                                                                                                     '#{file_folder_to_own} '
                                                                                                     '/r\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'file_folder_to_own': {'default': '%temp%\\T1222_takeown_folder',
                                                                                                                        'description': 'Path '
                                                                                                                                       'of '
                                                                                                                                       'the '
                                                                                                                                       'file '
                                                                                                                                       'or '
                                                                                                                                       'folder '
                                                                                                                                       'for '
                                                                                                                                       'takeown '
                                                                                                                                       'to '
                                                                                                                                       'take '
                                                                                                                                       'ownership.',
                                                                                                                        'type': 'path'}},
                                                                             'name': 'Take '
                                                                                     'ownership '
                                                                                     'using '
                                                                                     'takeown '
                                                                                     'utility',
                                                                             'supported_platforms': ['windows']},
                                                                            {'dependencies': [{'description': 'Test '
                                                                                                              'requrires '
                                                                                                              'a '
                                                                                                              'file '
                                                                                                              'to '
                                                                                                              'modifyto '
                                                                                                              'be '
                                                                                                              'located '
                                                                                                              'at '
                                                                                                              '(#{file_or_folder})\n',
                                                                                               'get_prereq_command': 'mkdir '
                                                                                                                     '#{file_or_folder}\n'
                                                                                                                     'echo '
                                                                                                                     'T1222_cacls1 '
                                                                                                                     '>> '
                                                                                                                     '#{file_or_folder}\\T1222_cacls1.txt\n'
                                                                                                                     'echo '
                                                                                                                     'T1222_cacls2 '
                                                                                                                     '>> '
                                                                                                                     '#{file_or_folder}\\T1222_cacls2.txt\n',
                                                                                               'prereq_command': 'IF '
                                                                                                                 'EXIST '
                                                                                                                 '#{file_or_folder} '
                                                                                                                 '( '
                                                                                                                 'EXIT '
                                                                                                                 '0 '
                                                                                                                 ') '
                                                                                                                 'ELSE '
                                                                                                                 '( '
                                                                                                                 'EXIT '
                                                                                                                 '1 '
                                                                                                                 ')\n'}],
                                                                             'dependency_executor_name': 'command_prompt',
                                                                             'description': 'Modifies '
                                                                                            'the '
                                                                                            'filesystem '
                                                                                            'permissions '
                                                                                            'of '
                                                                                            'the '
                                                                                            'specified '
                                                                                            'folder '
                                                                                            'and '
                                                                                            'contents '
                                                                                            'to '
                                                                                            'allow '
                                                                                            'the '
                                                                                            'specified '
                                                                                            'user '
                                                                                            'or '
                                                                                            'group '
                                                                                            'Full '
                                                                                            'Control. '
                                                                                            'If '
                                                                                            '"Access '
                                                                                            'is '
                                                                                            'denied"\n'
                                                                                            'is '
                                                                                            'displayed '
                                                                                            'it '
                                                                                            'may '
                                                                                            'be '
                                                                                            'because '
                                                                                            'the '
                                                                                            'file '
                                                                                            'or '
                                                                                            'folder '
                                                                                            "doesn't "
                                                                                            'exit. '
                                                                                            'Run '
                                                                                            'the '
                                                                                            'prereq '
                                                                                            'command '
                                                                                            'to '
                                                                                            'create '
                                                                                            'it. '
                                                                                            'Upon '
                                                                                            'successfull '
                                                                                            'execution, '
                                                                                            '"Successfully '
                                                                                            'processed '
                                                                                            '3 '
                                                                                            'files"\n'
                                                                                            'will '
                                                                                            'be '
                                                                                            'displayed.\n',
                                                                             'executor': {'command': 'Icacls.exe '
                                                                                                     '#{file_or_folder} '
                                                                                                     '/grant '
                                                                                                     '#{user_or_group}:F\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'file_or_folder': {'default': '%temp%\\T1222_cacls',
                                                                                                                    'description': 'Path '
                                                                                                                                   'of '
                                                                                                                                   'the '
                                                                                                                                   'file '
                                                                                                                                   'or '
                                                                                                                                   'folder '
                                                                                                                                   'to '
                                                                                                                                   'change '
                                                                                                                                   'permissions.',
                                                                                                                    'type': 'path'},
                                                                                                 'user_or_group': {'default': 'Everyone',
                                                                                                                   'description': 'User '
                                                                                                                                  'or '
                                                                                                                                  'group '
                                                                                                                                  'to '
                                                                                                                                  'allow '
                                                                                                                                  'full '
                                                                                                                                  'control',
                                                                                                                   'type': 'string'}},
                                                                             'name': 'cacls '
                                                                                     '- '
                                                                                     'Grant '
                                                                                     'permission '
                                                                                     'to '
                                                                                     'specified '
                                                                                     'user '
                                                                                     'or '
                                                                                     'group '
                                                                                     'recursively',
                                                                             'supported_platforms': ['windows']},
                                                                            {'dependencies': [{'description': 'Test '
                                                                                                              'requrires '
                                                                                                              'a '
                                                                                                              'file '
                                                                                                              'to '
                                                                                                              'modify '
                                                                                                              'to '
                                                                                                              'be '
                                                                                                              'located '
                                                                                                              'at '
                                                                                                              '(#{file_or_folder})\n',
                                                                                               'get_prereq_command': 'mkdir '
                                                                                                                     '#{file_or_folder}\n'
                                                                                                                     'echo '
                                                                                                                     'T1222_attrib1 '
                                                                                                                     '>> '
                                                                                                                     '#{file_or_folder}\\T1222_attrib1.txt\n'
                                                                                                                     'echo '
                                                                                                                     'T1222_attrib2 '
                                                                                                                     '>> '
                                                                                                                     '#{file_or_folder}\\T1222_attrib2.txt\n'
                                                                                                                     'attrib.exe '
                                                                                                                     '+r '
                                                                                                                     '#{file_or_folder}\\T1222_attrib1.txt\n'
                                                                                                                     'attrib.exe '
                                                                                                                     '+r '
                                                                                                                     '#{file_or_folder}\\T1222_attrib2.txt\n',
                                                                                               'prereq_command': 'IF '
                                                                                                                 'EXIST '
                                                                                                                 '#{file_or_folder} '
                                                                                                                 '( '
                                                                                                                 'EXIT '
                                                                                                                 '0 '
                                                                                                                 ') '
                                                                                                                 'ELSE '
                                                                                                                 '( '
                                                                                                                 'EXIT '
                                                                                                                 '1 '
                                                                                                                 ')\n'}],
                                                                             'dependency_executor_name': 'command_prompt',
                                                                             'description': 'Removes '
                                                                                            'the '
                                                                                            'read-only '
                                                                                            'attribute '
                                                                                            'from '
                                                                                            'a '
                                                                                            'file '
                                                                                            'or '
                                                                                            'folder '
                                                                                            'using '
                                                                                            'the '
                                                                                            'attrib.exe '
                                                                                            'command. '
                                                                                            'Upon '
                                                                                            'execution, '
                                                                                            'no '
                                                                                            'output '
                                                                                            'will '
                                                                                            'be '
                                                                                            'displayed.\n'
                                                                                            'Open '
                                                                                            'the '
                                                                                            'file '
                                                                                            'in '
                                                                                            'File '
                                                                                            'Explorer '
                                                                                            '> '
                                                                                            'Right '
                                                                                            'Click '
                                                                                            '- '
                                                                                            'Prperties '
                                                                                            'and '
                                                                                            'observe '
                                                                                            'that '
                                                                                            'the '
                                                                                            'Read '
                                                                                            'Only '
                                                                                            'checkbox '
                                                                                            'is '
                                                                                            'empty.\n',
                                                                             'executor': {'command': 'attrib.exe '
                                                                                                     '-r '
                                                                                                     '#{file_or_folder}\\*.* '
                                                                                                     '/s\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'file_or_folder': {'default': '%temp%\\T1222_attrib',
                                                                                                                    'description': 'Path '
                                                                                                                                   'of '
                                                                                                                                   'the '
                                                                                                                                   'file '
                                                                                                                                   'or '
                                                                                                                                   'folder '
                                                                                                                                   'remove '
                                                                                                                                   'attribute.',
                                                                                                                    'type': 'path'}},
                                                                             'name': 'attrib '
                                                                                     '- '
                                                                                     'Remove '
                                                                                     'read-only '
                                                                                     'attribute',
                                                                             'supported_platforms': ['windows']},
                                                                            {'description': 'Changes '
                                                                                            'a '
                                                                                            'file '
                                                                                            'or '
                                                                                            "folder's "
                                                                                            'permissions '
                                                                                            'using '
                                                                                            'chmod '
                                                                                            'and '
                                                                                            'a '
                                                                                            'specified '
                                                                                            'numeric '
                                                                                            'mode.\n',
                                                                             'executor': {'command': 'chmod '
                                                                                                     '#{numeric_mode} '
                                                                                                     '#{file_or_folder}\n',
                                                                                          'name': 'bash'},
                                                                             'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222',
                                                                                                                    'description': 'Path '
                                                                                                                                   'of '
                                                                                                                                   'the '
                                                                                                                                   'file '
                                                                                                                                   'or '
                                                                                                                                   'folder',
                                                                                                                    'type': 'path'},
                                                                                                 'numeric_mode': {'default': 755,
                                                                                                                  'description': 'Specified '
                                                                                                                                 'numeric '
                                                                                                                                 'mode '
                                                                                                                                 'value',
                                                                                                                  'type': 'string'}},
                                                                             'name': 'chmod '
                                                                                     '- '
                                                                                     'Change '
                                                                                     'file '
                                                                                     'or '
                                                                                     'folder '
                                                                                     'mode '
                                                                                     '(numeric '
                                                                                     'mode)',
                                                                             'supported_platforms': ['macos',
                                                                                                     'linux']},
                                                                            {'description': 'Changes '
                                                                                            'a '
                                                                                            'file '
                                                                                            'or '
                                                                                            "folder's "
                                                                                            'permissions '
                                                                                            'using '
                                                                                            'chmod '
                                                                                            'and '
                                                                                            'a '
                                                                                            'specified '
                                                                                            'symbolic '
                                                                                            'mode.\n',
                                                                             'executor': {'command': 'chmod '
                                                                                                     '#{symbolic_mode} '
                                                                                                     '#{file_or_folder}\n',
                                                                                          'name': 'bash'},
                                                                             'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222',
                                                                                                                    'description': 'Path '
                                                                                                                                   'of '
                                                                                                                                   'the '
                                                                                                                                   'file '
                                                                                                                                   'or '
                                                                                                                                   'folder',
                                                                                                                    'type': 'path'},
                                                                                                 'symbolic_mode': {'default': 'a+w',
                                                                                                                   'description': 'Specified '
                                                                                                                                  'symbolic '
                                                                                                                                  'mode '
                                                                                                                                  'value',
                                                                                                                   'type': 'string'}},
                                                                             'name': 'chmod '
                                                                                     '- '
                                                                                     'Change '
                                                                                     'file '
                                                                                     'or '
                                                                                     'folder '
                                                                                     'mode '
                                                                                     '(symbolic '
                                                                                     'mode)',
                                                                             'supported_platforms': ['macos',
                                                                                                     'linux']},
                                                                            {'description': 'Changes '
                                                                                            'a '
                                                                                            'file '
                                                                                            'or '
                                                                                            "folder's "
                                                                                            'permissions '
                                                                                            'recursively '
                                                                                            'using '
                                                                                            'chmod '
                                                                                            'and '
                                                                                            'a '
                                                                                            'specified '
                                                                                            'numeric '
                                                                                            'mode.\n',
                                                                             'executor': {'command': 'chmod '
                                                                                                     '#{numeric_mode} '
                                                                                                     '#{file_or_folder} '
                                                                                                     '-R\n',
                                                                                          'name': 'bash'},
                                                                             'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222',
                                                                                                                    'description': 'Path '
                                                                                                                                   'of '
                                                                                                                                   'the '
                                                                                                                                   'file '
                                                                                                                                   'or '
                                                                                                                                   'folder',
                                                                                                                    'type': 'path'},
                                                                                                 'numeric_mode': {'default': 755,
                                                                                                                  'description': 'Specified '
                                                                                                                                 'numeric '
                                                                                                                                 'mode '
                                                                                                                                 'value',
                                                                                                                  'type': 'string'}},
                                                                             'name': 'chmod '
                                                                                     '- '
                                                                                     'Change '
                                                                                     'file '
                                                                                     'or '
                                                                                     'folder '
                                                                                     'mode '
                                                                                     '(numeric '
                                                                                     'mode) '
                                                                                     'recursively',
                                                                             'supported_platforms': ['macos',
                                                                                                     'linux']},
                                                                            {'description': 'Changes '
                                                                                            'a '
                                                                                            'file '
                                                                                            'or '
                                                                                            "folder's "
                                                                                            'permissions '
                                                                                            'recursively '
                                                                                            'using '
                                                                                            'chmod '
                                                                                            'and '
                                                                                            'a '
                                                                                            'specified '
                                                                                            'symbolic '
                                                                                            'mode.\n',
                                                                             'executor': {'command': 'chmod '
                                                                                                     '#{symbolic_mode} '
                                                                                                     '#{file_or_folder} '
                                                                                                     '-R\n',
                                                                                          'name': 'bash'},
                                                                             'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222',
                                                                                                                    'description': 'Path '
                                                                                                                                   'of '
                                                                                                                                   'the '
                                                                                                                                   'file '
                                                                                                                                   'or '
                                                                                                                                   'folder',
                                                                                                                    'type': 'path'},
                                                                                                 'symbolic_mode': {'default': 'a+w',
                                                                                                                   'description': 'Specified '
                                                                                                                                  'symbolic '
                                                                                                                                  'mode '
                                                                                                                                  'value',
                                                                                                                   'type': 'string'}},
                                                                             'name': 'chmod '
                                                                                     '- '
                                                                                     'Change '
                                                                                     'file '
                                                                                     'or '
                                                                                     'folder '
                                                                                     'mode '
                                                                                     '(symbolic '
                                                                                     'mode) '
                                                                                     'recursively',
                                                                             'supported_platforms': ['macos',
                                                                                                     'linux']},
                                                                            {'description': 'Changes '
                                                                                            'a '
                                                                                            'file '
                                                                                            'or '
                                                                                            "folder's "
                                                                                            'ownership '
                                                                                            'and '
                                                                                            'group '
                                                                                            'information '
                                                                                            'using '
                                                                                            'chown.\n',
                                                                             'executor': {'command': 'chown '
                                                                                                     '#{owner}:#{group} '
                                                                                                     '#{file_or_folder}\n',
                                                                                          'name': 'bash'},
                                                                             'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222/T1222.yaml',
                                                                                                                    'description': 'Path '
                                                                                                                                   'of '
                                                                                                                                   'the '
                                                                                                                                   'file '
                                                                                                                                   'or '
                                                                                                                                   'folder',
                                                                                                                    'type': 'path'},
                                                                                                 'group': {'default': 'root',
                                                                                                           'description': 'Group '
                                                                                                                          'name '
                                                                                                                          'of '
                                                                                                                          'desired '
                                                                                                                          'group',
                                                                                                           'type': 'string'},
                                                                                                 'owner': {'default': 'root',
                                                                                                           'description': 'Username '
                                                                                                                          'of '
                                                                                                                          'desired '
                                                                                                                          'owner',
                                                                                                           'type': 'string'}},
                                                                             'name': 'chown '
                                                                                     '- '
                                                                                     'Change '
                                                                                     'file '
                                                                                     'or '
                                                                                     'folder '
                                                                                     'ownership '
                                                                                     'and '
                                                                                     'group',
                                                                             'supported_platforms': ['macos',
                                                                                                     'linux']},
                                                                            {'description': 'Changes '
                                                                                            'a '
                                                                                            'file '
                                                                                            'or '
                                                                                            "folder's "
                                                                                            'ownership '
                                                                                            'and '
                                                                                            'group '
                                                                                            'information '
                                                                                            'recursively '
                                                                                            'using '
                                                                                            'chown.\n',
                                                                             'executor': {'command': 'chown '
                                                                                                     '#{owner}:#{group} '
                                                                                                     '#{file_or_folder} '
                                                                                                     '-R\n',
                                                                                          'name': 'bash'},
                                                                             'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222',
                                                                                                                    'description': 'Path '
                                                                                                                                   'of '
                                                                                                                                   'the '
                                                                                                                                   'file '
                                                                                                                                   'or '
                                                                                                                                   'folder',
                                                                                                                    'type': 'path'},
                                                                                                 'group': {'default': 'root',
                                                                                                           'description': 'Group '
                                                                                                                          'name '
                                                                                                                          'of '
                                                                                                                          'desired '
                                                                                                                          'group',
                                                                                                           'type': 'string'},
                                                                                                 'owner': {'default': 'root',
                                                                                                           'description': 'Username '
                                                                                                                          'of '
                                                                                                                          'desired '
                                                                                                                          'owner',
                                                                                                           'type': 'string'}},
                                                                             'name': 'chown '
                                                                                     '- '
                                                                                     'Change '
                                                                                     'file '
                                                                                     'or '
                                                                                     'folder '
                                                                                     'ownership '
                                                                                     'and '
                                                                                     'group '
                                                                                     'recursively',
                                                                             'supported_platforms': ['macos',
                                                                                                     'linux']},
                                                                            {'description': 'Changes '
                                                                                            'a '
                                                                                            'file '
                                                                                            'or '
                                                                                            "folder's "
                                                                                            'ownership '
                                                                                            'only '
                                                                                            'using '
                                                                                            'chown.\n',
                                                                             'executor': {'command': 'chown '
                                                                                                     '#{owner} '
                                                                                                     '#{file_or_folder}\n',
                                                                                          'name': 'bash'},
                                                                             'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222/T1222.yaml',
                                                                                                                    'description': 'Path '
                                                                                                                                   'of '
                                                                                                                                   'the '
                                                                                                                                   'file '
                                                                                                                                   'or '
                                                                                                                                   'folder',
                                                                                                                    'type': 'path'},
                                                                                                 'owner': {'default': 'root',
                                                                                                           'description': 'Username '
                                                                                                                          'of '
                                                                                                                          'desired '
                                                                                                                          'owner',
                                                                                                           'type': 'string'}},
                                                                             'name': 'chown '
                                                                                     '- '
                                                                                     'Change '
                                                                                     'file '
                                                                                     'or '
                                                                                     'folder '
                                                                                     'mode '
                                                                                     'ownership '
                                                                                     'only',
                                                                             'supported_platforms': ['macos',
                                                                                                     'linux']},
                                                                            {'description': 'Changes '
                                                                                            'a '
                                                                                            'file '
                                                                                            'or '
                                                                                            "folder's "
                                                                                            'ownership '
                                                                                            'only '
                                                                                            'recursively '
                                                                                            'using '
                                                                                            'chown.\n',
                                                                             'executor': {'command': 'chown '
                                                                                                     '#{owner} '
                                                                                                     '#{file_or_folder} '
                                                                                                     '-R\n',
                                                                                          'name': 'bash'},
                                                                             'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222',
                                                                                                                    'description': 'Path '
                                                                                                                                   'of '
                                                                                                                                   'the '
                                                                                                                                   'file '
                                                                                                                                   'or '
                                                                                                                                   'folder',
                                                                                                                    'type': 'path'},
                                                                                                 'owner': {'default': 'root',
                                                                                                           'description': 'Username '
                                                                                                                          'of '
                                                                                                                          'desired '
                                                                                                                          'owner',
                                                                                                           'type': 'string'}},
                                                                             'name': 'chown '
                                                                                     '- '
                                                                                     'Change '
                                                                                     'file '
                                                                                     'or '
                                                                                     'folder '
                                                                                     'ownership '
                                                                                     'recursively',
                                                                             'supported_platforms': ['macos',
                                                                                                     'linux']},
                                                                            {'description': "Remove's "
                                                                                            'a '
                                                                                            "file's "
                                                                                            '`immutable` '
                                                                                            'attribute '
                                                                                            'using '
                                                                                            '`chattr`.\n'
                                                                                            'This '
                                                                                            'technique '
                                                                                            'was '
                                                                                            'used '
                                                                                            'by '
                                                                                            'the '
                                                                                            'threat '
                                                                                            'actor '
                                                                                            'Rocke '
                                                                                            'during '
                                                                                            'the '
                                                                                            'compromise '
                                                                                            'of '
                                                                                            'Linux '
                                                                                            'web '
                                                                                            'servers.\n',
                                                                             'executor': {'command': 'chattr '
                                                                                                     '-i '
                                                                                                     '#{file_to_modify}\n',
                                                                                          'name': 'sh'},
                                                                             'input_arguments': {'file_to_modify': {'default': '/var/spool/cron/root',
                                                                                                                    'description': 'Path '
                                                                                                                                   'of '
                                                                                                                                   'the '
                                                                                                                                   'file',
                                                                                                                    'type': 'path'}},
                                                                             'name': 'chattr '
                                                                                     '- '
                                                                                     'Remove '
                                                                                     'immutable '
                                                                                     'file '
                                                                                     'attribute',
                                                                             'supported_platforms': ['macos',
                                                                                                     'linux']}],
                                                           'attack_technique': 'T1222',
                                                           'display_name': 'File '
                                                                           'Permissions '
                                                                           'Modification'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [APT32](../actors/APT32.md)

