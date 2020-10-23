
# Windows File and Directory Permissions Modification

## Description

### MITRE Description

> Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.(Citation: Hybrid Analysis Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).

Windows implements file and directory ACLs as Discretionary Access Control Lists (DACLs).(Citation: Microsoft DACL May 2018) Similar to a standard ACL, DACLs identifies the accounts that are allowed or denied access to a securable object. When an attempt is made to access a securable object, the system checks the access control entries in the DACL in order. If a matching entry is found, access to the object is granted. Otherwise, access is denied.(Citation: Microsoft Access Control Lists May 2018)

Adversaries can interact with the DACLs using built-in Windows commands, such as `icacls`, `takeown`, and `attrib`, which can grant adversaries higher permissions on specific files and folders. Further, [PowerShell](https://attack.mitre.org/techniques/T1059/001) provides cmdlets that can be used to retrieve or modify file and directory DACLs. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via [Accessibility Features](https://attack.mitre.org/techniques/T1546/008), [Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037), or tainting/hijacking other instrumental binary/configuration files via [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1222/001

## Potential Commands

```
icacls "C:\*" /grant Everyone:F /T /C /Q
icacls.exe %temp%\T1222.001_cacls /grant #{user_or_group}:F
icacls.exe #{file_or_folder} /grant Everyone:F
attrib.exe -r %temp%\T1222.001_attrib\*.* /s
takeown.exe /f %temp%\T1222.001_takeown_folder /r
```

## Commands Dataset

```
[{'command': 'takeown.exe /f %temp%\\T1222.001_takeown_folder /r\n',
  'name': None,
  'source': 'atomics/T1222.001/T1222.001.yaml'},
 {'command': 'icacls.exe %temp%\\T1222.001_cacls /grant #{user_or_group}:F\n',
  'name': None,
  'source': 'atomics/T1222.001/T1222.001.yaml'},
 {'command': 'icacls.exe #{file_or_folder} /grant Everyone:F\n',
  'name': None,
  'source': 'atomics/T1222.001/T1222.001.yaml'},
 {'command': 'attrib.exe -r %temp%\\T1222.001_attrib\\*.* /s\n',
  'name': None,
  'source': 'atomics/T1222.001/T1222.001.yaml'},
 {'command': 'icacls "C:\\*" /grant Everyone:F /T /C /Q',
  'name': None,
  'source': 'atomics/T1222.001/T1222.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - File and Directory Permissions Modification: Windows File and Directory Permissions Modification': {'atomic_tests': [{'auto_generated_guid': '98d34bb4-6e75-42ad-9c41-1dae7dc6a001',
                                                                                                                                                'dependencies': [{'description': 'Test '
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
                                                                                                                                                                                        'T1222.001_takeown1 '
                                                                                                                                                                                        '>> '
                                                                                                                                                                                        '#{file_folder_to_own}\\T1222.001_takeown1.txt\n'
                                                                                                                                                                                        'echo '
                                                                                                                                                                                        'T1222.001_takeown2 '
                                                                                                                                                                                        '>> '
                                                                                                                                                                                        '#{file_folder_to_own}\\T1222.001_takeown2.txt\n',
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
                                                                                                                                                'input_arguments': {'file_folder_to_own': {'default': '%temp%\\T1222.001_takeown_folder',
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
                                                                                                                                               {'auto_generated_guid': 'a8206bcc-f282-40a9-a389-05d9c0263485',
                                                                                                                                                'dependencies': [{'description': 'Test '
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
                                                                                                                                                                                        'T1222.001_cacls1 '
                                                                                                                                                                                        '>> '
                                                                                                                                                                                        '#{file_or_folder}\\T1222.001_cacls1.txt\n'
                                                                                                                                                                                        'echo '
                                                                                                                                                                                        'T1222.001_cacls2 '
                                                                                                                                                                                        '>> '
                                                                                                                                                                                        '#{file_or_folder}\\T1222.001_cacls2.txt\n',
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
                                                                                                                                                'executor': {'command': 'icacls.exe '
                                                                                                                                                                        '#{file_or_folder} '
                                                                                                                                                                        '/grant '
                                                                                                                                                                        '#{user_or_group}:F\n',
                                                                                                                                                             'name': 'command_prompt'},
                                                                                                                                                'input_arguments': {'file_or_folder': {'default': '%temp%\\T1222.001_cacls',
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
                                                                                                                                               {'auto_generated_guid': 'bec1e95c-83aa-492e-ab77-60c71bbd21b0',
                                                                                                                                                'dependencies': [{'description': 'Test '
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
                                                                                                                                                                                        'T1222.001_attrib1 '
                                                                                                                                                                                        '>> '
                                                                                                                                                                                        '#{file_or_folder}\\T1222.001_attrib1.txt\n'
                                                                                                                                                                                        'echo '
                                                                                                                                                                                        'T1222.001_attrib2 '
                                                                                                                                                                                        '>> '
                                                                                                                                                                                        '#{file_or_folder}\\T1222.001_attrib2.txt\n'
                                                                                                                                                                                        'attrib.exe '
                                                                                                                                                                                        '+r '
                                                                                                                                                                                        '#{file_or_folder}\\T1222.001_attrib1.txt\n'
                                                                                                                                                                                        'attrib.exe '
                                                                                                                                                                                        '+r '
                                                                                                                                                                                        '#{file_or_folder}\\T1222.001_attrib2.txt\n',
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
                                                                                                                                                'input_arguments': {'file_or_folder': {'default': '%temp%\\T1222.001_attrib',
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
                                                                                                                                               {'auto_generated_guid': 'ac7e6118-473d-41ec-9ac0-ef4f1d1ed2f6',
                                                                                                                                                'description': 'Invokes '
                                                                                                                                                               'the '
                                                                                                                                                               'command '
                                                                                                                                                               'line '
                                                                                                                                                               'used '
                                                                                                                                                               'by '
                                                                                                                                                               'Ryuk '
                                                                                                                                                               'Ransomware '
                                                                                                                                                               'to '
                                                                                                                                                               'grant '
                                                                                                                                                               'full '
                                                                                                                                                               'access '
                                                                                                                                                               'to '
                                                                                                                                                               'the '
                                                                                                                                                               'entire '
                                                                                                                                                               'C:\\ '
                                                                                                                                                               'drive '
                                                                                                                                                               'for '
                                                                                                                                                               'Everyone.',
                                                                                                                                                'executor': {'command': 'icacls '
                                                                                                                                                                        '"C:\\*" '
                                                                                                                                                                        '/grant '
                                                                                                                                                                        'Everyone:F '
                                                                                                                                                                        '/T '
                                                                                                                                                                        '/C '
                                                                                                                                                                        '/Q',
                                                                                                                                                             'name': 'powershell'},
                                                                                                                                                'name': 'Grant '
                                                                                                                                                        'Full '
                                                                                                                                                        'Access '
                                                                                                                                                        'to '
                                                                                                                                                        'Entire '
                                                                                                                                                        'C:\\ '
                                                                                                                                                        'Drive '
                                                                                                                                                        'for '
                                                                                                                                                        'Everyone '
                                                                                                                                                        '- '
                                                                                                                                                        'Ryuk '
                                                                                                                                                        'Ransomware '
                                                                                                                                                        'Style',
                                                                                                                                                'supported_platforms': ['windows']}],
                                                                                                                              'attack_technique': 'T1222.001',
                                                                                                                              'display_name': 'File '
                                                                                                                                              'and '
                                                                                                                                              'Directory '
                                                                                                                                              'Permissions '
                                                                                                                                              'Modification: '
                                                                                                                                              'Windows '
                                                                                                                                              'File '
                                                                                                                                              'and '
                                                                                                                                              'Directory '
                                                                                                                                              'Permissions '
                                                                                                                                              'Modification'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)

* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    

# Actors

None
