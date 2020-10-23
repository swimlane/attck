
# Linux and Mac File and Directory Permissions Modification

## Description

### MITRE Description

> Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.(Citation: Hybrid Analysis Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).

Most Linux and Linux-based platforms provide a standard set of permission groups (user, group, and other) and a standard set of permissions (read, write, and execute) that are applied to each group. While nuances of each platform’s permissions implementation may vary, most of the platforms provide two primary commands used to manipulate file and directory ACLs: <code>chown</code> (short for change owner), and <code>chmod</code> (short for change mode).

Adversarial may use these commands to make themselves the owner of files and directories or change the mode if current permissions allow it. They could subsequently lock others out of the file. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via [.bash_profile and .bashrc](https://attack.mitre.org/techniques/T1546/004) or tainting/hijacking other instrumental binary/configuration files via [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574).

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
* Wiki: https://attack.mitre.org/techniques/T1222/002

## Potential Commands

```
chmod #{numeric_mode} /tmp/AtomicRedTeam/atomics/T1222.002 -R
chattr -i /var/spool/cron/root
chown #{owner} /tmp/AtomicRedTeam/atomics/T1222.002 -R
chown root #{file_or_folder} -R
chown #{owner}:root #{file_or_folder} -R
chown #{owner}:root #{file_or_folder}
chown root:#{group} #{file_or_folder}
chmod 755 #{file_or_folder}
chmod #{symbolic_mode} /tmp/AtomicRedTeam/atomics/T1222.002
chmod a+w #{file_or_folder}
chmod #{symbolic_mode} /tmp/AtomicRedTeam/atomics/T1222.002 -R
chmod 755 #{file_or_folder} -R
chown root:#{group} #{file_or_folder} -R
chmod #{numeric_mode} /tmp/AtomicRedTeam/atomics/T1222.002
chmod a+w #{file_or_folder} -R
chown #{owner}:#{group} /tmp/AtomicRedTeam/atomics/T1222.002/T1222.002.yaml
chown root #{file_or_folder}
chown #{owner}:#{group} /tmp/AtomicRedTeam/atomics/T1222.002 -R
chown #{owner} /tmp/AtomicRedTeam/atomics/T1222.002/T1222.002.yaml
```

## Commands Dataset

```
[{'command': 'chmod 755 #{file_or_folder}\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chmod #{numeric_mode} /tmp/AtomicRedTeam/atomics/T1222.002\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chmod a+w #{file_or_folder}\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chmod #{symbolic_mode} /tmp/AtomicRedTeam/atomics/T1222.002\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chmod 755 #{file_or_folder} -R\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chmod #{numeric_mode} /tmp/AtomicRedTeam/atomics/T1222.002 -R\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chmod a+w #{file_or_folder} -R\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chmod #{symbolic_mode} /tmp/AtomicRedTeam/atomics/T1222.002 -R\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chown root:#{group} #{file_or_folder}\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chown #{owner}:#{group} '
             '/tmp/AtomicRedTeam/atomics/T1222.002/T1222.002.yaml\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chown #{owner}:root #{file_or_folder}\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chown root:#{group} #{file_or_folder} -R\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chown #{owner}:#{group} /tmp/AtomicRedTeam/atomics/T1222.002 '
             '-R\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chown #{owner}:root #{file_or_folder} -R\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chown root #{file_or_folder}\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chown #{owner} '
             '/tmp/AtomicRedTeam/atomics/T1222.002/T1222.002.yaml\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chown root #{file_or_folder} -R\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chown #{owner} /tmp/AtomicRedTeam/atomics/T1222.002 -R\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'},
 {'command': 'chattr -i /var/spool/cron/root\n',
  'name': None,
  'source': 'atomics/T1222.002/T1222.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification': {'atomic_tests': [{'auto_generated_guid': '34ca1464-de9d-40c6-8c77-690adf36a135',
                                                                                                                                                      'description': 'Changes '
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
                                                                                                                                                      'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222.002',
                                                                                                                                                                                             'description': 'Path '
                                                                                                                                                                                                            'of '
                                                                                                                                                                                                            'the '
                                                                                                                                                                                                            'file '
                                                                                                                                                                                                            'or '
                                                                                                                                                                                                            'folder',
                                                                                                                                                                                             'type': 'path'},
                                                                                                                                                                          'numeric_mode': {'default': '755',
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
                                                                                                                                                     {'auto_generated_guid': 'fc9d6695-d022-4a80-91b1-381f5c35aff3',
                                                                                                                                                      'description': 'Changes '
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
                                                                                                                                                      'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222.002',
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
                                                                                                                                                     {'auto_generated_guid': 'ea79f937-4a4d-4348-ace6-9916aec453a4',
                                                                                                                                                      'description': 'Changes '
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
                                                                                                                                                      'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222.002',
                                                                                                                                                                                             'description': 'Path '
                                                                                                                                                                                                            'of '
                                                                                                                                                                                                            'the '
                                                                                                                                                                                                            'file '
                                                                                                                                                                                                            'or '
                                                                                                                                                                                                            'folder',
                                                                                                                                                                                             'type': 'path'},
                                                                                                                                                                          'numeric_mode': {'default': '755',
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
                                                                                                                                                     {'auto_generated_guid': '0451125c-b5f6-488f-993b-5a32b09f7d8f',
                                                                                                                                                      'description': 'Changes '
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
                                                                                                                                                      'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222.002',
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
                                                                                                                                                     {'auto_generated_guid': 'd169e71b-85f9-44ec-8343-27093ff3dfc0',
                                                                                                                                                      'description': 'Changes '
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
                                                                                                                                                      'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222.002/T1222.002.yaml',
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
                                                                                                                                                     {'auto_generated_guid': 'b78598be-ff39-448f-a463-adbf2a5b7848',
                                                                                                                                                      'description': 'Changes '
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
                                                                                                                                                      'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222.002',
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
                                                                                                                                                     {'auto_generated_guid': '967ba79d-f184-4e0e-8d09-6362b3162e99',
                                                                                                                                                      'description': 'Changes '
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
                                                                                                                                                      'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222.002/T1222.002.yaml',
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
                                                                                                                                                     {'auto_generated_guid': '3b015515-b3d8-44e9-b8cd-6fa84faf30b2',
                                                                                                                                                      'description': 'Changes '
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
                                                                                                                                                      'input_arguments': {'file_or_folder': {'default': '/tmp/AtomicRedTeam/atomics/T1222.002',
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
                                                                                                                                                     {'auto_generated_guid': 'e7469fe2-ad41-4382-8965-99b94dd3c13f',
                                                                                                                                                      'description': "Remove's "
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
                                                                                                                                    'attack_technique': 'T1222.002',
                                                                                                                                    'display_name': 'File '
                                                                                                                                                    'and '
                                                                                                                                                    'Directory '
                                                                                                                                                    'Permissions '
                                                                                                                                                    'Modification: '
                                                                                                                                                    'Linux '
                                                                                                                                                    'and '
                                                                                                                                                    'Mac '
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


* [APT32](../actors/APT32.md)

* [Rocke](../actors/Rocke.md)
    
