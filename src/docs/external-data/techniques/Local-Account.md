
# Local Account

## Description

### MITRE Description

> Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.

Commands such as <code>net user</code> and <code>net localgroup</code> of the [Net](https://attack.mitre.org/software/S0039) utility and <code>id</code> and <code>groups</code>on macOS and Linux can list local users and groups. On Linux, local users can also be enumerated through the use of the <code>/etc/passwd</code> file.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1087/001

## Potential Commands

```
lastlog > /tmp/T1087.001.txt
cat /tmp/T1087.001.txt
groups
id
dscl . list /Groups
dscl . list /Users
dscl . list /Users | grep -v '_'
dscacheutil -q group
dscacheutil -q user
net user
dir c:\Users\
cmdkey.exe /list
net localgroup "Users"
net localgroup
query user
username=$(echo $HOME | awk -F'/' '{print $3}') && lsof -u $username
grep 'x:0:' /etc/passwd > /tmp/T1087.001.txt
cat /tmp/T1087.001.txt 2>/dev/null
net user
get-localuser
get-localgroupmember -group Users
cmdkey.exe /list
ls C:/Users
get-childitem C:\Users\
dir C:\Users\
get-localgroup
net localgroup
cat /etc/passwd > /tmp/T1087.001.txt
cat /tmp/T1087.001.txt
sudo cat /etc/sudoers > /tmp/T1087.001.txt
cat /tmp/T1087.001.txt
```

## Commands Dataset

```
[{'command': 'cat /etc/passwd > /tmp/T1087.001.txt\ncat /tmp/T1087.001.txt\n',
  'name': None,
  'source': 'atomics/T1087.001/T1087.001.yaml'},
 {'command': 'sudo cat /etc/sudoers > /tmp/T1087.001.txt\n'
             'cat /tmp/T1087.001.txt\n',
  'name': None,
  'source': 'atomics/T1087.001/T1087.001.yaml'},
 {'command': "grep 'x:0:' /etc/passwd > /tmp/T1087.001.txt\n"
             'cat /tmp/T1087.001.txt 2>/dev/null\n',
  'name': None,
  'source': 'atomics/T1087.001/T1087.001.yaml'},
 {'command': "username=$(echo $HOME | awk -F'/' '{print $3}') && lsof -u "
             '$username\n',
  'name': None,
  'source': 'atomics/T1087.001/T1087.001.yaml'},
 {'command': 'lastlog > /tmp/T1087.001.txt\ncat /tmp/T1087.001.txt\n',
  'name': None,
  'source': 'atomics/T1087.001/T1087.001.yaml'},
 {'command': 'groups\nid\n',
  'name': None,
  'source': 'atomics/T1087.001/T1087.001.yaml'},
 {'command': 'dscl . list /Groups\n'
             'dscl . list /Users\n'
             "dscl . list /Users | grep -v '_'\n"
             'dscacheutil -q group\n'
             'dscacheutil -q user\n',
  'name': None,
  'source': 'atomics/T1087.001/T1087.001.yaml'},
 {'command': 'net user\n'
             'dir c:\\Users\\\n'
             'cmdkey.exe /list\n'
             'net localgroup "Users"\n'
             'net localgroup\n',
  'name': None,
  'source': 'atomics/T1087.001/T1087.001.yaml'},
 {'command': 'net user\n'
             'get-localuser\n'
             'get-localgroupmember -group Users\n'
             'cmdkey.exe /list\n'
             'ls C:/Users\n'
             'get-childitem C:\\Users\\\n'
             'dir C:\\Users\\\n'
             'get-localgroup\n'
             'net localgroup\n',
  'name': None,
  'source': 'atomics/T1087.001/T1087.001.yaml'},
 {'command': 'query user\n',
  'name': None,
  'source': 'atomics/T1087.001/T1087.001.yaml'},
 {'command': 'query user\n',
  'name': None,
  'source': 'atomics/T1087.001/T1087.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Account Discovery: Local Account': {'atomic_tests': [{'auto_generated_guid': 'f8aab3dd-5990-4bf8-b8ab-2226c951696f',
                                                                                'description': 'Enumerate '
                                                                                               'all '
                                                                                               'accounts '
                                                                                               'by '
                                                                                               'copying '
                                                                                               '/etc/passwd '
                                                                                               'to '
                                                                                               'another '
                                                                                               'file\n',
                                                                                'executor': {'cleanup_command': 'rm '
                                                                                                                '-f '
                                                                                                                '#{output_file}\n',
                                                                                             'command': 'cat '
                                                                                                        '/etc/passwd '
                                                                                                        '> '
                                                                                                        '#{output_file}\n'
                                                                                                        'cat '
                                                                                                        '#{output_file}\n',
                                                                                             'name': 'sh'},
                                                                                'input_arguments': {'output_file': {'default': '/tmp/T1087.001.txt',
                                                                                                                    'description': 'Path '
                                                                                                                                   'where '
                                                                                                                                   'captured '
                                                                                                                                   'results '
                                                                                                                                   'will '
                                                                                                                                   'be '
                                                                                                                                   'placed',
                                                                                                                    'type': 'Path'}},
                                                                                'name': 'Enumerate '
                                                                                        'all '
                                                                                        'accounts '
                                                                                        '(Local)',
                                                                                'supported_platforms': ['linux',
                                                                                                        'macos']},
                                                                               {'auto_generated_guid': 'fed9be70-0186-4bde-9f8a-20945f9370c2',
                                                                                'description': '(requires '
                                                                                               'root)\n',
                                                                                'executor': {'cleanup_command': 'rm '
                                                                                                                '-f '
                                                                                                                '#{output_file}\n',
                                                                                             'command': 'sudo '
                                                                                                        'cat '
                                                                                                        '/etc/sudoers '
                                                                                                        '> '
                                                                                                        '#{output_file}\n'
                                                                                                        'cat '
                                                                                                        '#{output_file}\n',
                                                                                             'elevation_required': True,
                                                                                             'name': 'sh'},
                                                                                'input_arguments': {'output_file': {'default': '/tmp/T1087.001.txt',
                                                                                                                    'description': 'Path '
                                                                                                                                   'where '
                                                                                                                                   'captured '
                                                                                                                                   'results '
                                                                                                                                   'will '
                                                                                                                                   'be '
                                                                                                                                   'placed',
                                                                                                                    'type': 'Path'}},
                                                                                'name': 'View '
                                                                                        'sudoers '
                                                                                        'access',
                                                                                'supported_platforms': ['linux',
                                                                                                        'macos']},
                                                                               {'auto_generated_guid': 'c955a599-3653-4fe5-b631-f11c00eb0397',
                                                                                'description': 'View '
                                                                                               'accounts '
                                                                                               'with '
                                                                                               'UID '
                                                                                               '0\n',
                                                                                'executor': {'cleanup_command': 'rm '
                                                                                                                '-f '
                                                                                                                '#{output_file} '
                                                                                                                '2>/dev/null\n',
                                                                                             'command': 'grep '
                                                                                                        "'x:0:' "
                                                                                                        '/etc/passwd '
                                                                                                        '> '
                                                                                                        '#{output_file}\n'
                                                                                                        'cat '
                                                                                                        '#{output_file} '
                                                                                                        '2>/dev/null\n',
                                                                                             'name': 'sh'},
                                                                                'input_arguments': {'output_file': {'default': '/tmp/T1087.001.txt',
                                                                                                                    'description': 'Path '
                                                                                                                                   'where '
                                                                                                                                   'captured '
                                                                                                                                   'results '
                                                                                                                                   'will '
                                                                                                                                   'be '
                                                                                                                                   'placed',
                                                                                                                    'type': 'Path'}},
                                                                                'name': 'View '
                                                                                        'accounts '
                                                                                        'with '
                                                                                        'UID '
                                                                                        '0',
                                                                                'supported_platforms': ['linux',
                                                                                                        'macos']},
                                                                               {'auto_generated_guid': '7e46c7a5-0142-45be-a858-1a3ecb4fd3cb',
                                                                                'description': 'List '
                                                                                               'opened '
                                                                                               'files '
                                                                                               'by '
                                                                                               'user\n',
                                                                                'executor': {'command': 'username=$(echo '
                                                                                                        '$HOME '
                                                                                                        '| '
                                                                                                        'awk '
                                                                                                        "-F'/' "
                                                                                                        "'{print "
                                                                                                        "$3}') "
                                                                                                        '&& '
                                                                                                        'lsof '
                                                                                                        '-u '
                                                                                                        '$username\n',
                                                                                             'name': 'sh'},
                                                                                'name': 'List '
                                                                                        'opened '
                                                                                        'files '
                                                                                        'by '
                                                                                        'user',
                                                                                'supported_platforms': ['linux',
                                                                                                        'macos']},
                                                                               {'auto_generated_guid': '0f0b6a29-08c3-44ad-a30b-47fd996b2110',
                                                                                'dependencies': [{'description': 'Check '
                                                                                                                 'if '
                                                                                                                 'lastlog '
                                                                                                                 'command '
                                                                                                                 'exists '
                                                                                                                 'on '
                                                                                                                 'the '
                                                                                                                 'machine\n',
                                                                                                  'get_prereq_command': 'echo '
                                                                                                                        '"Install '
                                                                                                                        'lastlog '
                                                                                                                        'on '
                                                                                                                        'the '
                                                                                                                        'machine '
                                                                                                                        'to '
                                                                                                                        'run '
                                                                                                                        'the '
                                                                                                                        'test."; '
                                                                                                                        'exit '
                                                                                                                        '1;\n',
                                                                                                  'prereq_command': 'if '
                                                                                                                    '[ '
                                                                                                                    '-x '
                                                                                                                    '"$(command '
                                                                                                                    '-v '
                                                                                                                    'lastlog)" '
                                                                                                                    ']; '
                                                                                                                    'then '
                                                                                                                    'exit '
                                                                                                                    '0; '
                                                                                                                    'else '
                                                                                                                    'exit '
                                                                                                                    '1;\n'}],
                                                                                'dependency_executor_name': 'sh',
                                                                                'description': 'Show '
                                                                                               'if '
                                                                                               'a '
                                                                                               'user '
                                                                                               'account '
                                                                                               'has '
                                                                                               'ever '
                                                                                               'logged '
                                                                                               'in '
                                                                                               'remotely\n',
                                                                                'executor': {'cleanup_command': 'rm '
                                                                                                                '-f '
                                                                                                                '#{output_file}\n',
                                                                                             'command': 'lastlog '
                                                                                                        '> '
                                                                                                        '#{output_file}\n'
                                                                                                        'cat '
                                                                                                        '#{output_file}\n',
                                                                                             'name': 'sh'},
                                                                                'input_arguments': {'output_file': {'default': '/tmp/T1087.001.txt',
                                                                                                                    'description': 'Path '
                                                                                                                                   'where '
                                                                                                                                   'captured '
                                                                                                                                   'results '
                                                                                                                                   'will '
                                                                                                                                   'be '
                                                                                                                                   'placed',
                                                                                                                    'type': 'Path'}},
                                                                                'name': 'Show '
                                                                                        'if '
                                                                                        'a '
                                                                                        'user '
                                                                                        'account '
                                                                                        'has '
                                                                                        'ever '
                                                                                        'logged '
                                                                                        'in '
                                                                                        'remotely',
                                                                                'supported_platforms': ['linux']},
                                                                               {'auto_generated_guid': 'e6f36545-dc1e-47f0-9f48-7f730f54a02e',
                                                                                'description': 'Utilize '
                                                                                               'groups '
                                                                                               'and '
                                                                                               'id '
                                                                                               'to '
                                                                                               'enumerate '
                                                                                               'users '
                                                                                               'and '
                                                                                               'groups\n',
                                                                                'executor': {'command': 'groups\n'
                                                                                                        'id\n',
                                                                                             'name': 'sh'},
                                                                                'name': 'Enumerate '
                                                                                        'users '
                                                                                        'and '
                                                                                        'groups',
                                                                                'supported_platforms': ['linux',
                                                                                                        'macos']},
                                                                               {'auto_generated_guid': '319e9f6c-7a9e-432e-8c62-9385c803b6f2',
                                                                                'description': 'Utilize '
                                                                                               'local '
                                                                                               'utilities '
                                                                                               'to '
                                                                                               'enumerate '
                                                                                               'users '
                                                                                               'and '
                                                                                               'groups\n',
                                                                                'executor': {'command': 'dscl '
                                                                                                        '. '
                                                                                                        'list '
                                                                                                        '/Groups\n'
                                                                                                        'dscl '
                                                                                                        '. '
                                                                                                        'list '
                                                                                                        '/Users\n'
                                                                                                        'dscl '
                                                                                                        '. '
                                                                                                        'list '
                                                                                                        '/Users '
                                                                                                        '| '
                                                                                                        'grep '
                                                                                                        '-v '
                                                                                                        "'_'\n"
                                                                                                        'dscacheutil '
                                                                                                        '-q '
                                                                                                        'group\n'
                                                                                                        'dscacheutil '
                                                                                                        '-q '
                                                                                                        'user\n',
                                                                                             'name': 'sh'},
                                                                                'name': 'Enumerate '
                                                                                        'users '
                                                                                        'and '
                                                                                        'groups',
                                                                                'supported_platforms': ['macos']},
                                                                               {'auto_generated_guid': '80887bec-5a9b-4efc-a81d-f83eb2eb32ab',
                                                                                'description': 'Enumerate '
                                                                                               'all '
                                                                                               'accounts\n'
                                                                                               'Upon '
                                                                                               'exection, '
                                                                                               'multiple '
                                                                                               'enumeration '
                                                                                               'commands '
                                                                                               'will '
                                                                                               'be '
                                                                                               'run '
                                                                                               'and '
                                                                                               'their '
                                                                                               'output '
                                                                                               'displayed '
                                                                                               'in '
                                                                                               'the '
                                                                                               'PowerShell '
                                                                                               'session\n',
                                                                                'executor': {'command': 'net '
                                                                                                        'user\n'
                                                                                                        'dir '
                                                                                                        'c:\\Users\\\n'
                                                                                                        'cmdkey.exe '
                                                                                                        '/list\n'
                                                                                                        'net '
                                                                                                        'localgroup '
                                                                                                        '"Users"\n'
                                                                                                        'net '
                                                                                                        'localgroup\n',
                                                                                             'name': 'command_prompt'},
                                                                                'name': 'Enumerate '
                                                                                        'all '
                                                                                        'accounts '
                                                                                        'on '
                                                                                        'Windows '
                                                                                        '(Local)',
                                                                                'supported_platforms': ['windows']},
                                                                               {'auto_generated_guid': 'ae4b6361-b5f8-46cb-a3f9-9cf108ccfe7b',
                                                                                'description': 'Enumerate '
                                                                                               'all '
                                                                                               'accounts '
                                                                                               'via '
                                                                                               'PowerShell. '
                                                                                               'Upon '
                                                                                               'execution, '
                                                                                               'lots '
                                                                                               'of '
                                                                                               'user '
                                                                                               'account '
                                                                                               'and '
                                                                                               'group '
                                                                                               'information '
                                                                                               'will '
                                                                                               'be '
                                                                                               'displayed.\n',
                                                                                'executor': {'command': 'net '
                                                                                                        'user\n'
                                                                                                        'get-localuser\n'
                                                                                                        'get-localgroupmember '
                                                                                                        '-group '
                                                                                                        'Users\n'
                                                                                                        'cmdkey.exe '
                                                                                                        '/list\n'
                                                                                                        'ls '
                                                                                                        'C:/Users\n'
                                                                                                        'get-childitem '
                                                                                                        'C:\\Users\\\n'
                                                                                                        'dir '
                                                                                                        'C:\\Users\\\n'
                                                                                                        'get-localgroup\n'
                                                                                                        'net '
                                                                                                        'localgroup\n',
                                                                                             'name': 'powershell'},
                                                                                'name': 'Enumerate '
                                                                                        'all '
                                                                                        'accounts '
                                                                                        'via '
                                                                                        'PowerShell '
                                                                                        '(Local)',
                                                                                'supported_platforms': ['windows']},
                                                                               {'auto_generated_guid': 'a138085e-bfe5-46ba-a242-74a6fb884af3',
                                                                                'description': 'Enumerate '
                                                                                               'logged '
                                                                                               'on '
                                                                                               'users. '
                                                                                               'Upon '
                                                                                               'exeuction, '
                                                                                               'logged '
                                                                                               'on '
                                                                                               'users '
                                                                                               'will '
                                                                                               'be '
                                                                                               'displayed.\n',
                                                                                'executor': {'command': 'query '
                                                                                                        'user\n',
                                                                                             'name': 'command_prompt'},
                                                                                'name': 'Enumerate '
                                                                                        'logged '
                                                                                        'on '
                                                                                        'users '
                                                                                        'via '
                                                                                        'CMD '
                                                                                        '(Local)',
                                                                                'supported_platforms': ['windows']},
                                                                               {'auto_generated_guid': '2bdc42c7-8907-40c2-9c2b-42919a00fe03',
                                                                                'description': 'Enumerate '
                                                                                               'logged '
                                                                                               'on '
                                                                                               'users '
                                                                                               'via '
                                                                                               'PowerShell. '
                                                                                               'Upon '
                                                                                               'exeuction, '
                                                                                               'logged '
                                                                                               'on '
                                                                                               'users '
                                                                                               'will '
                                                                                               'be '
                                                                                               'displayed.\n',
                                                                                'executor': {'command': 'query '
                                                                                                        'user\n',
                                                                                             'name': 'powershell'},
                                                                                'name': 'Enumerate '
                                                                                        'logged '
                                                                                        'on '
                                                                                        'users '
                                                                                        'via '
                                                                                        'PowerShell',
                                                                                'supported_platforms': ['windows']}],
                                                              'attack_technique': 'T1087.001',
                                                              'display_name': 'Account '
                                                                              'Discovery: '
                                                                              'Local '
                                                                              'Account'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)


# Actors


* [APT3](../actors/APT3.md)

* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [admin@338](../actors/admin@338.md)
    
* [APT1](../actors/APT1.md)
    
* [APT32](../actors/APT32.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Poseidon Group](../actors/Poseidon-Group.md)
    
* [Turla](../actors/Turla.md)
    
