
# Hidden Files and Directories

## Description

### MITRE Description

> Adversaries may set files and directories to be hidden to evade detection mechanisms. To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (<code>dir /a</code> for Windows and <code>ls –a</code> for Linux and macOS).

On Linux and Mac, users can mark specific files as hidden simply by putting a “.” as the first character in the file or folder name  (Citation: Sofacy Komplex Trojan) (Citation: Antiquated Mac Malware). Files and folders that start with a period, ‘.’, are by default hidden from being viewed in the Finder application and standard command-line utilities like “ls”. Users must specifically change settings to have these files viewable.

Files on macOS can also be marked with the UF_HIDDEN flag which prevents them from being seen in Finder.app, but still allows them to be seen in Terminal.app (Citation: WireLurker). On Windows, users can mark specific files as hidden by using the attrib.exe binary. Many applications create these hidden files and folders to store information so that it doesn’t clutter up the user’s workspace. For example, SSH utilities create a .ssh folder that’s hidden and contains the user’s known hosts and keys.

Adversaries can use this to their advantage to hide files and folders anywhere on the system and evading a typical user or system analysis that does not incorporate investigation of hidden files.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Host forensic analysis']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows', 'macOS', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1564/001

## Potential Commands

```
xattr -lr * / 2>&1 /dev/null | grep -C 2 "00 00 00 00 00 00 00 00 40 00 FF FF FF FF 00 00"
setfile -a V /tmp/evil
attrib.exe +s %temp%\T1564.001.txt
attrib.exe +h %temp%\T1564.001.txt
touch /var/tmp/T1564.001_mac.txt
chflags hidden /var/tmp/T1564.001_mac.txt
mkdir /var/tmp/.hidden-directory
echo "T1564.001" > /var/tmp/.hidden-directory/.hidden-file
defaults write com.apple.finder AppleShowAllFiles YES
```

## Commands Dataset

```
[{'command': 'mkdir /var/tmp/.hidden-directory\n'
             'echo "T1564.001" > /var/tmp/.hidden-directory/.hidden-file\n',
  'name': None,
  'source': 'atomics/T1564.001/T1564.001.yaml'},
 {'command': 'xattr -lr * / 2>&1 /dev/null | grep -C 2 "00 00 00 00 00 00 00 '
             '00 40 00 FF FF FF FF 00 00"\n',
  'name': None,
  'source': 'atomics/T1564.001/T1564.001.yaml'},
 {'command': 'attrib.exe +s %temp%\\T1564.001.txt\n',
  'name': None,
  'source': 'atomics/T1564.001/T1564.001.yaml'},
 {'command': 'attrib.exe +h %temp%\\T1564.001.txt\n',
  'name': None,
  'source': 'atomics/T1564.001/T1564.001.yaml'},
 {'command': 'setfile -a V /tmp/evil\n',
  'name': None,
  'source': 'atomics/T1564.001/T1564.001.yaml'},
 {'command': 'touch /var/tmp/T1564.001_mac.txt\n'
             'chflags hidden /var/tmp/T1564.001_mac.txt\n',
  'name': None,
  'source': 'atomics/T1564.001/T1564.001.yaml'},
 {'command': 'defaults write com.apple.finder AppleShowAllFiles YES\n',
  'name': None,
  'source': 'atomics/T1564.001/T1564.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Hide Artifacts: Hidden Files and Directories': {'atomic_tests': [{'auto_generated_guid': '61a782e5-9a19-40b5-8ba4-69a4b9f3d7be',
                                                                                            'description': 'Creates '
                                                                                                           'a '
                                                                                                           'hidden '
                                                                                                           'file '
                                                                                                           'inside '
                                                                                                           'a '
                                                                                                           'hidden '
                                                                                                           'directory\n',
                                                                                            'executor': {'cleanup_command': 'rm '
                                                                                                                            '-rf '
                                                                                                                            '/var/tmp/.hidden-directory/\n',
                                                                                                         'command': 'mkdir '
                                                                                                                    '/var/tmp/.hidden-directory\n'
                                                                                                                    'echo '
                                                                                                                    '"T1564.001" '
                                                                                                                    '> '
                                                                                                                    '/var/tmp/.hidden-directory/.hidden-file\n',
                                                                                                         'name': 'sh'},
                                                                                            'name': 'Create '
                                                                                                    'a '
                                                                                                    'hidden '
                                                                                                    'file '
                                                                                                    'in '
                                                                                                    'a '
                                                                                                    'hidden '
                                                                                                    'directory',
                                                                                            'supported_platforms': ['linux',
                                                                                                                    'macos']},
                                                                                           {'auto_generated_guid': 'cddb9098-3b47-4e01-9d3b-6f5f323288a9',
                                                                                            'description': 'Hide '
                                                                                                           'a '
                                                                                                           'file '
                                                                                                           'on '
                                                                                                           'MacOS\n',
                                                                                            'executor': {'command': 'xattr '
                                                                                                                    '-lr '
                                                                                                                    '* '
                                                                                                                    '/ '
                                                                                                                    '2>&1 '
                                                                                                                    '/dev/null '
                                                                                                                    '| '
                                                                                                                    'grep '
                                                                                                                    '-C '
                                                                                                                    '2 '
                                                                                                                    '"00 '
                                                                                                                    '00 '
                                                                                                                    '00 '
                                                                                                                    '00 '
                                                                                                                    '00 '
                                                                                                                    '00 '
                                                                                                                    '00 '
                                                                                                                    '00 '
                                                                                                                    '40 '
                                                                                                                    '00 '
                                                                                                                    'FF '
                                                                                                                    'FF '
                                                                                                                    'FF '
                                                                                                                    'FF '
                                                                                                                    '00 '
                                                                                                                    '00"\n',
                                                                                                         'name': 'sh'},
                                                                                            'name': 'Mac '
                                                                                                    'Hidden '
                                                                                                    'file',
                                                                                            'supported_platforms': ['macos']},
                                                                                           {'auto_generated_guid': 'f70974c8-c094-4574-b542-2c545af95a32',
                                                                                            'dependencies': [{'description': 'The '
                                                                                                                             'file '
                                                                                                                             'must '
                                                                                                                             'exist '
                                                                                                                             'on '
                                                                                                                             'disk '
                                                                                                                             'at '
                                                                                                                             'specified '
                                                                                                                             'location '
                                                                                                                             '(#{file_to_modify})\n',
                                                                                                              'get_prereq_command': 'echo '
                                                                                                                                    'system_Attrib_T1564.001 '
                                                                                                                                    '>> '
                                                                                                                                    '#{file_to_modify}\n',
                                                                                                              'prereq_command': 'IF '
                                                                                                                                'EXIST '
                                                                                                                                '#{file_to_modify} '
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
                                                                                            'description': 'Creates '
                                                                                                           'a '
                                                                                                           'file '
                                                                                                           'and '
                                                                                                           'marks '
                                                                                                           'it '
                                                                                                           'as '
                                                                                                           'a '
                                                                                                           'system '
                                                                                                           'file '
                                                                                                           'using '
                                                                                                           'the '
                                                                                                           'attrib.exe '
                                                                                                           'utility. '
                                                                                                           'Upon '
                                                                                                           'execution, '
                                                                                                           'open '
                                                                                                           'the '
                                                                                                           'file '
                                                                                                           'in '
                                                                                                           'file '
                                                                                                           'explorer '
                                                                                                           'then '
                                                                                                           'open '
                                                                                                           'Properties '
                                                                                                           '> '
                                                                                                           'Details\n'
                                                                                                           'and '
                                                                                                           'observe '
                                                                                                           'that '
                                                                                                           'the '
                                                                                                           'Attributes '
                                                                                                           'are '
                                                                                                           '"SA" '
                                                                                                           'for '
                                                                                                           'System '
                                                                                                           'and '
                                                                                                           'Archive.\n',
                                                                                            'executor': {'cleanup_command': 'del '
                                                                                                                            '/A:S '
                                                                                                                            '#{file_to_modify} '
                                                                                                                            '>nul '
                                                                                                                            '2>&1\n',
                                                                                                         'command': 'attrib.exe '
                                                                                                                    '+s '
                                                                                                                    '#{file_to_modify}\n',
                                                                                                         'elevation_required': True,
                                                                                                         'name': 'command_prompt'},
                                                                                            'input_arguments': {'file_to_modify': {'default': '%temp%\\T1564.001.txt',
                                                                                                                                   'description': 'File '
                                                                                                                                                  'to '
                                                                                                                                                  'modify '
                                                                                                                                                  'using '
                                                                                                                                                  'Attrib '
                                                                                                                                                  'command',
                                                                                                                                   'type': 'string'}},
                                                                                            'name': 'Create '
                                                                                                    'Windows '
                                                                                                    'System '
                                                                                                    'File '
                                                                                                    'with '
                                                                                                    'Attrib',
                                                                                            'supported_platforms': ['windows']},
                                                                                           {'auto_generated_guid': 'dadb792e-4358-4d8d-9207-b771faa0daa5',
                                                                                            'dependencies': [{'description': 'The '
                                                                                                                             'file '
                                                                                                                             'must '
                                                                                                                             'exist '
                                                                                                                             'on '
                                                                                                                             'disk '
                                                                                                                             'at '
                                                                                                                             'specified '
                                                                                                                             'location '
                                                                                                                             '(#{file_to_modify})\n',
                                                                                                              'get_prereq_command': 'echo '
                                                                                                                                    'system_Attrib_T1564.001 '
                                                                                                                                    '>> '
                                                                                                                                    '#{file_to_modify}\n',
                                                                                                              'prereq_command': 'IF '
                                                                                                                                'EXIST '
                                                                                                                                '#{file_to_modify} '
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
                                                                                            'description': 'Creates '
                                                                                                           'a '
                                                                                                           'file '
                                                                                                           'and '
                                                                                                           'marks '
                                                                                                           'it '
                                                                                                           'as '
                                                                                                           'hidden '
                                                                                                           'using '
                                                                                                           'the '
                                                                                                           'attrib.exe '
                                                                                                           'utility.Upon '
                                                                                                           'execution, '
                                                                                                           'open '
                                                                                                           'File '
                                                                                                           'Epxplorer '
                                                                                                           'and '
                                                                                                           'enable '
                                                                                                           'View '
                                                                                                           '> '
                                                                                                           'Hidden '
                                                                                                           'Items. '
                                                                                                           'Then, '
                                                                                                           'open '
                                                                                                           'Properties '
                                                                                                           '> '
                                                                                                           'Details '
                                                                                                           'on '
                                                                                                           'the '
                                                                                                           'file\n'
                                                                                                           'and '
                                                                                                           'observe '
                                                                                                           'that '
                                                                                                           'the '
                                                                                                           'Attributes '
                                                                                                           'are '
                                                                                                           '"SH" '
                                                                                                           'for '
                                                                                                           'System '
                                                                                                           'and '
                                                                                                           'Hidden.\n',
                                                                                            'executor': {'cleanup_command': 'del '
                                                                                                                            '/A:H '
                                                                                                                            '#{file_to_modify} '
                                                                                                                            '>nul '
                                                                                                                            '2>&1\n',
                                                                                                         'command': 'attrib.exe '
                                                                                                                    '+h '
                                                                                                                    '#{file_to_modify}\n',
                                                                                                         'elevation_required': True,
                                                                                                         'name': 'command_prompt'},
                                                                                            'input_arguments': {'file_to_modify': {'default': '%temp%\\T1564.001.txt',
                                                                                                                                   'description': 'File '
                                                                                                                                                  'to '
                                                                                                                                                  'modify '
                                                                                                                                                  'using '
                                                                                                                                                  'Attrib '
                                                                                                                                                  'command',
                                                                                                                                   'type': 'string'}},
                                                                                            'name': 'Create '
                                                                                                    'Windows '
                                                                                                    'Hidden '
                                                                                                    'File '
                                                                                                    'with '
                                                                                                    'Attrib',
                                                                                            'supported_platforms': ['windows']},
                                                                                           {'auto_generated_guid': '3b7015f2-3144-4205-b799-b05580621379',
                                                                                            'description': 'Requires '
                                                                                                           'Apple '
                                                                                                           'Dev '
                                                                                                           'Tools\n',
                                                                                            'executor': {'command': 'setfile '
                                                                                                                    '-a '
                                                                                                                    'V '
                                                                                                                    '#{filename}\n',
                                                                                                         'name': 'sh'},
                                                                                            'input_arguments': {'filename': {'default': '/tmp/evil',
                                                                                                                             'description': 'path '
                                                                                                                                            'of '
                                                                                                                                            'file '
                                                                                                                                            'to '
                                                                                                                                            'hide',
                                                                                                                             'type': 'path'}},
                                                                                            'name': 'Hidden '
                                                                                                    'files',
                                                                                            'supported_platforms': ['macos']},
                                                                                           {'auto_generated_guid': 'b115ecaf-3b24-4ed2-aefe-2fcb9db913d3',
                                                                                            'description': 'Hide '
                                                                                                           'a '
                                                                                                           'directory '
                                                                                                           'on '
                                                                                                           'MacOS\n',
                                                                                            'executor': {'cleanup_command': 'rm '
                                                                                                                            '/var/tmp/T1564.001_mac.txt\n',
                                                                                                         'command': 'touch '
                                                                                                                    '/var/tmp/T1564.001_mac.txt\n'
                                                                                                                    'chflags '
                                                                                                                    'hidden '
                                                                                                                    '/var/tmp/T1564.001_mac.txt\n',
                                                                                                         'name': 'sh'},
                                                                                            'name': 'Hide '
                                                                                                    'a '
                                                                                                    'Directory',
                                                                                            'supported_platforms': ['macos']},
                                                                                           {'auto_generated_guid': '9a1ec7da-b892-449f-ad68-67066d04380c',
                                                                                            'description': 'Show '
                                                                                                           'all '
                                                                                                           'hidden '
                                                                                                           'files '
                                                                                                           'on '
                                                                                                           'MacOS\n',
                                                                                            'executor': {'cleanup_command': 'defaults '
                                                                                                                            'write '
                                                                                                                            'com.apple.finder '
                                                                                                                            'AppleShowAllFiles '
                                                                                                                            'NO\n',
                                                                                                         'command': 'defaults '
                                                                                                                    'write '
                                                                                                                    'com.apple.finder '
                                                                                                                    'AppleShowAllFiles '
                                                                                                                    'YES\n',
                                                                                                         'name': 'sh'},
                                                                                            'name': 'Show '
                                                                                                    'all '
                                                                                                    'hidden '
                                                                                                    'files',
                                                                                            'supported_platforms': ['macos']}],
                                                                          'attack_technique': 'T1564.001',
                                                                          'display_name': 'Hide '
                                                                                          'Artifacts: '
                                                                                          'Hidden '
                                                                                          'Files '
                                                                                          'and '
                                                                                          'Directories'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [APT28](../actors/APT28.md)

* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [APT32](../actors/APT32.md)
    
* [Rocke](../actors/Rocke.md)
    
