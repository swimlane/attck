
# File and Directory Discovery

## Description

### MITRE Description

> Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Many command shell utilities can be used to obtain this information. Examples include <code>dir</code>, <code>tree</code>, <code>ls</code>, <code>find</code>, and <code>locate</code>. (Citation: Windows Commands JPCERT) Custom tools may also be used to gather file and directory information and interact with the [Native API](https://attack.mitre.org/techniques/T1106).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1083

## Potential Commands

```
dir /s c:\ >> %temp%\download
dir /s "c:\Documents and Settings" >> %temp%\download
dir /s "c:\Program Files\" >> %temp%\download
dir "%systemdrive%\Users\*.*" >> %temp%\download
dir "%userprofile%\AppData\Roaming\Microsoft\Windows\Recent\*.*" >> %temp%\download
dir "%userprofile%\Desktop\*.*" >> %temp%\download
tree /F >> %temp%\download

ls -recurse
get-childitem -recurse
gci -recurse

ls -a >> /tmp/T1083.txt
if [ -d /Library/Preferences/ ]; then ls -la /Library/Preferences/ > /tmp/T1083.txt; fi;
file */* *>> /tmp/T1083.txt
cat /tmp/T1083.txt 2>/dev/null
find . -type f
ls -R | grep ":$" | sed -e 's/:$//' -e 's/[^-][^\/]*\//--/g' -e 's/^/ /' -e 's/-/|/'
locate *
which sh

cd $HOME && find . -print | sed -e 's;[^/]*/;|__;g;s;__|; |;g' > /tmp/T1083.txt
if [ -f /etc/mtab ]; then cat /etc/mtab >> /tmp/T1083.txt; fi;
find . -type f -iname *.pdf >> /tmp/T1083.txt
cat /tmp/T1083.txt
find . -type f -name ".*"

{'windows': {'psh': {'command': 'Get-ChildItem -Path #{host.system.path}\n'}}}
powershell/collection/file_finder
powershell/collection/file_finder
powershell/collection/find_interesting_file
powershell/collection/find_interesting_file
powershell/collection/get_indexed_item
powershell/collection/get_indexed_item
powershell/situational_awareness/network/powerview/get_fileserver
powershell/situational_awareness/network/powerview/get_fileserver
```

## Commands Dataset

```
[{'command': 'dir /s c:\\ >> %temp%\\download\n'
             'dir /s "c:\\Documents and Settings" >> %temp%\\download\n'
             'dir /s "c:\\Program Files\\" >> %temp%\\download\n'
             'dir "%systemdrive%\\Users\\*.*" >> %temp%\\download\n'
             'dir '
             '"%userprofile%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.*" '
             '>> %temp%\\download\n'
             'dir "%userprofile%\\Desktop\\*.*" >> %temp%\\download\n'
             'tree /F >> %temp%\\download\n',
  'name': None,
  'source': 'atomics/T1083/T1083.yaml'},
 {'command': 'ls -recurse\nget-childitem -recurse\ngci -recurse\n',
  'name': None,
  'source': 'atomics/T1083/T1083.yaml'},
 {'command': 'ls -a >> /tmp/T1083.txt\n'
             'if [ -d /Library/Preferences/ ]; then ls -la '
             '/Library/Preferences/ > /tmp/T1083.txt; fi;\n'
             'file */* *>> /tmp/T1083.txt\n'
             'cat /tmp/T1083.txt 2>/dev/null\n'
             'find . -type f\n'
             'ls -R | grep ":$" | sed -e \'s/:$//\' -e '
             "'s/[^-][^\\/]*\\//--/g' -e 's/^/ /' -e 's/-/|/'\n"
             'locate *\n'
             'which sh\n',
  'name': None,
  'source': 'atomics/T1083/T1083.yaml'},
 {'command': "cd $HOME && find . -print | sed -e 's;[^/]*/;|__;g;s;__|; |;g' > "
             '/tmp/T1083.txt\n'
             'if [ -f /etc/mtab ]; then cat /etc/mtab >> /tmp/T1083.txt; fi;\n'
             'find . -type f -iname *.pdf >> /tmp/T1083.txt\n'
             'cat /tmp/T1083.txt\n'
             'find . -type f -name ".*"\n',
  'name': None,
  'source': 'atomics/T1083/T1083.yaml'},
 {'command': {'windows': {'psh': {'command': 'Get-ChildItem -Path '
                                             '#{host.system.path}\n'}}},
  'name': 'Find or discover files on the file system',
  'source': 'data/abilities/discovery/1c353eb4-29ab-4dfe-88ed-f34f5a60848e.yml'},
 {'command': 'powershell/collection/file_finder',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/file_finder',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/find_interesting_file',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/find_interesting_file',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/get_indexed_item',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/get_indexed_item',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_fileserver',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_fileserver',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - File and Directory Discovery': {'atomic_tests': [{'auto_generated_guid': '0e36303b-6762-4500-b003-127743b80ba6',
                                                                            'description': 'Find '
                                                                                           'or '
                                                                                           'discover '
                                                                                           'files '
                                                                                           'on '
                                                                                           'the '
                                                                                           'file '
                                                                                           'system.  '
                                                                                           'Upon '
                                                                                           'execution, '
                                                                                           'the '
                                                                                           'file '
                                                                                           '"download" '
                                                                                           'will '
                                                                                           'be '
                                                                                           'placed '
                                                                                           'in '
                                                                                           'the '
                                                                                           'temporary '
                                                                                           'folder '
                                                                                           'and '
                                                                                           'contain '
                                                                                           'the '
                                                                                           'output '
                                                                                           'of\n'
                                                                                           'all '
                                                                                           'of '
                                                                                           'the '
                                                                                           'data '
                                                                                           'discovery '
                                                                                           'commands.\n',
                                                                            'executor': {'command': 'dir '
                                                                                                    '/s '
                                                                                                    'c:\\ '
                                                                                                    '>> '
                                                                                                    '%temp%\\download\n'
                                                                                                    'dir '
                                                                                                    '/s '
                                                                                                    '"c:\\Documents '
                                                                                                    'and '
                                                                                                    'Settings" '
                                                                                                    '>> '
                                                                                                    '%temp%\\download\n'
                                                                                                    'dir '
                                                                                                    '/s '
                                                                                                    '"c:\\Program '
                                                                                                    'Files\\" '
                                                                                                    '>> '
                                                                                                    '%temp%\\download\n'
                                                                                                    'dir '
                                                                                                    '"%systemdrive%\\Users\\*.*" '
                                                                                                    '>> '
                                                                                                    '%temp%\\download\n'
                                                                                                    'dir '
                                                                                                    '"%userprofile%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.*" '
                                                                                                    '>> '
                                                                                                    '%temp%\\download\n'
                                                                                                    'dir '
                                                                                                    '"%userprofile%\\Desktop\\*.*" '
                                                                                                    '>> '
                                                                                                    '%temp%\\download\n'
                                                                                                    'tree '
                                                                                                    '/F '
                                                                                                    '>> '
                                                                                                    '%temp%\\download\n',
                                                                                         'name': 'command_prompt'},
                                                                            'name': 'File '
                                                                                    'and '
                                                                                    'Directory '
                                                                                    'Discovery '
                                                                                    '(cmd.exe)',
                                                                            'supported_platforms': ['windows']},
                                                                           {'auto_generated_guid': '2158908e-b7ef-4c21-8a83-3ce4dd05a924',
                                                                            'description': 'Find '
                                                                                           'or '
                                                                                           'discover '
                                                                                           'files '
                                                                                           'on '
                                                                                           'the '
                                                                                           'file '
                                                                                           'system. '
                                                                                           'Upon '
                                                                                           'execution, '
                                                                                           'file '
                                                                                           'and '
                                                                                           'folder '
                                                                                           'information '
                                                                                           'will '
                                                                                           'be '
                                                                                           'displayed.\n',
                                                                            'executor': {'command': 'ls '
                                                                                                    '-recurse\n'
                                                                                                    'get-childitem '
                                                                                                    '-recurse\n'
                                                                                                    'gci '
                                                                                                    '-recurse\n',
                                                                                         'name': 'powershell'},
                                                                            'name': 'File '
                                                                                    'and '
                                                                                    'Directory '
                                                                                    'Discovery '
                                                                                    '(PowerShell)',
                                                                            'supported_platforms': ['windows']},
                                                                           {'auto_generated_guid': 'ffc8b249-372a-4b74-adcd-e4c0430842de',
                                                                            'description': 'Find '
                                                                                           'or '
                                                                                           'discover '
                                                                                           'files '
                                                                                           'on '
                                                                                           'the '
                                                                                           'file '
                                                                                           'system\n'
                                                                                           '\n'
                                                                                           'References:\n'
                                                                                           '\n'
                                                                                           'http://osxdaily.com/2013/01/29/list-all-files-subdirectory-contents-recursively/\n'
                                                                                           '\n'
                                                                                           'https://perishablepress.com/list-files-folders-recursively-terminal/\n',
                                                                            'executor': {'cleanup_command': 'rm '
                                                                                                            '#{output_file}\n',
                                                                                         'command': 'ls '
                                                                                                    '-a '
                                                                                                    '>> '
                                                                                                    '#{output_file}\n'
                                                                                                    'if '
                                                                                                    '[ '
                                                                                                    '-d '
                                                                                                    '/Library/Preferences/ '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'ls '
                                                                                                    '-la '
                                                                                                    '/Library/Preferences/ '
                                                                                                    '> '
                                                                                                    '#{output_file}; '
                                                                                                    'fi;\n'
                                                                                                    'file '
                                                                                                    '*/* '
                                                                                                    '*>> '
                                                                                                    '#{output_file}\n'
                                                                                                    'cat '
                                                                                                    '#{output_file} '
                                                                                                    '2>/dev/null\n'
                                                                                                    'find '
                                                                                                    '. '
                                                                                                    '-type '
                                                                                                    'f\n'
                                                                                                    'ls '
                                                                                                    '-R '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '":$" '
                                                                                                    '| '
                                                                                                    'sed '
                                                                                                    '-e '
                                                                                                    "'s/:$//' "
                                                                                                    '-e '
                                                                                                    "'s/[^-][^\\/]*\\//--/g' "
                                                                                                    '-e '
                                                                                                    "'s/^/ "
                                                                                                    "/' "
                                                                                                    '-e '
                                                                                                    "'s/-/|/'\n"
                                                                                                    'locate '
                                                                                                    '*\n'
                                                                                                    'which '
                                                                                                    'sh\n',
                                                                                         'name': 'sh'},
                                                                            'input_arguments': {'output_file': {'default': '/tmp/T1083.txt',
                                                                                                                'description': 'Output '
                                                                                                                               'file '
                                                                                                                               'used '
                                                                                                                               'to '
                                                                                                                               'store '
                                                                                                                               'the '
                                                                                                                               'results.',
                                                                                                                'type': 'path'}},
                                                                            'name': 'Nix '
                                                                                    'File '
                                                                                    'and '
                                                                                    'Diectory '
                                                                                    'Discovery',
                                                                            'supported_platforms': ['macos',
                                                                                                    'linux']},
                                                                           {'auto_generated_guid': '13c5e1ae-605b-46c4-a79f-db28c77ff24e',
                                                                            'description': 'Find '
                                                                                           'or '
                                                                                           'discover '
                                                                                           'files '
                                                                                           'on '
                                                                                           'the '
                                                                                           'file '
                                                                                           'system\n',
                                                                            'executor': {'cleanup_command': 'rm '
                                                                                                            '#{output_file}',
                                                                                         'command': 'cd '
                                                                                                    '$HOME '
                                                                                                    '&& '
                                                                                                    'find '
                                                                                                    '. '
                                                                                                    '-print '
                                                                                                    '| '
                                                                                                    'sed '
                                                                                                    '-e '
                                                                                                    "'s;[^/]*/;|__;g;s;__|; "
                                                                                                    "|;g' "
                                                                                                    '> '
                                                                                                    '#{output_file}\n'
                                                                                                    'if '
                                                                                                    '[ '
                                                                                                    '-f '
                                                                                                    '/etc/mtab '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'cat '
                                                                                                    '/etc/mtab '
                                                                                                    '>> '
                                                                                                    '#{output_file}; '
                                                                                                    'fi;\n'
                                                                                                    'find '
                                                                                                    '. '
                                                                                                    '-type '
                                                                                                    'f '
                                                                                                    '-iname '
                                                                                                    '*.pdf '
                                                                                                    '>> '
                                                                                                    '#{output_file}\n'
                                                                                                    'cat '
                                                                                                    '#{output_file}\n'
                                                                                                    'find '
                                                                                                    '. '
                                                                                                    '-type '
                                                                                                    'f '
                                                                                                    '-name '
                                                                                                    '".*"\n',
                                                                                         'name': 'sh'},
                                                                            'input_arguments': {'output_file': {'default': '/tmp/T1083.txt',
                                                                                                                'description': 'Output '
                                                                                                                               'file '
                                                                                                                               'used '
                                                                                                                               'to '
                                                                                                                               'store '
                                                                                                                               'the '
                                                                                                                               'results.',
                                                                                                                'type': 'path'}},
                                                                            'name': 'Nix '
                                                                                    'File '
                                                                                    'and '
                                                                                    'Directory '
                                                                                    'Discovery '
                                                                                    '2',
                                                                            'supported_platforms': ['macos',
                                                                                                    'linux']}],
                                                          'attack_technique': 'T1083',
                                                          'display_name': 'File '
                                                                          'and '
                                                                          'Directory '
                                                                          'Discovery'}},
 {'Mitre Stockpile - Find or discover files on the file system': {'description': 'Find '
                                                                                 'or '
                                                                                 'discover '
                                                                                 'files '
                                                                                 'on '
                                                                                 'the '
                                                                                 'file '
                                                                                 'system',
                                                                  'id': '1c353eb4-29ab-4dfe-88ed-f34f5a60848e',
                                                                  'name': 'File '
                                                                          'and '
                                                                          'Directory '
                                                                          'Discovery',
                                                                  'platforms': {'windows': {'psh': {'command': 'Get-ChildItem '
                                                                                                               '-Path '
                                                                                                               '#{host.system.path}\n'}}},
                                                                  'requirements': [{'plugins.stockpile.app.requirements.paw_provenance': [{'source': 'host.system.path'}]}],
                                                                  'tactic': 'discovery',
                                                                  'technique': {'attack_id': 'T1083',
                                                                                'name': 'File '
                                                                                        'and '
                                                                                        'Directory '
                                                                                        'Discovery'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1083',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/file_finder":  '
                                                                                 '["T1083"],',
                                            'Empire Module': 'powershell/collection/file_finder',
                                            'Technique': 'File and Directory '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1083',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/find_interesting_file":  '
                                                                                 '["T1083"],',
                                            'Empire Module': 'powershell/collection/find_interesting_file',
                                            'Technique': 'File and Directory '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1083',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/get_indexed_item":  '
                                                                                 '["T1083"],',
                                            'Empire Module': 'powershell/collection/get_indexed_item',
                                            'Technique': 'File and Directory '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1083',
                                            'ATT&CK Technique #2': 'T1135',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_fileserver":  '
                                                                                 '["T1083","T1135"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_fileserver',
                                            'Technique': 'File and Directory '
                                                         'Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [File and Directory Discovery Mitigation](../mitigations/File-and-Directory-Discovery-Mitigation.md)


# Actors


* [Patchwork](../actors/Patchwork.md)

* [Magic Hound](../actors/Magic-Hound.md)
    
* [APT28](../actors/APT28.md)
    
* [APT3](../actors/APT3.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Turla](../actors/Turla.md)
    
* [Sowbug](../actors/Sowbug.md)
    
* [Leafminer](../actors/Leafminer.md)
    
* [APT18](../actors/APT18.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Dark Caracal](../actors/Dark-Caracal.md)
    
* [admin@338](../actors/admin@338.md)
    
* [Dust Storm](../actors/Dust-Storm.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [APT32](../actors/APT32.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [APT41](../actors/APT41.md)
    
* [Inception](../actors/Inception.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
