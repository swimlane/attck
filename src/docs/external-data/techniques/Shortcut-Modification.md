
# Shortcut Modification

## Description

### MITRE Description

> Shortcuts or symbolic links are ways of referencing other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process. Adversaries could use shortcuts to execute their tools for persistence. They may create a new shortcut as a means of indirection that may use [Masquerading](https://attack.mitre.org/techniques/T1036) to look like a legitimate program. Adversaries could also edit the target path or entirely replace an existing shortcut so their tools will be executed instead of the intended legitimate program.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1023

## Potential Commands

```
echo [InternetShortcut] > %temp%\T1023_modified_shortcut.url
echo URL=C:\windows\system32\calc.exe >> %temp%\T1023_modified_shortcut.url
%temp%\T1023_modified_shortcut.url

$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\T1023.lnk")
$ShortCut.TargetPath="cmd.exe"
$ShortCut.WorkingDirectory = "C:\Windows\System32";
$ShortCut.WindowStyle = 1;
$ShortCut.Description = "T1023.";
$ShortCut.Save()

$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\T1023.lnk")
$ShortCut.TargetPath="cmd.exe"
$ShortCut.WorkingDirectory = "C:\Windows\System32";
$ShortCut.WindowStyle = 1;
$ShortCut.Description = "T1023.";
$ShortCut.Save()

powershell/persistence/userland/backdoor_lnk
powershell/persistence/userland/backdoor_lnk
```

## Commands Dataset

```
[{'command': 'echo [InternetShortcut] > %temp%\\T1023_modified_shortcut.url\n'
             'echo URL=C:\\windows\\system32\\calc.exe >> '
             '%temp%\\T1023_modified_shortcut.url\n'
             '%temp%\\T1023_modified_shortcut.url\n',
  'name': None,
  'source': 'atomics/T1023/T1023.yaml'},
 {'command': '$Shell = New-Object -ComObject ("WScript.Shell")\n'
             '$ShortCut = '
             '$Shell.CreateShortcut("$env:APPDATA\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\T1023.lnk")\n'
             '$ShortCut.TargetPath="cmd.exe"\n'
             '$ShortCut.WorkingDirectory = "C:\\Windows\\System32";\n'
             '$ShortCut.WindowStyle = 1;\n'
             '$ShortCut.Description = "T1023.";\n'
             '$ShortCut.Save()\n'
             '\n'
             '$Shell = New-Object -ComObject ("WScript.Shell")\n'
             '$ShortCut = '
             '$Shell.CreateShortcut("$env:ProgramData\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\T1023.lnk")\n'
             '$ShortCut.TargetPath="cmd.exe"\n'
             '$ShortCut.WorkingDirectory = "C:\\Windows\\System32";\n'
             '$ShortCut.WindowStyle = 1;\n'
             '$ShortCut.Description = "T1023.";\n'
             '$ShortCut.Save()\n',
  'name': None,
  'source': 'atomics/T1023/T1023.yaml'},
 {'command': 'powershell/persistence/userland/backdoor_lnk',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/userland/backdoor_lnk',
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
[{'Atomic Red Team Test - Shortcut Modification': {'atomic_tests': [{'description': 'This '
                                                                                    'test '
                                                                                    'to '
                                                                                    'simulate '
                                                                                    'shortcut '
                                                                                    'modification '
                                                                                    'and '
                                                                                    'then '
                                                                                    'execute. '
                                                                                    'example '
                                                                                    'shortcut '
                                                                                    '(*.lnk '
                                                                                    ', '
                                                                                    '.url) '
                                                                                    'strings '
                                                                                    'check '
                                                                                    'with '
                                                                                    'powershell;\n'
                                                                                    'gci '
                                                                                    '-path '
                                                                                    '"C:\\Users" '
                                                                                    '-recurse '
                                                                                    '-include '
                                                                                    '*.url '
                                                                                    '-ea '
                                                                                    'SilentlyContinue '
                                                                                    '| '
                                                                                    'Select-String '
                                                                                    '-Pattern '
                                                                                    '"exe" '
                                                                                    '| '
                                                                                    'FL.\n'
                                                                                    'Upon '
                                                                                    'execution, '
                                                                                    'calc.exe '
                                                                                    'will '
                                                                                    'be '
                                                                                    'launched.\n',
                                                                     'executor': {'cleanup_command': 'del '
                                                                                                     '-f '
                                                                                                     '#{shortcut_file_path} '
                                                                                                     '>nul '
                                                                                                     '2>&1\n',
                                                                                  'command': 'echo '
                                                                                             '[InternetShortcut] '
                                                                                             '> '
                                                                                             '#{shortcut_file_path}\n'
                                                                                             'echo '
                                                                                             'URL=C:\\windows\\system32\\calc.exe '
                                                                                             '>> '
                                                                                             '#{shortcut_file_path}\n'
                                                                                             '#{shortcut_file_path}\n',
                                                                                  'elevation_required': False,
                                                                                  'name': 'command_prompt'},
                                                                     'input_arguments': {'shortcut_file_path': {'default': '%temp%\\T1023_modified_shortcut.url',
                                                                                                                'description': 'shortcut '
                                                                                                                               'modified '
                                                                                                                               'and '
                                                                                                                               'execute',
                                                                                                                'type': 'path'}},
                                                                     'name': 'Shortcut '
                                                                             'Modification',
                                                                     'supported_platforms': ['windows']},
                                                                    {'description': 'LNK '
                                                                                    'file '
                                                                                    'to '
                                                                                    'launch '
                                                                                    'CMD '
                                                                                    'placed '
                                                                                    'in '
                                                                                    'startup '
                                                                                    'folder. '
                                                                                    'Upon '
                                                                                    'execution, '
                                                                                    'open '
                                                                                    'File '
                                                                                    'Explorer '
                                                                                    'and '
                                                                                    'browse '
                                                                                    'to '
                                                                                    '"%APPDATA%\\Microsoft\\Windows\\Start '
                                                                                    'Menu\\Programs\\Startup\\"\n'
                                                                                    'to '
                                                                                    'view '
                                                                                    'the '
                                                                                    'new '
                                                                                    'shortcut.\n',
                                                                     'executor': {'cleanup_command': 'Remove-Item '
                                                                                                     '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                                     'Menu\\Programs\\Startup\\T1023.lnk" '
                                                                                                     '-ErrorAction '
                                                                                                     'Ignore\n'
                                                                                                     'Remove-Item '
                                                                                                     '"$env:ProgramData\\Microsoft\\Windows\\Start '
                                                                                                     'Menu\\Programs\\Startup\\T1023.lnk" '
                                                                                                     '-ErrorAction '
                                                                                                     'Ignore\n',
                                                                                  'command': '$Shell '
                                                                                             '= '
                                                                                             'New-Object '
                                                                                             '-ComObject '
                                                                                             '("WScript.Shell")\n'
                                                                                             '$ShortCut '
                                                                                             '= '
                                                                                             '$Shell.CreateShortcut("$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                             'Menu\\Programs\\Startup\\T1023.lnk")\n'
                                                                                             '$ShortCut.TargetPath="cmd.exe"\n'
                                                                                             '$ShortCut.WorkingDirectory '
                                                                                             '= '
                                                                                             '"C:\\Windows\\System32";\n'
                                                                                             '$ShortCut.WindowStyle '
                                                                                             '= '
                                                                                             '1;\n'
                                                                                             '$ShortCut.Description '
                                                                                             '= '
                                                                                             '"T1023.";\n'
                                                                                             '$ShortCut.Save()\n'
                                                                                             '\n'
                                                                                             '$Shell '
                                                                                             '= '
                                                                                             'New-Object '
                                                                                             '-ComObject '
                                                                                             '("WScript.Shell")\n'
                                                                                             '$ShortCut '
                                                                                             '= '
                                                                                             '$Shell.CreateShortcut("$env:ProgramData\\Microsoft\\Windows\\Start '
                                                                                             'Menu\\Programs\\Startup\\T1023.lnk")\n'
                                                                                             '$ShortCut.TargetPath="cmd.exe"\n'
                                                                                             '$ShortCut.WorkingDirectory '
                                                                                             '= '
                                                                                             '"C:\\Windows\\System32";\n'
                                                                                             '$ShortCut.WindowStyle '
                                                                                             '= '
                                                                                             '1;\n'
                                                                                             '$ShortCut.Description '
                                                                                             '= '
                                                                                             '"T1023.";\n'
                                                                                             '$ShortCut.Save()\n',
                                                                                  'elevation_required': True,
                                                                                  'name': 'powershell'},
                                                                     'name': 'Create '
                                                                             'shortcut '
                                                                             'to '
                                                                             'cmd '
                                                                             'in '
                                                                             'startup '
                                                                             'folders',
                                                                     'supported_platforms': ['windows']}],
                                                   'attack_technique': 'T1023',
                                                   'display_name': 'Shortcut '
                                                                   'Modification'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1023',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/userland/backdoor_lnk":  '
                                                                                 '["T1023"],',
                                            'Empire Module': 'powershell/persistence/userland/backdoor_lnk',
                                            'Technique': 'Shortcut '
                                                         'Modification'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors


* [Gorgon Group](../actors/Gorgon-Group.md)

* [FIN7](../actors/FIN7.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [APT29](../actors/APT29.md)
    
* [APT39](../actors/APT39.md)
    
