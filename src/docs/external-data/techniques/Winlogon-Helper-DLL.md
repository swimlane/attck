
# Winlogon Helper DLL

## Description

### MITRE Description

> Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in <code>HKLM\Software[\\Wow6432Node\\]\Microsoft\Windows NT\CurrentVersion\Winlogon\</code> and <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\</code> are used to manage additional helper programs and functionalities that support Winlogon. (Citation: Cylance Reg Persistence Sept 2013) 

Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables. Specifically, the following subkeys have been known to be possibly vulnerable to abuse: (Citation: Cylance Reg Persistence Sept 2013)

* Winlogon\Notify - points to notification package DLLs that handle Winlogon events
* Winlogon\Userinit - points to userinit.exe, the user initialization program executed when a user logs on
* Winlogon\Shell - points to explorer.exe, the system shell executed when a user logs on

Adversaries may take advantage of these features to repeatedly execute malicious code and establish persistence.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['SYSTEM', 'Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1547/004

## Potential Commands

```
New-Item "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" -Force
Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" "logon" "C:\Windows\Temp\atomicNotificationPackage.dll" -Force
Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Userinit" "Userinit.exe, C:\Windows\System32\cmd.exe" -Force
Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, C:\Windows\System32\cmd.exe" -Force
```

## Commands Dataset

```
[{'command': 'Set-ItemProperty "HKCU:\\Software\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Winlogon\\" "Shell" "explorer.exe, '
             'C:\\Windows\\System32\\cmd.exe" -Force\n',
  'name': None,
  'source': 'atomics/T1547.004/T1547.004.yaml'},
 {'command': 'Set-ItemProperty "HKCU:\\Software\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Winlogon\\" "Userinit" "Userinit.exe, '
             'C:\\Windows\\System32\\cmd.exe" -Force\n',
  'name': None,
  'source': 'atomics/T1547.004/T1547.004.yaml'},
 {'command': 'New-Item "HKCU:\\Software\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Winlogon\\Notify" -Force\n'
             'Set-ItemProperty "HKCU:\\Software\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Winlogon\\Notify" "logon" '
             '"C:\\Windows\\Temp\\atomicNotificationPackage.dll" -Force\n',
  'name': None,
  'source': 'atomics/T1547.004/T1547.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Boot or Logon Autostart Execution: Winlogon Helper DLL': {'atomic_tests': [{'auto_generated_guid': 'bf9f9d65-ee4d-4c3e-a843-777d04f19c38',
                                                                                                      'description': 'PowerShell '
                                                                                                                     'code '
                                                                                                                     'to '
                                                                                                                     'set '
                                                                                                                     'Winlogon '
                                                                                                                     'shell '
                                                                                                                     'key '
                                                                                                                     'to '
                                                                                                                     'execute '
                                                                                                                     'a '
                                                                                                                     'binary '
                                                                                                                     'at '
                                                                                                                     'logon '
                                                                                                                     'along '
                                                                                                                     'with '
                                                                                                                     'explorer.exe.\n'
                                                                                                                     '\n'
                                                                                                                     'Upon '
                                                                                                                     'successful '
                                                                                                                     'execution, '
                                                                                                                     'PowerShell '
                                                                                                                     'will '
                                                                                                                     'modify '
                                                                                                                     'a '
                                                                                                                     'registry '
                                                                                                                     'value '
                                                                                                                     'to '
                                                                                                                     'execute '
                                                                                                                     'cmd.exe '
                                                                                                                     'upon '
                                                                                                                     'logon/logoff.\n',
                                                                                                      'executor': {'cleanup_command': 'Remove-ItemProperty '
                                                                                                                                      '-Path '
                                                                                                                                      '"HKCU:\\Software\\Microsoft\\Windows '
                                                                                                                                      'NT\\CurrentVersion\\Winlogon\\" '
                                                                                                                                      '-Name '
                                                                                                                                      '"Shell" '
                                                                                                                                      '-Force '
                                                                                                                                      '-ErrorAction '
                                                                                                                                      'Ignore\n',
                                                                                                                   'command': 'Set-ItemProperty '
                                                                                                                              '"HKCU:\\Software\\Microsoft\\Windows '
                                                                                                                              'NT\\CurrentVersion\\Winlogon\\" '
                                                                                                                              '"Shell" '
                                                                                                                              '"explorer.exe, '
                                                                                                                              '#{binary_to_execute}" '
                                                                                                                              '-Force\n',
                                                                                                                   'name': 'powershell'},
                                                                                                      'input_arguments': {'binary_to_execute': {'default': 'C:\\Windows\\System32\\cmd.exe',
                                                                                                                                                'description': 'Path '
                                                                                                                                                               'of '
                                                                                                                                                               'binary '
                                                                                                                                                               'to '
                                                                                                                                                               'execute',
                                                                                                                                                'type': 'Path'}},
                                                                                                      'name': 'Winlogon '
                                                                                                              'Shell '
                                                                                                              'Key '
                                                                                                              'Persistence '
                                                                                                              '- '
                                                                                                              'PowerShell',
                                                                                                      'supported_platforms': ['windows']},
                                                                                                     {'auto_generated_guid': 'fb32c935-ee2e-454b-8fa3-1c46b42e8dfb',
                                                                                                      'description': 'PowerShell '
                                                                                                                     'code '
                                                                                                                     'to '
                                                                                                                     'set '
                                                                                                                     'Winlogon '
                                                                                                                     'userinit '
                                                                                                                     'key '
                                                                                                                     'to '
                                                                                                                     'execute '
                                                                                                                     'a '
                                                                                                                     'binary '
                                                                                                                     'at '
                                                                                                                     'logon '
                                                                                                                     'along '
                                                                                                                     'with '
                                                                                                                     'userinit.exe.\n'
                                                                                                                     '\n'
                                                                                                                     'Upon '
                                                                                                                     'successful '
                                                                                                                     'execution, '
                                                                                                                     'PowerShell '
                                                                                                                     'will '
                                                                                                                     'modify '
                                                                                                                     'a '
                                                                                                                     'registry '
                                                                                                                     'value '
                                                                                                                     'to '
                                                                                                                     'execute '
                                                                                                                     'cmd.exe '
                                                                                                                     'upon '
                                                                                                                     'logon/logoff.\n',
                                                                                                      'executor': {'cleanup_command': 'Remove-ItemProperty '
                                                                                                                                      '-Path '
                                                                                                                                      '"HKCU:\\Software\\Microsoft\\Windows '
                                                                                                                                      'NT\\CurrentVersion\\Winlogon\\" '
                                                                                                                                      '-Name '
                                                                                                                                      '"Userinit" '
                                                                                                                                      '-Force '
                                                                                                                                      '-ErrorAction '
                                                                                                                                      'Ignore\n',
                                                                                                                   'command': 'Set-ItemProperty '
                                                                                                                              '"HKCU:\\Software\\Microsoft\\Windows '
                                                                                                                              'NT\\CurrentVersion\\Winlogon\\" '
                                                                                                                              '"Userinit" '
                                                                                                                              '"Userinit.exe, '
                                                                                                                              '#{binary_to_execute}" '
                                                                                                                              '-Force\n',
                                                                                                                   'name': 'powershell'},
                                                                                                      'input_arguments': {'binary_to_execute': {'default': 'C:\\Windows\\System32\\cmd.exe',
                                                                                                                                                'description': 'Path '
                                                                                                                                                               'of '
                                                                                                                                                               'binary '
                                                                                                                                                               'to '
                                                                                                                                                               'execute',
                                                                                                                                                'type': 'Path'}},
                                                                                                      'name': 'Winlogon '
                                                                                                              'Userinit '
                                                                                                              'Key '
                                                                                                              'Persistence '
                                                                                                              '- '
                                                                                                              'PowerShell',
                                                                                                      'supported_platforms': ['windows']},
                                                                                                     {'auto_generated_guid': 'd40da266-e073-4e5a-bb8b-2b385023e5f9',
                                                                                                      'description': 'PowerShell '
                                                                                                                     'code '
                                                                                                                     'to '
                                                                                                                     'set '
                                                                                                                     'Winlogon '
                                                                                                                     'Notify '
                                                                                                                     'key '
                                                                                                                     'to '
                                                                                                                     'execute '
                                                                                                                     'a '
                                                                                                                     'notification '
                                                                                                                     'package '
                                                                                                                     'DLL '
                                                                                                                     'at '
                                                                                                                     'logon.\n'
                                                                                                                     '\n'
                                                                                                                     'Upon '
                                                                                                                     'successful '
                                                                                                                     'execution, '
                                                                                                                     'PowerShell '
                                                                                                                     'will '
                                                                                                                     'modify '
                                                                                                                     'a '
                                                                                                                     'registry '
                                                                                                                     'value '
                                                                                                                     'to '
                                                                                                                     'execute '
                                                                                                                     'atomicNotificationPackage.dll '
                                                                                                                     'upon '
                                                                                                                     'logon/logoff.\n',
                                                                                                      'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                                      '"HKCU:\\Software\\Microsoft\\Windows '
                                                                                                                                      'NT\\CurrentVersion\\Winlogon\\Notify" '
                                                                                                                                      '-Force '
                                                                                                                                      '-ErrorAction '
                                                                                                                                      'Ignore\n',
                                                                                                                   'command': 'New-Item '
                                                                                                                              '"HKCU:\\Software\\Microsoft\\Windows '
                                                                                                                              'NT\\CurrentVersion\\Winlogon\\Notify" '
                                                                                                                              '-Force\n'
                                                                                                                              'Set-ItemProperty '
                                                                                                                              '"HKCU:\\Software\\Microsoft\\Windows '
                                                                                                                              'NT\\CurrentVersion\\Winlogon\\Notify" '
                                                                                                                              '"logon" '
                                                                                                                              '"#{binary_to_execute}" '
                                                                                                                              '-Force\n',
                                                                                                                   'name': 'powershell'},
                                                                                                      'input_arguments': {'binary_to_execute': {'default': 'C:\\Windows\\Temp\\atomicNotificationPackage.dll',
                                                                                                                                                'description': 'Path '
                                                                                                                                                               'of '
                                                                                                                                                               'notification '
                                                                                                                                                               'package '
                                                                                                                                                               'to '
                                                                                                                                                               'execute',
                                                                                                                                                'type': 'Path'}},
                                                                                                      'name': 'Winlogon '
                                                                                                              'Notify '
                                                                                                              'Key '
                                                                                                              'Logon '
                                                                                                              'Persistence '
                                                                                                              '- '
                                                                                                              'PowerShell',
                                                                                                      'supported_platforms': ['windows']}],
                                                                                    'attack_technique': 'T1547.004',
                                                                                    'display_name': 'Boot '
                                                                                                    'or '
                                                                                                    'Logon '
                                                                                                    'Autostart '
                                                                                                    'Execution: '
                                                                                                    'Winlogon '
                                                                                                    'Helper '
                                                                                                    'DLL'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)

* [User Account Management](../mitigations/User-Account-Management.md)
    

# Actors


* [Turla](../actors/Turla.md)

* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
