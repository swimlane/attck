
# Application Shimming

## Description

### MITRE Description

> The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10. (Citation: Endgame Process Injection July 2017) Within the framework, shims are created to act as a buffer between the program (or more specifically, the Import Address Table) and the Windows OS. When a program is executed, the shim cache is referenced to determine if the program requires the use of the shim database (.sdb). If so, the shim database uses [Hooking](https://attack.mitre.org/techniques/T1179) to redirect the code as necessary in order to communicate with the OS. 

A list of all shims currently installed by the default Windows installer (sdbinst.exe) is kept in:

* <code>%WINDIR%\AppPatch\sysmain.sdb</code>
* <code>hklm\software\microsoft\windows nt\currentversion\appcompatflags\installedsdb</code>

Custom databases are stored in:

* <code>%WINDIR%\AppPatch\custom & %WINDIR%\AppPatch\AppPatch64\Custom</code>
* <code>hklm\software\microsoft\windows nt\currentversion\appcompatflags\custom</code>

To keep shims secure, Windows designed them to run in user mode so they cannot modify the kernel and you must have administrator privileges to install a shim. However, certain shims can be used to [Bypass User Account Control](https://attack.mitre.org/techniques/T1088) (UAC) (RedirectEXE), inject DLLs into processes (InjectDLL), disable Data Execution Prevention (DisableNX) and Structure Exception Handling (DisableSEH), and intercept memory addresses (GetProcAddress). Similar to [Hooking](https://attack.mitre.org/techniques/T1179), utilizing these shims may allow an adversary to perform several malicious acts such as elevate privileges, install backdoors, disable defenses like Windows Defender, etc.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1138

## Potential Commands

```
sdbinst.exe PathToAtomicsFolder\T1138\bin\AtomicShimx86.sdb

Copy-Item $PathToAtomicsFolder\T1138\bin\T1138CompatDatabase.sdb C:\Windows\apppatch\Custom\T1138CompatDatabase.sdb
Copy-Item $PathToAtomicsFolder\T1138\bin\T1138CompatDatabase.sdb C:\Windows\apppatch\Custom\Custom64\T1138CompatDatabase.sdb

New-ItemProperty -Path HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom" -Name "AtomicRedTeamT1138" -Value "AtomicRedTeamT1138"
New-ItemProperty -Path HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" -Name "AtomicRedTeamT1138" -Value "AtomicRedTeamT1138"

*.exe reg add
HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
*.exe reg add
HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
sdbinst.exe\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom|\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom|\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
```

## Commands Dataset

```
[{'command': 'sdbinst.exe PathToAtomicsFolder\\T1138\\bin\\AtomicShimx86.sdb\n',
  'name': None,
  'source': 'atomics/T1138/T1138.yaml'},
 {'command': 'Copy-Item '
             '$PathToAtomicsFolder\\T1138\\bin\\T1138CompatDatabase.sdb '
             'C:\\Windows\\apppatch\\Custom\\T1138CompatDatabase.sdb\n'
             'Copy-Item '
             '$PathToAtomicsFolder\\T1138\\bin\\T1138CompatDatabase.sdb '
             'C:\\Windows\\apppatch\\Custom\\Custom64\\T1138CompatDatabase.sdb\n',
  'name': None,
  'source': 'atomics/T1138/T1138.yaml'},
 {'command': 'New-ItemProperty -Path HKLM:"\\SOFTWARE\\Microsoft\\Windows '
             'NT\\CurrentVersion\\AppCompatFlags\\Custom" -Name '
             '"AtomicRedTeamT1138" -Value "AtomicRedTeamT1138"\n'
             'New-ItemProperty -Path HKLM:"\\SOFTWARE\\Microsoft\\Windows '
             'NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB" -Name '
             '"AtomicRedTeamT1138" -Value "AtomicRedTeamT1138"\n',
  'name': None,
  'source': 'atomics/T1138/T1138.yaml'},
 {'command': '*.exe reg add', 'name': None, 'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows '
             'NT\\CurrentVersion\\AppCompatFlags\\Custom',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe reg add', 'name': None, 'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows '
             'NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'sdbinst.exe\\SOFTWARE\\Microsoft\\Windows '
             'NT\\CurrentVersion\\AppCompatFlags\\Custom|\\SOFTWARE\\Microsoft\\Windows '
             'NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB',
  'name': None,
  'source': 'SysmonHunter - Application Shimming'},
 {'command': '\\SOFTWARE\\Microsoft\\Windows '
             'NT\\CurrentVersion\\AppCompatFlags\\Custom|\\SOFTWARE\\Microsoft\\Windows '
             'NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB',
  'name': None,
  'source': 'SysmonHunter - Application Shimming'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Markus Neis',
                  'description': 'Detects installation of a new shim using '
                                 'sdbinst.exe. A shim can be used to load '
                                 'malicious DLLs into applications.',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['*.sdb*'],
                                              'Image': ['*\\sdbinst.exe']}},
                  'falsepositives': ['Unknown'],
                  'id': '517490a7-115a-48c6-8862-1a481504d5a8',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html'],
                  'status': 'experimental',
                  'tags': ['attack.persistence', 'attack.t1138'],
                  'title': 'Possible Shim Database Persistence via '
                           'sdbinst.exe'}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['Loaded DLLs']},
 {'data_source': ['System calls']},
 {'data_source': ['Sysmon ID 7', 'Loaded DLLs']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['System calls']}]
```

## Potential Queries

```json
[{'name': 'Application Shimming FileAccess',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 11and file_name contains '
           '"C:\\\\Windows\\\\AppPatch\\\\Custom\\\\"'},
 {'name': 'Application Shimming Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and process_path contains "sdbinst.exe"'},
 {'name': 'Application Shimming Registry',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           'registry_key_path contains "\\\\SOFTWARE\\\\Microsoft\\\\Windows '
           'NT\\\\CurrentVersion\\\\AppCompatFlags\\\\InstalledSDB\\\\"'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Application Shimming': {'atomic_tests': [{'auto_generated_guid': '9ab27e22-ee62-4211-962b-d36d9a0e6a18',
                                                                    'dependencies': [{'description': 'Shim '
                                                                                                     'database '
                                                                                                     'file '
                                                                                                     'must '
                                                                                                     'exist '
                                                                                                     'on '
                                                                                                     'disk '
                                                                                                     'at '
                                                                                                     'specified '
                                                                                                     'location '
                                                                                                     '(#{file_path})\n',
                                                                                      'get_prereq_command': 'New-Item '
                                                                                                            '-Type '
                                                                                                            'Directory '
                                                                                                            '(split-path '
                                                                                                            '#{file_path}) '
                                                                                                            '-ErrorAction '
                                                                                                            'ignore '
                                                                                                            '| '
                                                                                                            'Out-Null\n'
                                                                                                            'Invoke-WebRequest '
                                                                                                            '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1138/bin/AtomicShimx86.sdb" '
                                                                                                            '-OutFile '
                                                                                                            '"#{file_path}"\n',
                                                                                      'prereq_command': 'if '
                                                                                                        '(Test-Path '
                                                                                                        '#{file_path}) '
                                                                                                        '{exit '
                                                                                                        '0} '
                                                                                                        'else '
                                                                                                        '{exit '
                                                                                                        '1}\n'},
                                                                                     {'description': 'AtomicTest.dll '
                                                                                                     'must '
                                                                                                     'exist '
                                                                                                     'at '
                                                                                                     'c:\\Tools\\AtomicTest.dll\n',
                                                                                      'get_prereq_command': 'New-Item '
                                                                                                            '-Type '
                                                                                                            'Directory '
                                                                                                            '(split-path '
                                                                                                            'c:\\Tools\\AtomicTest.dll) '
                                                                                                            '-ErrorAction '
                                                                                                            'ignore '
                                                                                                            '| '
                                                                                                            'Out-Null\n'
                                                                                                            'Invoke-WebRequest '
                                                                                                            '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1138/bin/AtomicTest.dll" '
                                                                                                            '-OutFile '
                                                                                                            'c:\\Tools\\AtomicTest.dll\n',
                                                                                      'prereq_command': 'if '
                                                                                                        '(Test-Path '
                                                                                                        'c:\\Tools\\AtomicTest.dll) '
                                                                                                        '{exit '
                                                                                                        '0} '
                                                                                                        'else '
                                                                                                        '{exit '
                                                                                                        '1}\n'}],
                                                                    'dependency_executor_name': 'powershell',
                                                                    'description': 'Install '
                                                                                   'a '
                                                                                   'shim '
                                                                                   'database. '
                                                                                   'This '
                                                                                   'technique '
                                                                                   'is '
                                                                                   'used '
                                                                                   'for '
                                                                                   'privilege '
                                                                                   'escalation '
                                                                                   'and '
                                                                                   'bypassing '
                                                                                   'user '
                                                                                   'access '
                                                                                   'control.\n'
                                                                                   'Upon '
                                                                                   'execution, '
                                                                                   '"Installation '
                                                                                   'of '
                                                                                   'AtomicShim '
                                                                                   'complete." '
                                                                                   'will '
                                                                                   'be '
                                                                                   'displayed. '
                                                                                   'To '
                                                                                   'verify '
                                                                                   'the '
                                                                                   'shim '
                                                                                   'behavior, '
                                                                                   'run \n'
                                                                                   'the '
                                                                                   'AtomicTest.exe '
                                                                                   'from '
                                                                                   'the '
                                                                                   '<PathToAtomicsFolder>\\T1138\\bin '
                                                                                   'directory. '
                                                                                   'You '
                                                                                   'should '
                                                                                   'see '
                                                                                   'a '
                                                                                   'message '
                                                                                   'box '
                                                                                   'appear\n'
                                                                                   'with '
                                                                                   '"Atomic '
                                                                                   'Shim '
                                                                                   'DLL '
                                                                                   'Test!" '
                                                                                   'as '
                                                                                   'defined '
                                                                                   'in '
                                                                                   'the '
                                                                                   'AtomicTest.dll. '
                                                                                   'To '
                                                                                   'better '
                                                                                   'understand '
                                                                                   'what '
                                                                                   'is '
                                                                                   'happening, '
                                                                                   'review\n'
                                                                                   'the '
                                                                                   'source '
                                                                                   'code '
                                                                                   'files '
                                                                                   'is '
                                                                                   'the '
                                                                                   '<PathToAtomicsFolder>\\T1138\\src '
                                                                                   'directory.\n',
                                                                    'executor': {'cleanup_command': 'sdbinst.exe '
                                                                                                    '-u '
                                                                                                    '#{file_path}\n',
                                                                                 'command': 'sdbinst.exe '
                                                                                            '#{file_path}\n',
                                                                                 'elevation_required': True,
                                                                                 'name': 'command_prompt'},
                                                                    'input_arguments': {'file_path': {'default': 'PathToAtomicsFolder\\T1138\\bin\\AtomicShimx86.sdb',
                                                                                                      'description': 'Path '
                                                                                                                     'to '
                                                                                                                     'the '
                                                                                                                     'shim '
                                                                                                                     'database '
                                                                                                                     'file',
                                                                                                      'type': 'String'}},
                                                                    'name': 'Application '
                                                                            'Shim '
                                                                            'Installation',
                                                                    'supported_platforms': ['windows']},
                                                                   {'auto_generated_guid': 'aefd6866-d753-431f-a7a4-215ca7e3f13d',
                                                                    'description': 'Upon '
                                                                                   'execution, '
                                                                                   'check '
                                                                                   'the '
                                                                                   '"C:\\Windows\\apppatch\\Custom\\" '
                                                                                   'folder '
                                                                                   'for '
                                                                                   'the '
                                                                                   'new '
                                                                                   'shim '
                                                                                   'database\n'
                                                                                   '\n'
                                                                                   'https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html\n',
                                                                    'executor': {'cleanup_command': 'Remove-Item '
                                                                                                    'C:\\Windows\\apppatch\\Custom\\T1138CompatDatabase.sdb '
                                                                                                    '-ErrorAction '
                                                                                                    'Ignore\n'
                                                                                                    'Remove-Item '
                                                                                                    'C:\\Windows\\apppatch\\Custom\\Custom64\\T1138CompatDatabase.sdb '
                                                                                                    '-ErrorAction '
                                                                                                    'Ignore\n',
                                                                                 'command': 'Copy-Item '
                                                                                            '$PathToAtomicsFolder\\T1138\\bin\\T1138CompatDatabase.sdb '
                                                                                            'C:\\Windows\\apppatch\\Custom\\T1138CompatDatabase.sdb\n'
                                                                                            'Copy-Item '
                                                                                            '$PathToAtomicsFolder\\T1138\\bin\\T1138CompatDatabase.sdb '
                                                                                            'C:\\Windows\\apppatch\\Custom\\Custom64\\T1138CompatDatabase.sdb\n',
                                                                                 'elevation_required': True,
                                                                                 'name': 'powershell'},
                                                                    'name': 'New '
                                                                            'shim '
                                                                            'database '
                                                                            'files '
                                                                            'created '
                                                                            'in '
                                                                            'the '
                                                                            'default '
                                                                            'shim '
                                                                            'database '
                                                                            'directory',
                                                                    'supported_platforms': ['windows']},
                                                                   {'auto_generated_guid': '9b6a06f9-ab5e-4e8d-8289-1df4289db02f',
                                                                    'description': 'Create '
                                                                                   'registry '
                                                                                   'keys '
                                                                                   'in '
                                                                                   'locations '
                                                                                   'where '
                                                                                   'fin7 '
                                                                                   'typically '
                                                                                   'places '
                                                                                   'SDB '
                                                                                   'patches. '
                                                                                   'Upon '
                                                                                   'execution, '
                                                                                   'output '
                                                                                   'will '
                                                                                   'be '
                                                                                   'displayed '
                                                                                   'describing\n'
                                                                                   'the '
                                                                                   'registry '
                                                                                   'keys '
                                                                                   'that '
                                                                                   'were '
                                                                                   'created. '
                                                                                   'These '
                                                                                   'keys '
                                                                                   'can '
                                                                                   'also '
                                                                                   'be '
                                                                                   'viewed '
                                                                                   'using '
                                                                                   'the '
                                                                                   'Registry '
                                                                                   'Editor.\n'
                                                                                   '\n'
                                                                                   'https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html\n',
                                                                    'executor': {'cleanup_command': 'Remove-ItemProperty '
                                                                                                    '-Path '
                                                                                                    'HKLM:"\\SOFTWARE\\Microsoft\\Windows '
                                                                                                    'NT\\CurrentVersion\\AppCompatFlags\\Custom" '
                                                                                                    '-Name '
                                                                                                    '"AtomicRedTeamT1138" '
                                                                                                    '-ErrorAction '
                                                                                                    'Ignore\n'
                                                                                                    'Remove-ItemProperty '
                                                                                                    '-Path '
                                                                                                    'HKLM:"\\SOFTWARE\\Microsoft\\Windows '
                                                                                                    'NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB" '
                                                                                                    '-Name '
                                                                                                    '"AtomicRedTeamT1138" '
                                                                                                    '-ErrorAction '
                                                                                                    'Ignore\n',
                                                                                 'command': 'New-ItemProperty '
                                                                                            '-Path '
                                                                                            'HKLM:"\\SOFTWARE\\Microsoft\\Windows '
                                                                                            'NT\\CurrentVersion\\AppCompatFlags\\Custom" '
                                                                                            '-Name '
                                                                                            '"AtomicRedTeamT1138" '
                                                                                            '-Value '
                                                                                            '"AtomicRedTeamT1138"\n'
                                                                                            'New-ItemProperty '
                                                                                            '-Path '
                                                                                            'HKLM:"\\SOFTWARE\\Microsoft\\Windows '
                                                                                            'NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB" '
                                                                                            '-Name '
                                                                                            '"AtomicRedTeamT1138" '
                                                                                            '-Value '
                                                                                            '"AtomicRedTeamT1138"\n',
                                                                                 'elevation_required': True,
                                                                                 'name': 'powershell'},
                                                                    'name': 'Registry '
                                                                            'key '
                                                                            'creation '
                                                                            'and/or '
                                                                            'modification '
                                                                            'events '
                                                                            'for '
                                                                            'SDB',
                                                                    'supported_platforms': ['windows']}],
                                                  'attack_technique': 'T1138',
                                                  'display_name': 'Application '
                                                                  'Shimming'}},
 {'Threat Hunting Tables': {'chain_id': '100182',
                            'commandline_string': 'reg add',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1138',
                            'mitre_caption': 'application_shimming',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\AppCompatFlags\\Custom',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100183',
                            'commandline_string': 'reg add',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1138',
                            'mitre_caption': 'application_shimming',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows '
                                             'NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'SysmonHunter - T1138': {'description': None,
                           'level': 'medium',
                           'name': 'Application Shimming',
                           'phase': 'Persistence',
                           'query': [{'process': {'cmdline': {'pattern': '\\SOFTWARE\\Microsoft\\Windows '
                                                                         'NT\\CurrentVersion\\AppCompatFlags\\Custom|\\SOFTWARE\\Microsoft\\Windows '
                                                                         'NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB'},
                                                  'image': {'pattern': 'sdbinst.exe'}},
                                      'type': 'process'},
                                     {'reg': {'path': {'pattern': '\\SOFTWARE\\Microsoft\\Windows '
                                                                  'NT\\CurrentVersion\\AppCompatFlags\\Custom|\\SOFTWARE\\Microsoft\\Windows '
                                                                  'NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB'}},
                                      'type': 'reg'}]}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors


* [FIN7](../actors/FIN7.md)

