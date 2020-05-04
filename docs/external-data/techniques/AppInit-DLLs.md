
# AppInit DLLs

## Description

### MITRE Description

> Dynamic-link libraries (DLLs) that are specified in the AppInit_DLLs value in the Registry keys <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> or <code>HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows</code> are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. (Citation: Endgame Process Injection July 2017) Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), these values can be abused to obtain persistence and privilege escalation by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. (Citation: AppInit Registry)

The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled. (Citation: AppInit Secure Boot)

## Additional Attributes

* Bypass: None
* Effective Permissions: ['Administrator', 'SYSTEM']
* Network: intentionally left blank
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1103

## Potential Commands

```
reg.exe import PathToAtomicsFolder\T1103\src\T1103.reg

reg.exe import #{registry_file}

Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs|Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs
```

## Commands Dataset

```
[{'command': 'reg.exe import PathToAtomicsFolder\\T1103\\src\\T1103.reg\n',
  'name': None,
  'source': 'atomics/T1103/T1103.yaml'},
 {'command': 'reg.exe import #{registry_file}\n',
  'name': None,
  'source': 'atomics/T1103/T1103.yaml'},
 {'command': 'Microsoft\\Windows '
             'NT\\CurrentVersion\\Windows\\AppInit_DLLs|Microsoft\\Windows '
             'NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs',
  'name': None,
  'source': 'SysmonHunter - AppInit DLLs'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'AppInit DLLs',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           '(registry_key_path contains "\\\\SOFTWARE\\\\Microsoft\\\\Windows '
           'NT\\\\CurrentVersion\\\\Windows\\\\Appinit_Dlls\\\\"or '
           'registry_key_path contains '
           '"\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows '
           'NT\\\\CurrentVersion\\\\Windows\\\\Appinit_Dlls\\\\")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - AppInit DLLs': {'atomic_tests': [{'dependencies': [{'description': 'Reg '
                                                                                             'files '
                                                                                             'must '
                                                                                             'exist '
                                                                                             'on '
                                                                                             'disk '
                                                                                             'at '
                                                                                             'specified '
                                                                                             'locations '
                                                                                             '(#{registry_file} '
                                                                                             'and '
                                                                                             '#{registry_cleanup_file})\n',
                                                                              'get_prereq_command': 'New-Item '
                                                                                                    '-Type '
                                                                                                    'Directory '
                                                                                                    '(split-path '
                                                                                                    '#{registry_file}) '
                                                                                                    '-ErrorAction '
                                                                                                    'ignore '
                                                                                                    '| '
                                                                                                    'Out-Null\n'
                                                                                                    'Invoke-WebRequest '
                                                                                                    '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1103/src/T1103.reg" '
                                                                                                    '-OutFile '
                                                                                                    '"#{registry_file}"\n'
                                                                                                    'Invoke-WebRequest '
                                                                                                    '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1103/src/T1103-cleanup.reg" '
                                                                                                    '-OutFile '
                                                                                                    '"#{registry_cleanup_file}"\n',
                                                                              'prereq_command': 'if '
                                                                                                '((Test-Path '
                                                                                                '#{registry_file}) '
                                                                                                '-and '
                                                                                                '(Test-Path '
                                                                                                '#{registry_cleanup_file})) '
                                                                                                '{exit '
                                                                                                '0} '
                                                                                                'else '
                                                                                                '{exit '
                                                                                                '1}\n'},
                                                                             {'description': "DLL's "
                                                                                             'must '
                                                                                             'exist '
                                                                                             'in '
                                                                                             'the '
                                                                                             'C:\\Tools '
                                                                                             'directory '
                                                                                             '(T1103.dll '
                                                                                             'and '
                                                                                             'T1103x86.dll)\n',
                                                                              'get_prereq_command': 'New-Item '
                                                                                                    '-Type '
                                                                                                    'Directory '
                                                                                                    'C:\\Tools '
                                                                                                    '-ErrorAction '
                                                                                                    'ignore '
                                                                                                    '| '
                                                                                                    'Out-Null\n'
                                                                                                    'Invoke-WebRequest '
                                                                                                    '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1103/bin/T1103.dll" '
                                                                                                    '-OutFile '
                                                                                                    'C:\\Tools\\T1103.dll\n'
                                                                                                    'Invoke-WebRequest '
                                                                                                    '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1103/bin/T1103x86.dll" '
                                                                                                    '-OutFile '
                                                                                                    'C:\\Tools\\T1103x86.dll\n',
                                                                              'prereq_command': 'if '
                                                                                                '((Test-Path '
                                                                                                'c:\\Tools\\T1103.dll) '
                                                                                                '-and '
                                                                                                '(Test-Path '
                                                                                                'c:\\Tools\\T1103x86.dll)) '
                                                                                                '{exit '
                                                                                                '0} '
                                                                                                'else '
                                                                                                '{exit '
                                                                                                '1}\n'}],
                                                            'dependency_executor_name': 'powershell',
                                                            'description': 'AppInit_DLLs '
                                                                           'is '
                                                                           'a '
                                                                           'mechanism '
                                                                           'that '
                                                                           'allows '
                                                                           'an '
                                                                           'arbitrary '
                                                                           'list '
                                                                           'of '
                                                                           'DLLs '
                                                                           'to '
                                                                           'be '
                                                                           'loaded '
                                                                           'into '
                                                                           'each '
                                                                           'user '
                                                                           'mode '
                                                                           'process '
                                                                           'on '
                                                                           'the '
                                                                           'system. '
                                                                           'Upon '
                                                                           'succesfully '
                                                                           'execution, \n'
                                                                           'you '
                                                                           'will '
                                                                           'see '
                                                                           'the '
                                                                           'message '
                                                                           '"The '
                                                                           'operation '
                                                                           'completed '
                                                                           'successfully." '
                                                                           'Each '
                                                                           'time '
                                                                           'the '
                                                                           'DLL '
                                                                           'is '
                                                                           'loaded, '
                                                                           'you '
                                                                           'will '
                                                                           'see '
                                                                           'a '
                                                                           'message '
                                                                           'box '
                                                                           'with '
                                                                           'a '
                                                                           'message '
                                                                           'of '
                                                                           '"Install '
                                                                           'AppInit '
                                                                           'Shim '
                                                                           'DLL '
                                                                           'was '
                                                                           'called!" '
                                                                           'appear.\n'
                                                                           'This '
                                                                           'will '
                                                                           'happen '
                                                                           'regular '
                                                                           'as '
                                                                           'your '
                                                                           'computer '
                                                                           'starts '
                                                                           'up '
                                                                           'various '
                                                                           'applications '
                                                                           'and '
                                                                           'may '
                                                                           'in '
                                                                           'fact '
                                                                           'drive '
                                                                           'you '
                                                                           'crazy. '
                                                                           'A '
                                                                           'reliable '
                                                                           'way '
                                                                           'to '
                                                                           'make '
                                                                           'the '
                                                                           'message '
                                                                           'box '
                                                                           'appear '
                                                                           'and '
                                                                           'verify '
                                                                           'the \n'
                                                                           'AppInit '
                                                                           'Dlls '
                                                                           'are '
                                                                           'loading '
                                                                           'is '
                                                                           'to '
                                                                           'start '
                                                                           'the '
                                                                           'notepad '
                                                                           'application. '
                                                                           'Be '
                                                                           'sure '
                                                                           'to '
                                                                           'run '
                                                                           'the '
                                                                           'cleanup '
                                                                           'commands '
                                                                           'afterwards '
                                                                           'so '
                                                                           'you '
                                                                           "don't "
                                                                           'keep '
                                                                           'getting '
                                                                           'message '
                                                                           'boxes '
                                                                           'showing '
                                                                           'up.\n',
                                                            'executor': {'cleanup_command': 'reg.exe '
                                                                                            'import '
                                                                                            '#{registry_cleanup_file}\n',
                                                                         'command': 'reg.exe '
                                                                                    'import '
                                                                                    '#{registry_file}\n',
                                                                         'elevation_required': True,
                                                                         'name': 'command_prompt'},
                                                            'input_arguments': {'registry_cleanup_file': {'default': 'PathToAtomicsFolder\\T1103\\src\\T1103-cleanup.reg',
                                                                                                          'description': 'Windows '
                                                                                                                         'Registry '
                                                                                                                         'File',
                                                                                                          'type': 'Path'},
                                                                                'registry_file': {'default': 'PathToAtomicsFolder\\T1103\\src\\T1103.reg',
                                                                                                  'description': 'Windows '
                                                                                                                 'Registry '
                                                                                                                 'File',
                                                                                                  'type': 'Path'}},
                                                            'name': 'Install '
                                                                    'AppInit '
                                                                    'Shim',
                                                            'supported_platforms': ['windows']}],
                                          'attack_technique': 'T1103',
                                          'display_name': 'AppInit DLLs'}},
 {'SysmonHunter - T1103': {'description': None,
                           'level': 'medium',
                           'name': 'AppInit DLLs',
                           'phase': 'Persistence',
                           'query': [{'reg': {'path': {'pattern': 'Microsoft\\Windows '
                                                                  'NT\\CurrentVersion\\Windows\\AppInit_DLLs|Microsoft\\Windows '
                                                                  'NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs'}},
                                      'type': 'reg'}]}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors

None
