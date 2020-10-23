
# AppInit DLLs

## Description

### MITRE Description

> Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppInit_DLLs</code> value in the Registry keys <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> or <code>HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows</code> are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. (Citation: Endgame Process Injection July 2017)

Similar to Process Injection, these values can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. (Citation: AppInit Registry) Malicious AppInit DLLs may also provide persistence by continuously being triggered by API activity. 

The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled. (Citation: AppInit Secure Boot)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: ['Administrator', 'SYSTEM']
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1546/010

## Potential Commands

```
reg.exe import #{registry_file}
reg.exe import PathToAtomicsFolder\T1546.010\src\T1546.010.reg
```

## Commands Dataset

```
[{'command': 'reg.exe import '
             'PathToAtomicsFolder\\T1546.010\\src\\T1546.010.reg\n',
  'name': None,
  'source': 'atomics/T1546.010/T1546.010.yaml'},
 {'command': 'reg.exe import #{registry_file}\n',
  'name': None,
  'source': 'atomics/T1546.010/T1546.010.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Event Triggered Execution: AppInit DLLs': {'atomic_tests': [{'auto_generated_guid': 'a58d9386-3080-4242-ab5f-454c16503d18',
                                                                                       'dependencies': [{'description': 'Reg '
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
                                                                                                         'get_prereq_command': '[Net.ServicePointManager]::SecurityProtocol '
                                                                                                                               '= '
                                                                                                                               '[Net.SecurityProtocolType]::Tls12\n'
                                                                                                                               'New-Item '
                                                                                                                               '-Type '
                                                                                                                               'Directory '
                                                                                                                               '(split-path '
                                                                                                                               '#{registry_file}) '
                                                                                                                               '-ErrorAction '
                                                                                                                               'ignore '
                                                                                                                               '| '
                                                                                                                               'Out-Null\n'
                                                                                                                               'Invoke-WebRequest '
                                                                                                                               '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1546.010/src/T1546.010.reg" '
                                                                                                                               '-OutFile '
                                                                                                                               '"#{registry_file}"\n'
                                                                                                                               'Invoke-WebRequest '
                                                                                                                               '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1546.010/src/T1546.010-cleanup.reg" '
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
                                                                                                                        '(T1546.010.dll '
                                                                                                                        'and '
                                                                                                                        'T1546.010x86.dll)\n',
                                                                                                         'get_prereq_command': 'New-Item '
                                                                                                                               '-Type '
                                                                                                                               'Directory '
                                                                                                                               'C:\\Tools '
                                                                                                                               '-ErrorAction '
                                                                                                                               'ignore '
                                                                                                                               '| '
                                                                                                                               'Out-Null\n'
                                                                                                                               'Invoke-WebRequest '
                                                                                                                               '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1546.010/bin/T1546.010.dll" '
                                                                                                                               '-OutFile '
                                                                                                                               'C:\\Tools\\T1546.010.dll\n'
                                                                                                                               'Invoke-WebRequest '
                                                                                                                               '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1546.010/bin/T1546.010x86.dll" '
                                                                                                                               '-OutFile '
                                                                                                                               'C:\\Tools\\T1546.010x86.dll\n',
                                                                                                         'prereq_command': 'if '
                                                                                                                           '((Test-Path '
                                                                                                                           'c:\\Tools\\T1546.010.dll) '
                                                                                                                           '-and '
                                                                                                                           '(Test-Path '
                                                                                                                           'c:\\Tools\\T1546.010x86.dll)) '
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
                                                                                                      'regularly '
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
                                                                                                      'up\n',
                                                                                       'executor': {'cleanup_command': 'reg.exe '
                                                                                                                       'import '
                                                                                                                       '#{registry_cleanup_file} '
                                                                                                                       '>nul '
                                                                                                                       '2>&1\n',
                                                                                                    'command': 'reg.exe '
                                                                                                               'import '
                                                                                                               '#{registry_file}\n',
                                                                                                    'elevation_required': True,
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'registry_cleanup_file': {'default': 'PathToAtomicsFolder\\T1546.010\\src\\T1546.010-cleanup.reg',
                                                                                                                                     'description': 'Windows '
                                                                                                                                                    'Registry '
                                                                                                                                                    'File',
                                                                                                                                     'type': 'Path'},
                                                                                                           'registry_file': {'default': 'PathToAtomicsFolder\\T1546.010\\src\\T1546.010.reg',
                                                                                                                             'description': 'Windows '
                                                                                                                                            'Registry '
                                                                                                                                            'File',
                                                                                                                             'type': 'Path'}},
                                                                                       'name': 'Install '
                                                                                               'AppInit '
                                                                                               'Shim',
                                                                                       'supported_platforms': ['windows']}],
                                                                     'attack_technique': 'T1546.010',
                                                                     'display_name': 'Event '
                                                                                     'Triggered '
                                                                                     'Execution: '
                                                                                     'AppInit '
                                                                                     'DLLs'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Update Software](../mitigations/Update-Software.md)

* [Execution Prevention](../mitigations/Execution-Prevention.md)
    

# Actors

None
