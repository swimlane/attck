
# Native API

## Description

### MITRE Description

> Adversaries may directly interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes.(Citation: NT API Windows)(Citation: Linux Kernel API) These native APIs are leveraged by the OS during system boot (when other system components are not yet initialized) as well as carrying out tasks and requests during routine operations.

Functionality provided by native APIs are often also exposed to user-mode applications via interfaces and libraries. For example, functions such as the Windows API <code>CreateProcess()</code> or GNU <code>fork()</code> will allow programs and scripts to start other processes.(Citation: Microsoft CreateProcess)(Citation: GNU Fork) This may allow API callers to execute a binary, run a CLI command, load modules, etc. as thousands of similar API functions exist for various system operations.(Citation: Microsoft Win32)(Citation: LIBC)(Citation: GLIBC)

Higher level software frameworks, such as Microsoft .NET and macOS Cocoa, are also available to interact with native APIs. These frameworks typically provide language wrappers/abstractions to API functionalities and are designed for ease-of-use/portability of code.(Citation: Microsoft NET)(Citation: Apple Core Services)(Citation: MACOS Cocoa)(Citation: macOS Foundation)

Adversaries may abuse these native API functions as a means of executing behaviors. Similar to [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), the native API and its hierarchy of interfaces, provide mechanisms to interact with and utilize various components of a victimized system.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows', 'macOS', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1106

## Potential Commands

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /out:"#{output_file}" /target:exe PathToAtomicsFolder\T1106\src\CreateProcess.cs
%tmp%/T1106.exe

C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /out:"%tmp%\T1106.exe" /target:exe #{source_file}
%tmp%/T1106.exe

python/situational_awareness/network/dcos/chronos_api_add_job
python/situational_awareness/network/dcos/chronos_api_add_job
python/situational_awareness/network/dcos/chronos_api_delete_job
python/situational_awareness/network/dcos/chronos_api_delete_job
python/situational_awareness/network/dcos/chronos_api_start_job
python/situational_awareness/network/dcos/chronos_api_start_job
python/situational_awareness/network/dcos/marathon_api_create_start_app
python/situational_awareness/network/dcos/marathon_api_create_start_app
python/situational_awareness/network/dcos/marathon_api_delete_app
python/situational_awareness/network/dcos/marathon_api_delete_app
python/situational_awareness/network/http_rest_api
python/situational_awareness/network/http_rest_api
```

## Commands Dataset

```
[{'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
             '/out:"#{output_file}" /target:exe '
             'PathToAtomicsFolder\\T1106\\src\\CreateProcess.cs\n'
             '%tmp%/T1106.exe\n',
  'name': None,
  'source': 'atomics/T1106/T1106.yaml'},
 {'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
             '/out:"%tmp%\\T1106.exe" /target:exe #{source_file}\n'
             '%tmp%/T1106.exe\n',
  'name': None,
  'source': 'atomics/T1106/T1106.yaml'},
 {'command': 'python/situational_awareness/network/dcos/chronos_api_add_job',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/chronos_api_add_job',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/chronos_api_delete_job',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/chronos_api_delete_job',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/chronos_api_start_job',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/chronos_api_start_job',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/marathon_api_create_start_app',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/marathon_api_create_start_app',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/marathon_api_delete_app',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/marathon_api_delete_app',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/http_rest_api',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/http_rest_api',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['API monitoring']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Native API': {'atomic_tests': [{'auto_generated_guid': '99be2089-c52d-4a4a-b5c3-261ee42c8b62',
                                                          'description': 'Execute '
                                                                         'program '
                                                                         'by '
                                                                         'leveraging '
                                                                         'Win32 '
                                                                         "API's. "
                                                                         'By '
                                                                         'default, '
                                                                         'this '
                                                                         'will '
                                                                         'launch '
                                                                         'calc.exe '
                                                                         'from '
                                                                         'the '
                                                                         'command '
                                                                         'prompt.',
                                                          'executor': {'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
                                                                                  '/out:"#{output_file}" '
                                                                                  '/target:exe '
                                                                                  '#{source_file}\n'
                                                                                  '%tmp%/T1106.exe\n',
                                                                       'name': 'command_prompt'},
                                                          'input_arguments': {'output_file': {'default': '%tmp%\\T1106.exe',
                                                                                              'description': 'Location '
                                                                                                             'of '
                                                                                                             'the '
                                                                                                             'payload',
                                                                                              'type': 'Path'},
                                                                              'source_file': {'default': 'PathToAtomicsFolder\\T1106\\src\\CreateProcess.cs',
                                                                                              'description': 'Location '
                                                                                                             'of '
                                                                                                             'the '
                                                                                                             'CSharp '
                                                                                                             'source '
                                                                                                             'file '
                                                                                                             'to '
                                                                                                             'compile '
                                                                                                             'and '
                                                                                                             'execute',
                                                                                              'type': 'Path'}},
                                                          'name': 'Execution '
                                                                  'through API '
                                                                  '- '
                                                                  'CreateProcess',
                                                          'supported_platforms': ['windows']}],
                                        'attack_technique': 'T1106',
                                        'display_name': 'Native API'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1106',
                                            'ATT&CK Technique #2': 'T1168',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/dcos/chronos_api_add_job":  '
                                                                                 '["T1106","T1168"],',
                                            'Empire Module': 'python/situational_awareness/network/dcos/chronos_api_add_job',
                                            'Technique': 'Execution through '
                                                         'API'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1106',
                                            'ATT&CK Technique #2': 'T1168',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/dcos/chronos_api_delete_job":  '
                                                                                 '["T1106","T1168"],',
                                            'Empire Module': 'python/situational_awareness/network/dcos/chronos_api_delete_job',
                                            'Technique': 'Execution through '
                                                         'API'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1106',
                                            'ATT&CK Technique #2': 'T1168',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/dcos/chronos_api_start_job":  '
                                                                                 '["T1106","T1168"],',
                                            'Empire Module': 'python/situational_awareness/network/dcos/chronos_api_start_job',
                                            'Technique': 'Execution through '
                                                         'API'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1106',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/dcos/marathon_api_create_start_app":  '
                                                                                 '["T1106"],',
                                            'Empire Module': 'python/situational_awareness/network/dcos/marathon_api_create_start_app',
                                            'Technique': 'Execution through '
                                                         'API'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1106',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/dcos/marathon_api_delete_app":  '
                                                                                 '["T1106"],',
                                            'Empire Module': 'python/situational_awareness/network/dcos/marathon_api_delete_app',
                                            'Technique': 'Execution through '
                                                         'API'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1106',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/http_rest_api":  '
                                                                                 '["T1106"],',
                                            'Empire Module': 'python/situational_awareness/network/http_rest_api',
                                            'Technique': 'Execution through '
                                                         'API'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)


# Actors


* [APT37](../actors/APT37.md)

* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [Silence](../actors/Silence.md)
    
* [Turla](../actors/Turla.md)
    
* [Sharpshooter](../actors/Sharpshooter.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
