
# Application Window Discovery

## Description

### MITRE Description

> Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger.

In Mac, this can be done natively with a small [AppleScript](https://attack.mitre.org/techniques/T1155) script.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1010

## Potential Commands

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe -out:#{output_file_name} PathToAtomicsFolder\T1010\src\T1010.cs
#{output_file_name}

C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe -out:$env:TEMP\T1010.exe #{input_source_code}
$env:TEMP\T1010.exe

{'windows': {'psh': {'command': '$x = Get-Process | Where-Object {$_.MainWindowTitle -ne ""} | Select-Object MainWindowTitle;\n$a = New-Object -com "Shell.Application"; $b = $a.windows() | select-object LocationName;\nwrite-host ($x | Format-List | Out-String) ($b | Format-List | Out-String)'}}}
```

## Commands Dataset

```
[{'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
             '-out:#{output_file_name} '
             'PathToAtomicsFolder\\T1010\\src\\T1010.cs\n'
             '#{output_file_name}\n',
  'name': None,
  'source': 'atomics/T1010/T1010.yaml'},
 {'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
             '-out:$env:TEMP\\T1010.exe #{input_source_code}\n'
             '$env:TEMP\\T1010.exe\n',
  'name': None,
  'source': 'atomics/T1010/T1010.yaml'},
 {'command': {'windows': {'psh': {'command': '$x = Get-Process | Where-Object '
                                             '{$_.MainWindowTitle -ne ""} | '
                                             'Select-Object MainWindowTitle;\n'
                                             '$a = New-Object -com '
                                             '"Shell.Application"; $b = '
                                             '$a.windows() | select-object '
                                             'LocationName;\n'
                                             'write-host ($x | Format-List | '
                                             'Out-String) ($b | Format-List | '
                                             'Out-String)'}}},
  'name': 'Extracts the names of all open non-explorer windows, and the '
          'locations of all explorer windows.',
  'source': 'data/abilities/discovery/5c65eec8-4839-4713-a4e1-86b2e75d1927.yml'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['API monitoring']}]
```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows local Powershell command execution, enumerate the '
           'application window\n'
           'description: windows server 2016\n'
           'references: No\n'
           'tags: T1010\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: powershell\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4104 # remote command '
           'execution\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0message:\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- 'get-process | "
           'where-object {. $ _ Mainwindowtitle -ne ""} | Select-Object '
           "mainwindowtitle' # command line parameters based on the detection, "
           'the detection rate is low\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0-. [Activator] :: '
           'CreateInstance ([type] :: GetTypeFromCLSID ( '
           '"13709620-C279-11CE-A49E-444553540000")) windows () # command line '
           'parameters based on the detection, the detection rate is low\n'
           '\xa0\xa0\xa0\xa0condition: selection\n'
           'level: low'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Application Window Discovery': {'atomic_tests': [{'auto_generated_guid': 'fe94a1c3-3e22-4dc9-9fdf-3a8bdbc10dc4',
                                                                            'dependencies': [{'description': 'T1010.cs '
                                                                                                             'must '
                                                                                                             'exist '
                                                                                                             'on '
                                                                                                             'disk '
                                                                                                             'at '
                                                                                                             'specified '
                                                                                                             'location '
                                                                                                             '(#{input_source_code})\n',
                                                                                              'get_prereq_command': 'New-Item '
                                                                                                                    '-Type '
                                                                                                                    'Directory '
                                                                                                                    '(split-path '
                                                                                                                    '#{input_source_code}) '
                                                                                                                    '-ErrorAction '
                                                                                                                    'ignore '
                                                                                                                    '| '
                                                                                                                    'Out-Null\n'
                                                                                                                    'Invoke-WebRequest '
                                                                                                                    'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1010/src/T1010.cs '
                                                                                                                    '-OutFile '
                                                                                                                    '"#{input_source_code}"\n',
                                                                                              'prereq_command': 'if '
                                                                                                                '(Test-Path '
                                                                                                                '#{input_source_code}) '
                                                                                                                '{exit '
                                                                                                                '0} '
                                                                                                                'else '
                                                                                                                '{exit '
                                                                                                                '1}\n'}],
                                                                            'dependency_executor_name': 'powershell',
                                                                            'description': 'Compiles '
                                                                                           'and '
                                                                                           'executes '
                                                                                           'C# '
                                                                                           'code '
                                                                                           'to '
                                                                                           'list '
                                                                                           'main '
                                                                                           'window '
                                                                                           'titles '
                                                                                           'associated '
                                                                                           'with '
                                                                                           'each '
                                                                                           'process.\n'
                                                                                           '\n'
                                                                                           'Upon '
                                                                                           'successful '
                                                                                           'execution, '
                                                                                           'powershell '
                                                                                           'will '
                                                                                           'download '
                                                                                           'the '
                                                                                           '.cs '
                                                                                           'from '
                                                                                           'the '
                                                                                           'Atomic '
                                                                                           'Red '
                                                                                           'Team '
                                                                                           'repo, '
                                                                                           'and '
                                                                                           'cmd.exe '
                                                                                           'will '
                                                                                           'compile '
                                                                                           'and '
                                                                                           'execute '
                                                                                           'T1010.exe. '
                                                                                           'Upon '
                                                                                           'T1010.exe '
                                                                                           'execution, '
                                                                                           'expected '
                                                                                           'output '
                                                                                           'will '
                                                                                           'be '
                                                                                           'via '
                                                                                           'stdout.\n',
                                                                            'executor': {'cleanup_command': 'del '
                                                                                                            '/f '
                                                                                                            '/q '
                                                                                                            '/s '
                                                                                                            '#{output_file_name} '
                                                                                                            '>nul '
                                                                                                            '2>&1\n',
                                                                                         'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
                                                                                                    '-out:#{output_file_name} '
                                                                                                    '#{input_source_code}\n'
                                                                                                    '#{output_file_name}\n',
                                                                                         'elevation_required': False,
                                                                                         'name': 'command_prompt'},
                                                                            'input_arguments': {'input_source_code': {'default': 'PathToAtomicsFolder\\T1010\\src\\T1010.cs',
                                                                                                                      'description': 'Path '
                                                                                                                                     'to '
                                                                                                                                     'source '
                                                                                                                                     'of '
                                                                                                                                     'C# '
                                                                                                                                     'code',
                                                                                                                      'type': 'path'},
                                                                                                'output_file_name': {'default': '$env:TEMP\\T1010.exe',
                                                                                                                     'description': 'Name '
                                                                                                                                    'of '
                                                                                                                                    'output '
                                                                                                                                    'binary',
                                                                                                                     'type': 'string'}},
                                                                            'name': 'List '
                                                                                    'Process '
                                                                                    'Main '
                                                                                    'Windows '
                                                                                    '- '
                                                                                    'C# '
                                                                                    '.NET',
                                                                            'supported_platforms': ['windows']}],
                                                          'attack_technique': 'T1010',
                                                          'display_name': 'Application '
                                                                          'Window '
                                                                          'Discovery'}},
 {'Mitre Stockpile - Extracts the names of all open non-explorer windows, and the locations of all explorer windows.': {'description': 'Extracts '
                                                                                                                                       'the '
                                                                                                                                       'names '
                                                                                                                                       'of '
                                                                                                                                       'all '
                                                                                                                                       'open '
                                                                                                                                       'non-explorer '
                                                                                                                                       'windows, '
                                                                                                                                       'and '
                                                                                                                                       'the '
                                                                                                                                       'locations '
                                                                                                                                       'of '
                                                                                                                                       'all '
                                                                                                                                       'explorer '
                                                                                                                                       'windows.',
                                                                                                                        'id': '5c65eec8-4839-4713-a4e1-86b2e75d1927',
                                                                                                                        'name': 'Application '
                                                                                                                                'Window '
                                                                                                                                'Discovery',
                                                                                                                        'platforms': {'windows': {'psh': {'command': '$x '
                                                                                                                                                                     '= '
                                                                                                                                                                     'Get-Process '
                                                                                                                                                                     '| '
                                                                                                                                                                     'Where-Object '
                                                                                                                                                                     '{$_.MainWindowTitle '
                                                                                                                                                                     '-ne '
                                                                                                                                                                     '""} '
                                                                                                                                                                     '| '
                                                                                                                                                                     'Select-Object '
                                                                                                                                                                     'MainWindowTitle;\n'
                                                                                                                                                                     '$a '
                                                                                                                                                                     '= '
                                                                                                                                                                     'New-Object '
                                                                                                                                                                     '-com '
                                                                                                                                                                     '"Shell.Application"; '
                                                                                                                                                                     '$b '
                                                                                                                                                                     '= '
                                                                                                                                                                     '$a.windows() '
                                                                                                                                                                     '| '
                                                                                                                                                                     'select-object '
                                                                                                                                                                     'LocationName;\n'
                                                                                                                                                                     'write-host '
                                                                                                                                                                     '($x '
                                                                                                                                                                     '| '
                                                                                                                                                                     'Format-List '
                                                                                                                                                                     '| '
                                                                                                                                                                     'Out-String) '
                                                                                                                                                                     '($b '
                                                                                                                                                                     '| '
                                                                                                                                                                     'Format-List '
                                                                                                                                                                     '| '
                                                                                                                                                                     'Out-String)'}}},
                                                                                                                        'tactic': 'discovery',
                                                                                                                        'technique': {'attack_id': 'T1010',
                                                                                                                                      'name': 'Application '
                                                                                                                                              'Window '
                                                                                                                                              'Discovery'}}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations

None

# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

