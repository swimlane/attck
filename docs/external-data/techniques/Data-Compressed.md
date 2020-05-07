
# Data Compressed

## Description

### MITRE Description

> An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network. The compression is done separately from the exfiltration channel and is performed using a custom program or algorithm, or a more common compression library or utility such as 7zip, RAR, ZIP, or zlib.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1002

## Potential Commands

```
dir $env:USERPROFILE -Recurse | Compress-Archive -DestinationPath #{output_file}

dir #{input_file} -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\T1002-data-ps.zip

"#{rar_exe}" a -r #{output_file} %USERPROFILE%\*#{file_extension}

"#{rar_exe}" a -r #{output_file} #{input_path}\*.txt

"#{rar_exe}" a -r %USERPROFILE%\T1002-data.rar #{input_path}\*#{file_extension}

"#{rar_exe}" a -r #{output_file} #{input_path}\*#{file_extension}

"%programfiles%/WinRAR/Rar.exe" a -r #{output_file} #{input_path}\*#{file_extension}

zip #{output_file} $HOME/*.txt

zip $HOME/data.zip #{input_files}

test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt || (echo '#{input_content}' >> $HOME/victim-gzip.txt; gzip -k $HOME/victim-gzip.txt)

test -e #{input_file} && gzip -k #{input_file} || (echo 'confidential! SSN: 078-05-1120 - CCN: 4000 1234 5678 9101' >> #{input_file}; gzip -k #{input_file})

tar -cvzf #{output_file} $HOME/$USERNAME

tar -cvzf $HOME/data.tar.gz #{input_file_folder}

{'darwin': {'sh': {'command': 'tar -P -zcf #{host.dir.staged}.tar.gz #{host.dir.staged} && echo #{host.dir.staged}.tar.gz\n', 'cleanup': 'rm #{host.dir.staged}.tar.gz\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.compress'}]}}}, 'linux': {'sh': {'command': 'tar -P -zcf #{host.dir.staged}.tar.gz #{host.dir.staged} && echo #{host.dir.staged}.tar.gz\n', 'cleanup': 'rm #{host.dir.staged}.tar.gz\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.compress'}]}}}, 'windows': {'psh,pwsh': {'command': 'Compress-Archive -Path #{host.dir.staged} -DestinationPath #{host.dir.staged}.zip -Force;\nsleep 1; ls #{host.dir.staged}.zip | foreach {$_.FullName} | select\n', 'cleanup': 'rm #{host.dir.staged}.zip\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.compress'}]}}}}
rar.exe
powershell/management/zipfolder
powershell/management/zipfolder
```

## Commands Dataset

```
[{'command': 'dir $env:USERPROFILE -Recurse | Compress-Archive '
             '-DestinationPath #{output_file}\n',
  'name': None,
  'source': 'atomics/T1002/T1002.yaml'},
 {'command': 'dir #{input_file} -Recurse | Compress-Archive -DestinationPath '
             '$env:USERPROFILE\\T1002-data-ps.zip\n',
  'name': None,
  'source': 'atomics/T1002/T1002.yaml'},
 {'command': '"#{rar_exe}" a -r #{output_file} '
             '%USERPROFILE%\\*#{file_extension}\n',
  'name': None,
  'source': 'atomics/T1002/T1002.yaml'},
 {'command': '"#{rar_exe}" a -r #{output_file} #{input_path}\\*.txt\n',
  'name': None,
  'source': 'atomics/T1002/T1002.yaml'},
 {'command': '"#{rar_exe}" a -r %USERPROFILE%\\T1002-data.rar '
             '#{input_path}\\*#{file_extension}\n',
  'name': None,
  'source': 'atomics/T1002/T1002.yaml'},
 {'command': '"#{rar_exe}" a -r #{output_file} '
             '#{input_path}\\*#{file_extension}\n',
  'name': None,
  'source': 'atomics/T1002/T1002.yaml'},
 {'command': '"%programfiles%/WinRAR/Rar.exe" a -r #{output_file} '
             '#{input_path}\\*#{file_extension}\n',
  'name': None,
  'source': 'atomics/T1002/T1002.yaml'},
 {'command': 'zip #{output_file} $HOME/*.txt\n',
  'name': None,
  'source': 'atomics/T1002/T1002.yaml'},
 {'command': 'zip $HOME/data.zip #{input_files}\n',
  'name': None,
  'source': 'atomics/T1002/T1002.yaml'},
 {'command': 'test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt '
             "|| (echo '#{input_content}' >> $HOME/victim-gzip.txt; gzip -k "
             '$HOME/victim-gzip.txt)\n',
  'name': None,
  'source': 'atomics/T1002/T1002.yaml'},
 {'command': 'test -e #{input_file} && gzip -k #{input_file} || (echo '
             "'confidential! SSN: 078-05-1120 - CCN: 4000 1234 5678 9101' >> "
             '#{input_file}; gzip -k #{input_file})\n',
  'name': None,
  'source': 'atomics/T1002/T1002.yaml'},
 {'command': 'tar -cvzf #{output_file} $HOME/$USERNAME\n',
  'name': None,
  'source': 'atomics/T1002/T1002.yaml'},
 {'command': 'tar -cvzf $HOME/data.tar.gz #{input_file_folder}\n',
  'name': None,
  'source': 'atomics/T1002/T1002.yaml'},
 {'command': {'darwin': {'sh': {'cleanup': 'rm #{host.dir.staged}.tar.gz\n',
                                'command': 'tar -P -zcf '
                                           '#{host.dir.staged}.tar.gz '
                                           '#{host.dir.staged} && echo '
                                           '#{host.dir.staged}.tar.gz\n',
                                'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.compress'}]}}},
              'linux': {'sh': {'cleanup': 'rm #{host.dir.staged}.tar.gz\n',
                               'command': 'tar -P -zcf '
                                          '#{host.dir.staged}.tar.gz '
                                          '#{host.dir.staged} && echo '
                                          '#{host.dir.staged}.tar.gz\n',
                               'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.compress'}]}}},
              'windows': {'psh,pwsh': {'cleanup': 'rm #{host.dir.staged}.zip\n',
                                       'command': 'Compress-Archive -Path '
                                                  '#{host.dir.staged} '
                                                  '-DestinationPath '
                                                  '#{host.dir.staged}.zip '
                                                  '-Force;\n'
                                                  'sleep 1; ls '
                                                  '#{host.dir.staged}.zip | '
                                                  'foreach {$_.FullName} | '
                                                  'select\n',
                                       'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.compress'}]}}}},
  'name': 'Compress a directory on the file system',
  'source': 'data/abilities/exfiltration/300157e5-f4ad-4569-b533-9d1fa0e74d74.yml'},
 {'command': 'rar.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell/management/zipfolder',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/zipfolder',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'date': '2019/02/21',
                  'description': 'Detects Judgement Panda activity as '
                                 'described in Global Threat Report 2019 by '
                                 'Crowdstrike',
                  'detection': {'condition': 'selection1 or selection2',
                                'selection1': {'CommandLine': ['*\\ldifde.exe '
                                                               '-f -n *',
                                                               '*\\7za.exe a '
                                                               '1.7z *',
                                                               '* eprod.ldf',
                                                               '*\\aaaa\\procdump64.exe*',
                                                               '*\\aaaa\\netsess.exe*',
                                                               '*\\aaaa\\7za.exe*',
                                                               '*copy .\\1.7z '
                                                               '\\\\*',
                                                               '*copy '
                                                               '\\\\client\\c$\\aaaa\\\\*']},
                                'selection2': {'Image': 'C:\\Users\\Public\\7za.exe'}},
                  'falsepositives': ['unknown'],
                  'id': '03e2746e-2b31-42f1-ab7a-eb39365b2422',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/'],
                  'tags': ['attack.lateral_movement',
                           'attack.g0010',
                           'attack.credential_access',
                           'attack.t1098',
                           'attack.exfiltration',
                           'attack.t1002'],
                  'title': 'Judgement Panda Exfil Activity'}},
 {'data_source': {'author': 'Timur Zinniatullin, oscd.community',
                  'date': '2019/10/21',
                  'description': 'An adversary may compress data (e.g., '
                                 'sensitive documents) that is collected prior '
                                 'to exfiltration in order to make it portable '
                                 'and minimize the amount of data sent over '
                                 'the network',
                  'detection': {'condition': '1 of them',
                                'selection1': {'a0': 'zip', 'type': 'execve'},
                                'selection2': {'a0': 'gzip',
                                               'a1': '-f',
                                               'type': 'execve'},
                                'selection3': {'a0': 'tar',
                                               'a1|contains': '-c',
                                               'type': 'execve'}},
                  'falsepositives': ['Legitimate use of archiving tools by '
                                     'legitimate user'],
                  'id': 'a3b5e3e9-1b49-4119-8b8e-0344a01f21ee',
                  'level': 'low',
                  'logsource': {'product': 'linux', 'service': 'auditd'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml'],
                  'status': 'experimental',
                  'tags': ['attack.exfiltration', 'attack.t1002'],
                  'title': 'Data Compressed'}},
 {'data_source': {'author': 'Timur Zinniatullin, oscd.community',
                  'date': '2019/10/21',
                  'description': 'An adversary may compress data (e.g., '
                                 'sensitive documents) that is collected prior '
                                 'to exfiltration in order to make it portable '
                                 'and minimize the amount of data sent over '
                                 'the network',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 4104,
                                              'keywords|contains|all': ['-Recurse',
                                                                        '|',
                                                                        'Compress-Archive']}},
                  'falsepositives': ['highly likely if archive ops are done '
                                     'via PS'],
                  'id': '6dc5d284-69ea-42cf-9311-fb1c3932a69a',
                  'level': 'low',
                  'logsource': {'description': 'Script block logging must be '
                                               'enabled',
                                'product': 'windows',
                                'service': 'powershell'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml'],
                  'status': 'experimental',
                  'tags': ['attack.exfiltration', 'attack.t1002'],
                  'title': 'Data Compressed'}},
 {'data_source': {'author': 'Timur Zinniatullin, oscd.community',
                  'date': '2019/10/21',
                  'description': 'An adversary may compress data (e.g., '
                                 'sensitive documents) that is collected prior '
                                 'to exfiltration in order to make it portable '
                                 'and minimize the amount of data sent over '
                                 'the network',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine|contains|all': [' '
                                                                           'a ',
                                                                           '-r'],
                                              'Image|endswith': '\\rar.exe'}},
                  'falsepositives': ['highly likely if rar is default archiver '
                                     'in the monitored environment'],
                  'fields': ['Image',
                             'CommandLine',
                             'User',
                             'LogonGuid',
                             'Hashes',
                             'ParentProcessGuid',
                             'ParentCommandLine'],
                  'id': '6f3e2987-db24-4c78-a860-b4f4095a7095',
                  'level': 'low',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml'],
                  'status': 'experimental',
                  'tags': ['attack.exfiltration', 'attack.t1002'],
                  'title': 'Data Compressed'}},
 {'data_source': {'author': 'Florian Roth, Samir Bousseaden',
                  'date': '2019/10/15',
                  'description': 'Detects suspicious command line arguments of '
                                 'common data compression tools',
                  'detection': {'condition': 'selection and not falsepositive',
                                'falsepositive': {'ParentImage': 'C:\\Program*'},
                                'selection': {'CommandLine': ['* -p*',
                                                              '* -ta*',
                                                              '* -tb*',
                                                              '* -sdel*',
                                                              '* -dw*',
                                                              '* -hp*'],
                                              'OriginalFileName': ['7z*.exe',
                                                                   '*rar.exe',
                                                                   '*Command*Line*RAR*']}},
                  'falsepositives': ['unknown'],
                  'id': '27a72a60-7e5e-47b1-9d17-909c9abafdcd',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://twitter.com/SBousseaden/status/1184067445612535811'],
                  'status': 'experimental',
                  'tags': ['attack.exfiltration',
                           'attack.t1020',
                           'attack.t1002'],
                  'title': 'Suspicious Compression Tool Parameters'}}]
```

## Potential Queries

```json
[{'name': 'Data Compressed',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains '
           '"powershell.exe"and process_command_line contains "-Recurse | '
           'Compress-Archive")or (process_path contains "rar.exe"and '
           'process_command_line contains "rar*a*")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Data Compressed': {'atomic_tests': [{'description': 'An '
                                                                              'adversary '
                                                                              'may '
                                                                              'compress '
                                                                              'data '
                                                                              '(e.g., '
                                                                              'sensitive '
                                                                              'documents) '
                                                                              'that '
                                                                              'is '
                                                                              'collected '
                                                                              'prior '
                                                                              'to '
                                                                              'exfiltration.\n'
                                                                              'When '
                                                                              'the '
                                                                              'test '
                                                                              'completes '
                                                                              'you '
                                                                              'should '
                                                                              'find '
                                                                              'the '
                                                                              'files '
                                                                              'from '
                                                                              'the '
                                                                              '$env:USERPROFILE '
                                                                              'directory '
                                                                              'compressed '
                                                                              'in '
                                                                              'a '
                                                                              'file '
                                                                              'called '
                                                                              'T1002-data-ps.zip '
                                                                              'in '
                                                                              'the '
                                                                              '$env:USERPROFILE '
                                                                              'directory \n',
                                                               'executor': {'cleanup_command': 'Remove-Item '
                                                                                               '-path '
                                                                                               '#{output_file} '
                                                                                               '-ErrorAction '
                                                                                               'Ignore\n',
                                                                            'command': 'dir '
                                                                                       '#{input_file} '
                                                                                       '-Recurse '
                                                                                       '| '
                                                                                       'Compress-Archive '
                                                                                       '-DestinationPath '
                                                                                       '#{output_file}\n',
                                                                            'elevation_required': False,
                                                                            'name': 'powershell'},
                                                               'input_arguments': {'input_file': {'default': '$env:USERPROFILE',
                                                                                                  'description': 'Path '
                                                                                                                 'that '
                                                                                                                 'should '
                                                                                                                 'be '
                                                                                                                 'compressed '
                                                                                                                 'into '
                                                                                                                 'our '
                                                                                                                 'output '
                                                                                                                 'file',
                                                                                                  'type': 'Path'},
                                                                                   'output_file': {'default': '$env:USERPROFILE\\T1002-data-ps.zip',
                                                                                                   'description': 'Path '
                                                                                                                  'where '
                                                                                                                  'resulting '
                                                                                                                  'compressed '
                                                                                                                  'data '
                                                                                                                  'should '
                                                                                                                  'be '
                                                                                                                  'placed',
                                                                                                   'type': 'Path'}},
                                                               'name': 'Compress '
                                                                       'Data '
                                                                       'for '
                                                                       'Exfiltration '
                                                                       'With '
                                                                       'PowerShell',
                                                               'supported_platforms': ['windows']},
                                                              {'dependencies': [{'description': 'Rar '
                                                                                                'tool '
                                                                                                'must '
                                                                                                'be '
                                                                                                'installed '
                                                                                                'at '
                                                                                                'specified '
                                                                                                'location '
                                                                                                '(#{rar_exe})\n',
                                                                                 'get_prereq_command': 'echo '
                                                                                                       'Downloading '
                                                                                                       'Winrar '
                                                                                                       'installer\n'
                                                                                                       'bitsadmin '
                                                                                                       '/transfer '
                                                                                                       'myDownloadJob '
                                                                                                       '/download '
                                                                                                       '/priority '
                                                                                                       'normal '
                                                                                                       '"https://www.win-rar.com/fileadmin/winrar-versions/winrar/th/winrar-x64-580.exe" '
                                                                                                       '#{rar_installer}\n'
                                                                                                       'echo '
                                                                                                       'Follow '
                                                                                                       'the '
                                                                                                       'installer '
                                                                                                       'prompts '
                                                                                                       'to '
                                                                                                       'install '
                                                                                                       'Winrar\n'
                                                                                                       '#{rar_installer}\n',
                                                                                 'prereq_command': 'if '
                                                                                                   'not '
                                                                                                   'exist '
                                                                                                   '"#{rar_exe}" '
                                                                                                   '(exit '
                                                                                                   '/b '
                                                                                                   '1)\n'}],
                                                               'description': 'An '
                                                                              'adversary '
                                                                              'may '
                                                                              'compress '
                                                                              'data '
                                                                              '(e.g., '
                                                                              'sensitive '
                                                                              'documents) '
                                                                              'that '
                                                                              'is '
                                                                              'collected '
                                                                              'prior '
                                                                              'to '
                                                                              'exfiltration.\n'
                                                                              'When '
                                                                              'the '
                                                                              'test '
                                                                              'completes '
                                                                              'you '
                                                                              'should '
                                                                              'find '
                                                                              'the '
                                                                              'txt '
                                                                              'files '
                                                                              'from '
                                                                              'the '
                                                                              '%USERPROFILE% '
                                                                              'directory '
                                                                              'compressed '
                                                                              'in '
                                                                              'a '
                                                                              'file '
                                                                              'called '
                                                                              'T1002-data.rar '
                                                                              'in '
                                                                              'the '
                                                                              '%USERPROFILE% '
                                                                              'directory \n',
                                                               'executor': {'cleanup_command': 'del '
                                                                                               '/f '
                                                                                               '/q '
                                                                                               '/s '
                                                                                               '#{output_file} '
                                                                                               '>nul '
                                                                                               '2>&1\n',
                                                                            'command': '"#{rar_exe}" '
                                                                                       'a '
                                                                                       '-r '
                                                                                       '#{output_file} '
                                                                                       '#{input_path}\\*#{file_extension}\n',
                                                                            'elevation_required': False,
                                                                            'name': 'command_prompt'},
                                                               'input_arguments': {'file_extension': {'default': '.txt',
                                                                                                      'description': 'Extension '
                                                                                                                     'of '
                                                                                                                     'files '
                                                                                                                     'to '
                                                                                                                     'compress',
                                                                                                      'type': 'String'},
                                                                                   'input_path': {'default': '%USERPROFILE%',
                                                                                                  'description': 'Path '
                                                                                                                 'that '
                                                                                                                 'should '
                                                                                                                 'be '
                                                                                                                 'compressed '
                                                                                                                 'into '
                                                                                                                 'our '
                                                                                                                 'output '
                                                                                                                 'file',
                                                                                                  'type': 'Path'},
                                                                                   'output_file': {'default': '%USERPROFILE%\\T1002-data.rar',
                                                                                                   'description': 'Path '
                                                                                                                  'where '
                                                                                                                  'resulting '
                                                                                                                  'compressed '
                                                                                                                  'data '
                                                                                                                  'should '
                                                                                                                  'be '
                                                                                                                  'placed',
                                                                                                   'type': 'Path'},
                                                                                   'rar_exe': {'default': '%programfiles%/WinRAR/Rar.exe',
                                                                                               'description': 'The '
                                                                                                              'RAR '
                                                                                                              'executable '
                                                                                                              'from '
                                                                                                              'Winrar',
                                                                                               'type': 'Path'},
                                                                                   'rar_installer': {'default': '%TEMP%\\winrar.exe',
                                                                                                     'description': 'Winrar '
                                                                                                                    'installer',
                                                                                                     'type': 'Path'}},
                                                               'name': 'Compress '
                                                                       'Data '
                                                                       'for '
                                                                       'Exfiltration '
                                                                       'With '
                                                                       'Rar',
                                                               'supported_platforms': ['windows']},
                                                              {'dependencies': [{'description': 'Files '
                                                                                                'to '
                                                                                                'zip '
                                                                                                'must '
                                                                                                'exist '
                                                                                                '(#{input_files})\n',
                                                                                 'get_prereq_command': 'echo '
                                                                                                       'Please '
                                                                                                       'set '
                                                                                                       'input_files '
                                                                                                       'argument '
                                                                                                       'to '
                                                                                                       'include '
                                                                                                       'files '
                                                                                                       'that '
                                                                                                       'exist\n',
                                                                                 'prereq_command': 'ls '
                                                                                                   '#{input_files}\n'}],
                                                               'description': 'An '
                                                                              'adversary '
                                                                              'may '
                                                                              'compress '
                                                                              'data '
                                                                              '(e.g., '
                                                                              'sensitive '
                                                                              'documents) '
                                                                              'that '
                                                                              'is '
                                                                              'collected '
                                                                              'prior '
                                                                              'to '
                                                                              'exfiltration. '
                                                                              'This '
                                                                              'test '
                                                                              'uses '
                                                                              'standard '
                                                                              'zip '
                                                                              'compression.\n',
                                                               'executor': {'cleanup_command': 'rm '
                                                                                               '-f '
                                                                                               '#{output_file}\n',
                                                                            'command': 'zip '
                                                                                       '#{output_file} '
                                                                                       '#{input_files}\n',
                                                                            'elevation_required': False,
                                                                            'name': 'sh',
                                                                            'prereq_command': 'ls '
                                                                                              '#{input_files} '
                                                                                              '> '
                                                                                              '/dev/null\n'},
                                                               'input_arguments': {'input_files': {'default': '$HOME/*.txt',
                                                                                                   'description': 'Path '
                                                                                                                  'that '
                                                                                                                  'should '
                                                                                                                  'be '
                                                                                                                  'compressed '
                                                                                                                  'into '
                                                                                                                  'our '
                                                                                                                  'output '
                                                                                                                  'file, '
                                                                                                                  'may '
                                                                                                                  'include '
                                                                                                                  'wildcards',
                                                                                                   'type': 'Path'},
                                                                                   'output_file': {'default': '$HOME/data.zip',
                                                                                                   'description': 'Path '
                                                                                                                  'that '
                                                                                                                  'should '
                                                                                                                  'be '
                                                                                                                  'output '
                                                                                                                  'as '
                                                                                                                  'a '
                                                                                                                  'zip '
                                                                                                                  'archive',
                                                                                                   'type': 'Path'}},
                                                               'name': 'Data '
                                                                       'Compressed '
                                                                       '- nix '
                                                                       '- zip',
                                                               'supported_platforms': ['linux',
                                                                                       'macos']},
                                                              {'description': 'An '
                                                                              'adversary '
                                                                              'may '
                                                                              'compress '
                                                                              'data '
                                                                              '(e.g., '
                                                                              'sensitive '
                                                                              'documents) '
                                                                              'that '
                                                                              'is '
                                                                              'collected '
                                                                              'prior '
                                                                              'to '
                                                                              'exfiltration. '
                                                                              'This '
                                                                              'test '
                                                                              'uses '
                                                                              'standard '
                                                                              'gzip '
                                                                              'compression.\n',
                                                               'executor': {'cleanup_command': 'rm '
                                                                                               '-f '
                                                                                               '#{input_file}.gz\n',
                                                                            'command': 'test '
                                                                                       '-e '
                                                                                       '#{input_file} '
                                                                                       '&& '
                                                                                       'gzip '
                                                                                       '-k '
                                                                                       '#{input_file} '
                                                                                       '|| '
                                                                                       '(echo '
                                                                                       "'#{input_content}' "
                                                                                       '>> '
                                                                                       '#{input_file}; '
                                                                                       'gzip '
                                                                                       '-k '
                                                                                       '#{input_file})\n',
                                                                            'elevation_required': False,
                                                                            'name': 'sh'},
                                                               'input_arguments': {'input_content': {'default': 'confidential! '
                                                                                                                'SSN: '
                                                                                                                '078-05-1120 '
                                                                                                                '- '
                                                                                                                'CCN: '
                                                                                                                '4000 '
                                                                                                                '1234 '
                                                                                                                '5678 '
                                                                                                                '9101',
                                                                                                     'description': 'contents '
                                                                                                                    'of '
                                                                                                                    'compressed '
                                                                                                                    'files '
                                                                                                                    'if '
                                                                                                                    'file '
                                                                                                                    'does '
                                                                                                                    'not '
                                                                                                                    'already '
                                                                                                                    'exist. '
                                                                                                                    'default '
                                                                                                                    'contains '
                                                                                                                    'test '
                                                                                                                    'credit '
                                                                                                                    'card '
                                                                                                                    'and '
                                                                                                                    'social '
                                                                                                                    'security '
                                                                                                                    'number',
                                                                                                     'type': 'String'},
                                                                                   'input_file': {'default': '$HOME/victim-gzip.txt',
                                                                                                  'description': 'Path '
                                                                                                                 'that '
                                                                                                                 'should '
                                                                                                                 'be '
                                                                                                                 'compressed',
                                                                                                  'type': 'Path'}},
                                                               'name': 'Data '
                                                                       'Compressed '
                                                                       '- nix '
                                                                       '- gzip '
                                                                       'Single '
                                                                       'File',
                                                               'supported_platforms': ['linux',
                                                                                       'macos']},
                                                              {'dependencies': [{'description': 'Folder '
                                                                                                'to '
                                                                                                'zip '
                                                                                                'must '
                                                                                                'exist '
                                                                                                '(#{input_file_folder})\n',
                                                                                 'get_prereq_command': 'echo '
                                                                                                       'Please '
                                                                                                       'set '
                                                                                                       'input_file_folder '
                                                                                                       'argument '
                                                                                                       'to '
                                                                                                       'a '
                                                                                                       'folder '
                                                                                                       'that '
                                                                                                       'exists\n',
                                                                                 'prereq_command': 'test '
                                                                                                   '-e '
                                                                                                   '#{input_file_folder}\n'}],
                                                               'description': 'An '
                                                                              'adversary '
                                                                              'may '
                                                                              'compress '
                                                                              'data '
                                                                              '(e.g., '
                                                                              'sensitive '
                                                                              'documents) '
                                                                              'that '
                                                                              'is '
                                                                              'collected '
                                                                              'prior '
                                                                              'to '
                                                                              'exfiltration. '
                                                                              'This '
                                                                              'test '
                                                                              'uses '
                                                                              'standard '
                                                                              'gzip '
                                                                              'compression.\n',
                                                               'executor': {'cleanup_command': 'rm '
                                                                                               '-f '
                                                                                               '#{output_file}\n',
                                                                            'command': 'tar '
                                                                                       '-cvzf '
                                                                                       '#{output_file} '
                                                                                       '#{input_file_folder}\n',
                                                                            'elevation_required': False,
                                                                            'name': 'sh'},
                                                               'input_arguments': {'input_file_folder': {'default': '$HOME/$USERNAME',
                                                                                                         'description': 'Path '
                                                                                                                        'that '
                                                                                                                        'should '
                                                                                                                        'be '
                                                                                                                        'compressed',
                                                                                                         'type': 'Path'},
                                                                                   'output_file': {'default': '$HOME/data.tar.gz',
                                                                                                   'description': 'File '
                                                                                                                  'that '
                                                                                                                  'should '
                                                                                                                  'be '
                                                                                                                  'output',
                                                                                                   'type': 'Path'}},
                                                               'name': 'Data '
                                                                       'Compressed '
                                                                       '- nix '
                                                                       '- tar '
                                                                       'Folder '
                                                                       'or '
                                                                       'File',
                                                               'supported_platforms': ['linux',
                                                                                       'macos']}],
                                             'attack_technique': 'T1002',
                                             'display_name': 'Data '
                                                             'Compressed'}},
 {'Mitre Stockpile - Compress a directory on the file system': {'description': 'Compress '
                                                                               'a '
                                                                               'directory '
                                                                               'on '
                                                                               'the '
                                                                               'file '
                                                                               'system',
                                                                'id': '300157e5-f4ad-4569-b533-9d1fa0e74d74',
                                                                'name': 'Compress '
                                                                        'staged '
                                                                        'directory',
                                                                'platforms': {'darwin': {'sh': {'cleanup': 'rm '
                                                                                                           '#{host.dir.staged}.tar.gz\n',
                                                                                                'command': 'tar '
                                                                                                           '-P '
                                                                                                           '-zcf '
                                                                                                           '#{host.dir.staged}.tar.gz '
                                                                                                           '#{host.dir.staged} '
                                                                                                           '&& '
                                                                                                           'echo '
                                                                                                           '#{host.dir.staged}.tar.gz\n',
                                                                                                'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.compress'}]}}},
                                                                              'linux': {'sh': {'cleanup': 'rm '
                                                                                                          '#{host.dir.staged}.tar.gz\n',
                                                                                               'command': 'tar '
                                                                                                          '-P '
                                                                                                          '-zcf '
                                                                                                          '#{host.dir.staged}.tar.gz '
                                                                                                          '#{host.dir.staged} '
                                                                                                          '&& '
                                                                                                          'echo '
                                                                                                          '#{host.dir.staged}.tar.gz\n',
                                                                                               'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.compress'}]}}},
                                                                              'windows': {'psh,pwsh': {'cleanup': 'rm '
                                                                                                                  '#{host.dir.staged}.zip\n',
                                                                                                       'command': 'Compress-Archive '
                                                                                                                  '-Path '
                                                                                                                  '#{host.dir.staged} '
                                                                                                                  '-DestinationPath '
                                                                                                                  '#{host.dir.staged}.zip '
                                                                                                                  '-Force;\n'
                                                                                                                  'sleep '
                                                                                                                  '1; '
                                                                                                                  'ls '
                                                                                                                  '#{host.dir.staged}.zip '
                                                                                                                  '| '
                                                                                                                  'foreach '
                                                                                                                  '{$_.FullName} '
                                                                                                                  '| '
                                                                                                                  'select\n',
                                                                                                       'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.compress'}]}}}},
                                                                'requirements': [{'plugins.stockpile.app.requirements.paw_provenance': [{'source': 'host.dir.staged'}]}],
                                                                'tactic': 'exfiltration',
                                                                'technique': {'attack_id': 'T1002',
                                                                              'name': 'Data '
                                                                                      'Compressed'}}},
 {'Threat Hunting Tables': {'chain_id': '100067',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1002',
                            'mitre_caption': 'data_compressed',
                            'os': 'windows',
                            'parent_process': 'rar.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1002',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/zipfolder":  '
                                                                                 '["T1002"],',
                                            'Empire Module': 'powershell/management/zipfolder',
                                            'Technique': 'Data Compressed'}}]
```

# Tactics


* [Exfiltration](../tactics/Exfiltration.md)


# Mitigations

None

# Actors


* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)

* [CopyKittens](../actors/CopyKittens.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [APT1](../actors/APT1.md)
    
* [FIN8](../actors/FIN8.md)
    
* [FIN6](../actors/FIN6.md)
    
* [Sowbug](../actors/Sowbug.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [APT3](../actors/APT3.md)
    
* [APT28](../actors/APT28.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT39](../actors/APT39.md)
    
* [APT32](../actors/APT32.md)
    
* [APT33](../actors/APT33.md)
    
* [Gallmaker](../actors/Gallmaker.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
