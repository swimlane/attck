
# Process Discovery

## Description

### MITRE Description

> Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Adversaries may use the information from [Process Discovery](https://attack.mitre.org/techniques/T1057) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

In Windows environments, adversaries could obtain details on running processes using the [Tasklist](https://attack.mitre.org/software/S0057) utility via [cmd](https://attack.mitre.org/software/S0106) or <code>Get-Process</code> via [PowerShell](https://attack.mitre.org/techniques/T1059/001). Information about processes can also be extracted from the output of [Native API](https://attack.mitre.org/techniques/T1106) calls such as <code>CreateToolhelp32Snapshot</code>. In Mac and Linux, this is accomplished with the <code>ps</code> command. Adversaries may also opt to enumerate processes via /proc.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1057

## Potential Commands

```
tasklist /v [/svc]
net start
qprocess *
ps
shell tasklist /v [/svc]
shell net start
ps
post/windows/gather/enum_services
ps >> /tmp/loot.txt
ps aux >> /tmp/loot.txt

tasklist

{'windows': {'psh,pwsh': {'command': '$ps_url = "https://download.sysinternals.com/files/PSTools.zip";\n$download_folder = "C:\\Users\\Public\\";\n$staging_folder = "C:\\Users\\Public\\temp";\nStart-BitsTransfer -Source $ps_url -Destination $download_folder;\nExpand-Archive -LiteralPath $download_folder"PSTools.zip" -DestinationPath $staging_folder;\niex $staging_folder"\\pslist.exe" >> $env:LOCALAPPDATA\\output.log;\nRemove-Item $download_folder"PSTools.zip";\nRemove-Item $staging_folder -Recurse\n'}}}
{'linux': {'sh': {'command': 'acrnctl list\n', 'parsers': {'plugins.stockpile.app.parsers.acrn': [{'source': 'hypervisor.vm.name'}]}}}}
{'windows': {'psh': {'command': '$owners = @{};\ngwmi win32_process |% {$owners[$_.handle] = $_.getowner().user};\n$ps = get-process | select processname,Id,@{l="Owner";e={$owners[$_.id.tostring()]}};\n$valid = foreach($p in $ps) { if($p.Owner -eq $env:USERNAME -And $p.ProcessName -eq "svchost") {$p} };\n$valid | ConvertTo-Json\n', 'parsers': {'plugins.stockpile.app.parsers.json': [{'source': 'host.process.id', 'custom_parser_vals': {'json_key': 'Id', 'json_type': 'int'}}]}}}}
{'windows': {'psh': {'command': '$ps = get-process | select processname,Id;\n$valid = foreach($p in $ps) { if($p.ProcessName -eq "lsass") {$p} };\n$valid | ConvertTo-Json\n', 'parsers': {'plugins.stockpile.app.parsers.json': [{'source': 'host.process.id', 'custom_parser_vals': {'json_key': 'Id', 'json_type': 'int'}}]}}, 'cmd': {'build_target': 'GetLsass.exe', 'language': 'csharp', 'code': 'using System;\nusing System.Diagnostics;\nusing System.ComponentModel;\n\nnamespace ProcessDump\n{\n    class MyProcess\n    {\n        void GrabLsassProcess()\n        {\n            Process[] allProc = Process.GetProcessesByName("lsass");\n            foreach(Process proc in allProc){\n                Console.WriteLine("Process: {0} -> PID: {1}", proc.ProcessName, proc.Id);\n            }\n        }\n        static void Main(string[] args)\n        {\n            MyProcess myProc = new MyProcess();\n            myProc.GrabLsassProcess();\n        }\n    }\n}\n'}}}
{'darwin': {'sh': {'command': 'ps\n'}}, 'linux': {'sh': {'command': 'ps\n'}}, 'windows': {'psh': {'command': 'get-process\n'}}}
{'darwin': {'sh': {'command': 'ps aux | grep #{host.user.name}\n'}}, 'linux': {'sh': {'command': 'ps aux | grep #{host.user.name}\n'}}, 'windows': {'psh': {'command': '$owners = @{};\ngwmi win32_process |% {$owners[$_.handle] = $_.getowner().user};\n$ps = get-process | select processname,Id,@{l="Owner";e={$owners[$_.id.tostring()]}};\nforeach($p in $ps) {\n    if($p.Owner -eq "#{host.user.name}") {\n        $p;\n    }\n}\n'}}}
{'windows': {'psh,pwsh': {'command': 'get-process >> $env:APPDATA\\vmtools.log;\ncat $env:APPDATA\\vmtools.log\n'}}}
{'windows': {'psh': {'command': 'Get-Process'}, 'cmd': {'command': 'tasklist'}, 'donut_amd64': {'build_target': 'ProcessDump.donut', 'language': 'csharp', 'code': 'using System;\nusing System.Diagnostics;\nusing System.ComponentModel;\n\nnamespace ProcessDump\n{\n    class MyProcess\n    {\n        void GrabAllProcesses()\n        {\n            Process[] allProc = Process.GetProcesses();\n            foreach(Process proc in allProc){\n                Console.WriteLine("Process: {0} -> PID: {1}", proc.ProcessName, proc.Id);\n            }\n        }\n        static void Main(string[] args)\n        {\n            MyProcess myProc = new MyProcess();\n            myProc.GrabAllProcesses();\n        }\n    }\n}\n'}}, 'darwin': {'sh': {'command': 'ps aux'}}, 'linux': {'sh': {'command': 'ps aux'}}}
{'windows': {'psh': {'command': 'tasklist /m  >> $env:APPDATA\\vmtool.log;\ncat $env:APPDATA\\vmtool.log\n'}}}
powershell/situational_awareness/host/paranoia
powershell/situational_awareness/host/paranoia
powershell/situational_awareness/network/powerview/process_hunter
powershell/situational_awareness/network/powerview/process_hunter
```

## Commands Dataset

```
[{'command': 'tasklist /v [/svc]\nnet start\nqprocess *',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'ps\nshell tasklist /v [/svc]\nshell net start',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'ps\npost/windows/gather/enum_services',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'ps >> /tmp/loot.txt\nps aux >> /tmp/loot.txt\n',
  'name': None,
  'source': 'atomics/T1057/T1057.yaml'},
 {'command': 'tasklist\n', 'name': None, 'source': 'atomics/T1057/T1057.yaml'},
 {'command': {'windows': {'psh,pwsh': {'command': '$ps_url = '
                                                  '"https://download.sysinternals.com/files/PSTools.zip";\n'
                                                  '$download_folder = '
                                                  '"C:\\Users\\Public\\";\n'
                                                  '$staging_folder = '
                                                  '"C:\\Users\\Public\\temp";\n'
                                                  'Start-BitsTransfer -Source '
                                                  '$ps_url -Destination '
                                                  '$download_folder;\n'
                                                  'Expand-Archive -LiteralPath '
                                                  '$download_folder"PSTools.zip" '
                                                  '-DestinationPath '
                                                  '$staging_folder;\n'
                                                  'iex '
                                                  '$staging_folder"\\pslist.exe" '
                                                  '>> '
                                                  '$env:LOCALAPPDATA\\output.log;\n'
                                                  'Remove-Item '
                                                  '$download_folder"PSTools.zip";\n'
                                                  'Remove-Item $staging_folder '
                                                  '-Recurse\n'}}},
  'name': 'Process discovery via SysInternals pstool',
  'source': 'data/abilities/collection/cc191baa-7472-4386-a2f4-42f203f1acfd.yml'},
 {'command': {'linux': {'sh': {'command': 'acrnctl list\n',
                               'parsers': {'plugins.stockpile.app.parsers.acrn': [{'source': 'hypervisor.vm.name'}]}}}},
  'name': 'Enumerate running virtual machines on hypervisor',
  'source': 'data/abilities/discovery/0093c0e0-68b6-4cab-b0d4-2b40b3c78f71.yml'},
 {'command': {'windows': {'psh': {'command': '$owners = @{};\n'
                                             'gwmi win32_process |% '
                                             '{$owners[$_.handle] = '
                                             '$_.getowner().user};\n'
                                             '$ps = get-process | select '
                                             'processname,Id,@{l="Owner";e={$owners[$_.id.tostring()]}};\n'
                                             '$valid = foreach($p in $ps) { '
                                             'if($p.Owner -eq $env:USERNAME '
                                             '-And $p.ProcessName -eq '
                                             '"svchost") {$p} };\n'
                                             '$valid | ConvertTo-Json\n',
                                  'parsers': {'plugins.stockpile.app.parsers.json': [{'custom_parser_vals': {'json_key': 'Id',
                                                                                                             'json_type': 'int'},
                                                                                      'source': 'host.process.id'}]}}}},
  'name': 'Discovers processes that the current user has the ability to access '
          'and selects an injectable one',
  'source': 'data/abilities/discovery/05cda6f6-2b1b-462e-bff1-845af94343f7.yml'},
 {'command': {'windows': {'cmd': {'build_target': 'GetLsass.exe',
                                  'code': 'using System;\n'
                                          'using System.Diagnostics;\n'
                                          'using System.ComponentModel;\n'
                                          '\n'
                                          'namespace ProcessDump\n'
                                          '{\n'
                                          '    class MyProcess\n'
                                          '    {\n'
                                          '        void GrabLsassProcess()\n'
                                          '        {\n'
                                          '            Process[] allProc = '
                                          'Process.GetProcessesByName("lsass");\n'
                                          '            foreach(Process proc in '
                                          'allProc){\n'
                                          '                '
                                          'Console.WriteLine("Process: {0} -> '
                                          'PID: {1}", proc.ProcessName, '
                                          'proc.Id);\n'
                                          '            }\n'
                                          '        }\n'
                                          '        static void Main(string[] '
                                          'args)\n'
                                          '        {\n'
                                          '            MyProcess myProc = new '
                                          'MyProcess();\n'
                                          '            '
                                          'myProc.GrabLsassProcess();\n'
                                          '        }\n'
                                          '    }\n'
                                          '}\n',
                                  'language': 'csharp'},
                          'psh': {'command': '$ps = get-process | select '
                                             'processname,Id;\n'
                                             '$valid = foreach($p in $ps) { '
                                             'if($p.ProcessName -eq "lsass") '
                                             '{$p} };\n'
                                             '$valid | ConvertTo-Json\n',
                                  'parsers': {'plugins.stockpile.app.parsers.json': [{'custom_parser_vals': {'json_key': 'Id',
                                                                                                             'json_type': 'int'},
                                                                                      'source': 'host.process.id'}]}}}},
  'name': 'Get process info for LSASS',
  'source': 'data/abilities/discovery/0bff4ee7-42a4-4bde-b09a-9d79d8b9edd7.yml'},
 {'command': {'darwin': {'sh': {'command': 'ps\n'}},
              'linux': {'sh': {'command': 'ps\n'}},
              'windows': {'psh': {'command': 'get-process\n'}}},
  'name': 'Display information about current system processes',
  'source': 'data/abilities/discovery/335cea7b-bec0-48c6-adfb-6066070f5f68.yml'},
 {'command': {'darwin': {'sh': {'command': 'ps aux | grep '
                                           '#{host.user.name}\n'}},
              'linux': {'sh': {'command': 'ps aux | grep #{host.user.name}\n'}},
              'windows': {'psh': {'command': '$owners = @{};\n'
                                             'gwmi win32_process |% '
                                             '{$owners[$_.handle] = '
                                             '$_.getowner().user};\n'
                                             '$ps = get-process | select '
                                             'processname,Id,@{l="Owner";e={$owners[$_.id.tostring()]}};\n'
                                             'foreach($p in $ps) {\n'
                                             '    if($p.Owner -eq '
                                             '"#{host.user.name}") {\n'
                                             '        $p;\n'
                                             '    }\n'
                                             '}\n'}}},
  'name': 'Get process info for processes running as a user',
  'source': 'data/abilities/discovery/3b5db901-2cb8-4df7-8043-c4628a6a5d5a.yml'},
 {'command': {'windows': {'psh,pwsh': {'command': 'get-process >> '
                                                  '$env:APPDATA\\vmtools.log;\n'
                                                  'cat '
                                                  '$env:APPDATA\\vmtools.log\n'}}},
  'name': 'Capture running processes via PowerShell',
  'source': 'data/abilities/discovery/4d9b079c-9ede-4116-8b14-72ad3a5533af.yml'},
 {'command': {'darwin': {'sh': {'command': 'ps aux'}},
              'linux': {'sh': {'command': 'ps aux'}},
              'windows': {'cmd': {'command': 'tasklist'},
                          'donut_amd64': {'build_target': 'ProcessDump.donut',
                                          'code': 'using System;\n'
                                                  'using System.Diagnostics;\n'
                                                  'using '
                                                  'System.ComponentModel;\n'
                                                  '\n'
                                                  'namespace ProcessDump\n'
                                                  '{\n'
                                                  '    class MyProcess\n'
                                                  '    {\n'
                                                  '        void '
                                                  'GrabAllProcesses()\n'
                                                  '        {\n'
                                                  '            Process[] '
                                                  'allProc = '
                                                  'Process.GetProcesses();\n'
                                                  '            foreach(Process '
                                                  'proc in allProc){\n'
                                                  '                '
                                                  'Console.WriteLine("Process: '
                                                  '{0} -> PID: {1}", '
                                                  'proc.ProcessName, '
                                                  'proc.Id);\n'
                                                  '            }\n'
                                                  '        }\n'
                                                  '        static void '
                                                  'Main(string[] args)\n'
                                                  '        {\n'
                                                  '            MyProcess '
                                                  'myProc = new MyProcess();\n'
                                                  '            '
                                                  'myProc.GrabAllProcesses();\n'
                                                  '        }\n'
                                                  '    }\n'
                                                  '}\n',
                                          'language': 'csharp'},
                          'psh': {'command': 'Get-Process'}}},
  'name': 'Identify system processes',
  'source': 'data/abilities/discovery/5a39d7ed-45c9-4a79-b581-e5fb99e24f65.yml'},
 {'command': {'windows': {'psh': {'command': 'tasklist /m  >> '
                                             '$env:APPDATA\\vmtool.log;\n'
                                             'cat '
                                             '$env:APPDATA\\vmtool.log\n'}}},
  'name': 'Capture running processes and their loaded DLLs',
  'source': 'data/abilities/discovery/8adf02e8-6e71-4244-886c-98c402857404.yml'},
 {'command': 'powershell/situational_awareness/host/paranoia',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/host/paranoia',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/process_hunter',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/process_hunter',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']}]
```

## Potential Queries

```json
[{'name': 'Process Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and process_path contains '
           '"tasklist.exe"or process_command_line contains "Get-Process"'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'tasklist '
                                                                              '/v '
                                                                              '[/svc]\n'
                                                                              'net '
                                                                              'start\n'
                                                                              'qprocess '
                                                                              '*',
                                                  'Category': 'T1057',
                                                  'Cobalt Strike': 'ps\n'
                                                                   'shell '
                                                                   'tasklist '
                                                                   '/v [/svc]\n'
                                                                   'shell net '
                                                                   'start',
                                                  'Description': 'Display list '
                                                                 'of currently '
                                                                 'running '
                                                                 'processes '
                                                                 'and services '
                                                                 'on the '
                                                                 'system',
                                                  'Metasploit': 'ps\n'
                                                                'post/windows/gather/enum_services'}},
 {'Atomic Red Team Test - Process Discovery': {'atomic_tests': [{'auto_generated_guid': '4ff64f0b-aaf2-4866-b39d-38d9791407cc',
                                                                 'description': 'Utilize '
                                                                                'ps '
                                                                                'to '
                                                                                'identify '
                                                                                'processes.\n'
                                                                                '\n'
                                                                                'Upon '
                                                                                'successful '
                                                                                'execution, '
                                                                                'sh '
                                                                                'will '
                                                                                'execute '
                                                                                'ps '
                                                                                'and '
                                                                                'output '
                                                                                'to '
                                                                                '/tmp/loot.txt.\n',
                                                                 'executor': {'cleanup_command': 'rm '
                                                                                                 '#{output_file}\n',
                                                                              'command': 'ps '
                                                                                         '>> '
                                                                                         '#{output_file}\n'
                                                                                         'ps '
                                                                                         'aux '
                                                                                         '>> '
                                                                                         '#{output_file}\n',
                                                                              'name': 'sh'},
                                                                 'input_arguments': {'output_file': {'default': '/tmp/loot.txt',
                                                                                                     'description': 'path '
                                                                                                                    'of '
                                                                                                                    'output '
                                                                                                                    'file',
                                                                                                     'type': 'path'}},
                                                                 'name': 'Process '
                                                                         'Discovery '
                                                                         '- ps',
                                                                 'supported_platforms': ['macos',
                                                                                         'linux']},
                                                                {'auto_generated_guid': 'c5806a4f-62b8-4900-980b-c7ec004e9908',
                                                                 'description': 'Utilize '
                                                                                'tasklist '
                                                                                'to '
                                                                                'identify '
                                                                                'processes.\n'
                                                                                '\n'
                                                                                'Upon '
                                                                                'successful '
                                                                                'execution, '
                                                                                'cmd.exe '
                                                                                'will '
                                                                                'execute '
                                                                                'tasklist.exe '
                                                                                'to '
                                                                                'list '
                                                                                'processes. '
                                                                                'Output '
                                                                                'will '
                                                                                'be '
                                                                                'via '
                                                                                'stdout. \n',
                                                                 'executor': {'command': 'tasklist\n',
                                                                              'name': 'command_prompt'},
                                                                 'name': 'Process '
                                                                         'Discovery '
                                                                         '- '
                                                                         'tasklist',
                                                                 'supported_platforms': ['windows']}],
                                               'attack_technique': 'T1057',
                                               'display_name': 'Process '
                                                               'Discovery'}},
 {'Mitre Stockpile - Process discovery via SysInternals pstool': {'description': 'Process '
                                                                                 'discovery '
                                                                                 'via '
                                                                                 'SysInternals '
                                                                                 'pstool',
                                                                  'id': 'cc191baa-7472-4386-a2f4-42f203f1acfd',
                                                                  'name': 'SysInternals '
                                                                          'PSTool '
                                                                          'Process '
                                                                          'Discovery',
                                                                  'platforms': {'windows': {'psh,pwsh': {'command': '$ps_url '
                                                                                                                    '= '
                                                                                                                    '"https://download.sysinternals.com/files/PSTools.zip";\n'
                                                                                                                    '$download_folder '
                                                                                                                    '= '
                                                                                                                    '"C:\\Users\\Public\\";\n'
                                                                                                                    '$staging_folder '
                                                                                                                    '= '
                                                                                                                    '"C:\\Users\\Public\\temp";\n'
                                                                                                                    'Start-BitsTransfer '
                                                                                                                    '-Source '
                                                                                                                    '$ps_url '
                                                                                                                    '-Destination '
                                                                                                                    '$download_folder;\n'
                                                                                                                    'Expand-Archive '
                                                                                                                    '-LiteralPath '
                                                                                                                    '$download_folder"PSTools.zip" '
                                                                                                                    '-DestinationPath '
                                                                                                                    '$staging_folder;\n'
                                                                                                                    'iex '
                                                                                                                    '$staging_folder"\\pslist.exe" '
                                                                                                                    '>> '
                                                                                                                    '$env:LOCALAPPDATA\\output.log;\n'
                                                                                                                    'Remove-Item '
                                                                                                                    '$download_folder"PSTools.zip";\n'
                                                                                                                    'Remove-Item '
                                                                                                                    '$staging_folder '
                                                                                                                    '-Recurse\n'}}},
                                                                  'tactic': 'collection',
                                                                  'technique': {'attack_id': 'T1057',
                                                                                'name': 'Process '
                                                                                        'Discovery'}}},
 {'Mitre Stockpile - Enumerate running virtual machines on hypervisor': {'description': 'Enumerate '
                                                                                        'running '
                                                                                        'virtual '
                                                                                        'machines '
                                                                                        'on '
                                                                                        'hypervisor',
                                                                         'id': '0093c0e0-68b6-4cab-b0d4-2b40b3c78f71',
                                                                         'name': 'enumerate '
                                                                                 'VMs',
                                                                         'platforms': {'linux': {'sh': {'command': 'acrnctl '
                                                                                                                   'list\n',
                                                                                                        'parsers': {'plugins.stockpile.app.parsers.acrn': [{'source': 'hypervisor.vm.name'}]}}}},
                                                                         'tactic': 'discovery',
                                                                         'technique': {'attack_id': 'T1057',
                                                                                       'name': 'Process '
                                                                                               'Discovery'}}},
 {'Mitre Stockpile - Discovers processes that the current user has the ability to access and selects an injectable one': {'description': 'Discovers '
                                                                                                                                         'processes '
                                                                                                                                         'that '
                                                                                                                                         'the '
                                                                                                                                         'current '
                                                                                                                                         'user '
                                                                                                                                         'has '
                                                                                                                                         'the '
                                                                                                                                         'ability '
                                                                                                                                         'to '
                                                                                                                                         'access '
                                                                                                                                         'and '
                                                                                                                                         'selects '
                                                                                                                                         'an '
                                                                                                                                         'injectable '
                                                                                                                                         'one',
                                                                                                                          'id': '05cda6f6-2b1b-462e-bff1-845af94343f7',
                                                                                                                          'name': 'Discover '
                                                                                                                                  'injectable '
                                                                                                                                  'process',
                                                                                                                          'platforms': {'windows': {'psh': {'command': '$owners '
                                                                                                                                                                       '= '
                                                                                                                                                                       '@{};\n'
                                                                                                                                                                       'gwmi '
                                                                                                                                                                       'win32_process '
                                                                                                                                                                       '|% '
                                                                                                                                                                       '{$owners[$_.handle] '
                                                                                                                                                                       '= '
                                                                                                                                                                       '$_.getowner().user};\n'
                                                                                                                                                                       '$ps '
                                                                                                                                                                       '= '
                                                                                                                                                                       'get-process '
                                                                                                                                                                       '| '
                                                                                                                                                                       'select '
                                                                                                                                                                       'processname,Id,@{l="Owner";e={$owners[$_.id.tostring()]}};\n'
                                                                                                                                                                       '$valid '
                                                                                                                                                                       '= '
                                                                                                                                                                       'foreach($p '
                                                                                                                                                                       'in '
                                                                                                                                                                       '$ps) '
                                                                                                                                                                       '{ '
                                                                                                                                                                       'if($p.Owner '
                                                                                                                                                                       '-eq '
                                                                                                                                                                       '$env:USERNAME '
                                                                                                                                                                       '-And '
                                                                                                                                                                       '$p.ProcessName '
                                                                                                                                                                       '-eq '
                                                                                                                                                                       '"svchost") '
                                                                                                                                                                       '{$p} '
                                                                                                                                                                       '};\n'
                                                                                                                                                                       '$valid '
                                                                                                                                                                       '| '
                                                                                                                                                                       'ConvertTo-Json\n',
                                                                                                                                                            'parsers': {'plugins.stockpile.app.parsers.json': [{'custom_parser_vals': {'json_key': 'Id',
                                                                                                                                                                                                                                       'json_type': 'int'},
                                                                                                                                                                                                                'source': 'host.process.id'}]}}}},
                                                                                                                          'tactic': 'discovery',
                                                                                                                          'technique': {'attack_id': 'T1057',
                                                                                                                                        'name': 'Process '
                                                                                                                                                'Discovery'}}},
 {'Mitre Stockpile - Get process info for LSASS': {'description': 'Get process '
                                                                  'info for '
                                                                  'LSASS',
                                                   'id': '0bff4ee7-42a4-4bde-b09a-9d79d8b9edd7',
                                                   'name': 'Find LSASS',
                                                   'platforms': {'windows': {'cmd': {'build_target': 'GetLsass.exe',
                                                                                     'code': 'using '
                                                                                             'System;\n'
                                                                                             'using '
                                                                                             'System.Diagnostics;\n'
                                                                                             'using '
                                                                                             'System.ComponentModel;\n'
                                                                                             '\n'
                                                                                             'namespace '
                                                                                             'ProcessDump\n'
                                                                                             '{\n'
                                                                                             '    '
                                                                                             'class '
                                                                                             'MyProcess\n'
                                                                                             '    '
                                                                                             '{\n'
                                                                                             '        '
                                                                                             'void '
                                                                                             'GrabLsassProcess()\n'
                                                                                             '        '
                                                                                             '{\n'
                                                                                             '            '
                                                                                             'Process[] '
                                                                                             'allProc '
                                                                                             '= '
                                                                                             'Process.GetProcessesByName("lsass");\n'
                                                                                             '            '
                                                                                             'foreach(Process '
                                                                                             'proc '
                                                                                             'in '
                                                                                             'allProc){\n'
                                                                                             '                '
                                                                                             'Console.WriteLine("Process: '
                                                                                             '{0} '
                                                                                             '-> '
                                                                                             'PID: '
                                                                                             '{1}", '
                                                                                             'proc.ProcessName, '
                                                                                             'proc.Id);\n'
                                                                                             '            '
                                                                                             '}\n'
                                                                                             '        '
                                                                                             '}\n'
                                                                                             '        '
                                                                                             'static '
                                                                                             'void '
                                                                                             'Main(string[] '
                                                                                             'args)\n'
                                                                                             '        '
                                                                                             '{\n'
                                                                                             '            '
                                                                                             'MyProcess '
                                                                                             'myProc '
                                                                                             '= '
                                                                                             'new '
                                                                                             'MyProcess();\n'
                                                                                             '            '
                                                                                             'myProc.GrabLsassProcess();\n'
                                                                                             '        '
                                                                                             '}\n'
                                                                                             '    '
                                                                                             '}\n'
                                                                                             '}\n',
                                                                                     'language': 'csharp'},
                                                                             'psh': {'command': '$ps '
                                                                                                '= '
                                                                                                'get-process '
                                                                                                '| '
                                                                                                'select '
                                                                                                'processname,Id;\n'
                                                                                                '$valid '
                                                                                                '= '
                                                                                                'foreach($p '
                                                                                                'in '
                                                                                                '$ps) '
                                                                                                '{ '
                                                                                                'if($p.ProcessName '
                                                                                                '-eq '
                                                                                                '"lsass") '
                                                                                                '{$p} '
                                                                                                '};\n'
                                                                                                '$valid '
                                                                                                '| '
                                                                                                'ConvertTo-Json\n',
                                                                                     'parsers': {'plugins.stockpile.app.parsers.json': [{'custom_parser_vals': {'json_key': 'Id',
                                                                                                                                                                'json_type': 'int'},
                                                                                                                                         'source': 'host.process.id'}]}}}},
                                                   'tactic': 'discovery',
                                                   'technique': {'attack_id': 'T1057',
                                                                 'name': 'Process '
                                                                         'Discovery'}}},
 {'Mitre Stockpile - Display information about current system processes': {'description': 'Display '
                                                                                          'information '
                                                                                          'about '
                                                                                          'current '
                                                                                          'system '
                                                                                          'processes',
                                                                           'id': '335cea7b-bec0-48c6-adfb-6066070f5f68',
                                                                           'name': 'View '
                                                                                   'Processes',
                                                                           'platforms': {'darwin': {'sh': {'command': 'ps\n'}},
                                                                                         'linux': {'sh': {'command': 'ps\n'}},
                                                                                         'windows': {'psh': {'command': 'get-process\n'}}},
                                                                           'tactic': 'discovery',
                                                                           'technique': {'attack_id': 'T1057',
                                                                                         'name': 'Process '
                                                                                                 'Discovery'}}},
 {'Mitre Stockpile - Get process info for processes running as a user': {'description': 'Get '
                                                                                        'process '
                                                                                        'info '
                                                                                        'for '
                                                                                        'processes '
                                                                                        'running '
                                                                                        'as '
                                                                                        'a '
                                                                                        'user',
                                                                         'id': '3b5db901-2cb8-4df7-8043-c4628a6a5d5a',
                                                                         'name': 'Find '
                                                                                 'user '
                                                                                 'processes',
                                                                         'platforms': {'darwin': {'sh': {'command': 'ps '
                                                                                                                    'aux '
                                                                                                                    '| '
                                                                                                                    'grep '
                                                                                                                    '#{host.user.name}\n'}},
                                                                                       'linux': {'sh': {'command': 'ps '
                                                                                                                   'aux '
                                                                                                                   '| '
                                                                                                                   'grep '
                                                                                                                   '#{host.user.name}\n'}},
                                                                                       'windows': {'psh': {'command': '$owners '
                                                                                                                      '= '
                                                                                                                      '@{};\n'
                                                                                                                      'gwmi '
                                                                                                                      'win32_process '
                                                                                                                      '|% '
                                                                                                                      '{$owners[$_.handle] '
                                                                                                                      '= '
                                                                                                                      '$_.getowner().user};\n'
                                                                                                                      '$ps '
                                                                                                                      '= '
                                                                                                                      'get-process '
                                                                                                                      '| '
                                                                                                                      'select '
                                                                                                                      'processname,Id,@{l="Owner";e={$owners[$_.id.tostring()]}};\n'
                                                                                                                      'foreach($p '
                                                                                                                      'in '
                                                                                                                      '$ps) '
                                                                                                                      '{\n'
                                                                                                                      '    '
                                                                                                                      'if($p.Owner '
                                                                                                                      '-eq '
                                                                                                                      '"#{host.user.name}") '
                                                                                                                      '{\n'
                                                                                                                      '        '
                                                                                                                      '$p;\n'
                                                                                                                      '    '
                                                                                                                      '}\n'
                                                                                                                      '}\n'}}},
                                                                         'requirements': [{'plugins.stockpile.app.requirements.paw_provenance': [{'source': 'host.user.name'}]}],
                                                                         'tactic': 'discovery',
                                                                         'technique': {'attack_id': 'T1057',
                                                                                       'name': 'Process '
                                                                                               'Discovery'}}},
 {'Mitre Stockpile - Capture running processes via PowerShell': {'description': 'Capture '
                                                                                'running '
                                                                                'processes '
                                                                                'via '
                                                                                'PowerShell',
                                                                 'id': '4d9b079c-9ede-4116-8b14-72ad3a5533af',
                                                                 'name': 'PowerShell '
                                                                         'Process '
                                                                         'Enumeration',
                                                                 'platforms': {'windows': {'psh,pwsh': {'command': 'get-process '
                                                                                                                   '>> '
                                                                                                                   '$env:APPDATA\\vmtools.log;\n'
                                                                                                                   'cat '
                                                                                                                   '$env:APPDATA\\vmtools.log\n'}}},
                                                                 'tactic': 'discovery',
                                                                 'technique': {'attack_id': 'T1057',
                                                                               'name': 'Process '
                                                                                       'Discovery'}}},
 {'Mitre Stockpile - Identify system processes': {'description': 'Identify '
                                                                 'system '
                                                                 'processes',
                                                  'id': '5a39d7ed-45c9-4a79-b581-e5fb99e24f65',
                                                  'name': 'System processes',
                                                  'platforms': {'darwin': {'sh': {'command': 'ps '
                                                                                             'aux'}},
                                                                'linux': {'sh': {'command': 'ps '
                                                                                            'aux'}},
                                                                'windows': {'cmd': {'command': 'tasklist'},
                                                                            'donut_amd64': {'build_target': 'ProcessDump.donut',
                                                                                            'code': 'using '
                                                                                                    'System;\n'
                                                                                                    'using '
                                                                                                    'System.Diagnostics;\n'
                                                                                                    'using '
                                                                                                    'System.ComponentModel;\n'
                                                                                                    '\n'
                                                                                                    'namespace '
                                                                                                    'ProcessDump\n'
                                                                                                    '{\n'
                                                                                                    '    '
                                                                                                    'class '
                                                                                                    'MyProcess\n'
                                                                                                    '    '
                                                                                                    '{\n'
                                                                                                    '        '
                                                                                                    'void '
                                                                                                    'GrabAllProcesses()\n'
                                                                                                    '        '
                                                                                                    '{\n'
                                                                                                    '            '
                                                                                                    'Process[] '
                                                                                                    'allProc '
                                                                                                    '= '
                                                                                                    'Process.GetProcesses();\n'
                                                                                                    '            '
                                                                                                    'foreach(Process '
                                                                                                    'proc '
                                                                                                    'in '
                                                                                                    'allProc){\n'
                                                                                                    '                '
                                                                                                    'Console.WriteLine("Process: '
                                                                                                    '{0} '
                                                                                                    '-> '
                                                                                                    'PID: '
                                                                                                    '{1}", '
                                                                                                    'proc.ProcessName, '
                                                                                                    'proc.Id);\n'
                                                                                                    '            '
                                                                                                    '}\n'
                                                                                                    '        '
                                                                                                    '}\n'
                                                                                                    '        '
                                                                                                    'static '
                                                                                                    'void '
                                                                                                    'Main(string[] '
                                                                                                    'args)\n'
                                                                                                    '        '
                                                                                                    '{\n'
                                                                                                    '            '
                                                                                                    'MyProcess '
                                                                                                    'myProc '
                                                                                                    '= '
                                                                                                    'new '
                                                                                                    'MyProcess();\n'
                                                                                                    '            '
                                                                                                    'myProc.GrabAllProcesses();\n'
                                                                                                    '        '
                                                                                                    '}\n'
                                                                                                    '    '
                                                                                                    '}\n'
                                                                                                    '}\n',
                                                                                            'language': 'csharp'},
                                                                            'psh': {'command': 'Get-Process'}}},
                                                  'tactic': 'discovery',
                                                  'technique': {'attack_id': 'T1057',
                                                                'name': 'Process '
                                                                        'Discovery'}}},
 {'Mitre Stockpile - Capture running processes and their loaded DLLs': {'description': 'Capture '
                                                                                       'running '
                                                                                       'processes '
                                                                                       'and '
                                                                                       'their '
                                                                                       'loaded '
                                                                                       'DLLs',
                                                                        'id': '8adf02e8-6e71-4244-886c-98c402857404',
                                                                        'name': 'tasklist '
                                                                                'Process '
                                                                                'Enumeration',
                                                                        'platforms': {'windows': {'psh': {'command': 'tasklist '
                                                                                                                     '/m  '
                                                                                                                     '>> '
                                                                                                                     '$env:APPDATA\\vmtool.log;\n'
                                                                                                                     'cat '
                                                                                                                     '$env:APPDATA\\vmtool.log\n'}}},
                                                                        'tactic': 'discovery',
                                                                        'technique': {'attack_id': 'T1057',
                                                                                      'name': 'Process '
                                                                                              'Discovery'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1057',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/host/paranoia":  '
                                                                                 '["T1057"],',
                                            'Empire Module': 'powershell/situational_awareness/host/paranoia',
                                            'Technique': 'Process Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1057',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/process_hunter":  '
                                                                                 '["T1057"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/process_hunter',
                                            'Technique': 'Process Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [Process Discovery Mitigation](../mitigations/Process-Discovery-Mitigation.md)


# Actors


* [OilRig](../actors/OilRig.md)

* [APT37](../actors/APT37.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [APT1](../actors/APT1.md)
    
* [APT38](../actors/APT38.md)
    
* [Winnti Group](../actors/Winnti-Group.md)
    
* [APT3](../actors/APT3.md)
    
* [Poseidon Group](../actors/Poseidon-Group.md)
    
* [Molerats](../actors/Molerats.md)
    
* [Deep Panda](../actors/Deep-Panda.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Turla](../actors/Turla.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [APT28](../actors/APT28.md)
    
* [Inception](../actors/Inception.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
* [Rocke](../actors/Rocke.md)
    
