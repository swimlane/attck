
# Indirect Command Execution

## Description

### MITRE Description

> Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters. Various Windows utilities may be used to execute commands, possibly without invoking [cmd](https://attack.mitre.org/software/S0106). For example, [Forfiles](https://attack.mitre.org/software/S0193), the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), Run window, or via scripts. (Citation: VectorSec ForFiles Aug 2017) (Citation: Evi1cg Forfiles Nov 2017)

Adversaries may abuse these features for [Defense Evasion](https://attack.mitre.org/tactics/TA0005), specifically to perform arbitrary execution while subverting detections and/or mitigation controls (such as Group Policy) that limit/prevent the usage of [cmd](https://attack.mitre.org/software/S0106) or file extensions more commonly associated with malicious payloads.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Static File Analysis', 'Application control', 'Application control by file name or path']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1202

## Potential Commands

```
pcalua.exe -a #{process}
pcalua.exe -a C:\Windows\System32\calc.exe

pcalua.exe -a calc.exe
pcalua.exe -a #{payload_path}

forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe
forfiles /p c:\windows\system32 /m notepad.exe /c "c:\folder\normal.dll:evil.exe"

pcalua.exe
```

## Commands Dataset

```
[{'command': 'pcalua.exe -a #{process}\n'
             'pcalua.exe -a C:\\Windows\\System32\\calc.exe\n',
  'name': None,
  'source': 'atomics/T1202/T1202.yaml'},
 {'command': 'pcalua.exe -a calc.exe\npcalua.exe -a #{payload_path}\n',
  'name': None,
  'source': 'atomics/T1202/T1202.yaml'},
 {'command': 'forfiles /p c:\\windows\\system32 /m notepad.exe /c calc.exe\n'
             'forfiles /p c:\\windows\\system32 /m notepad.exe /c '
             '"c:\\folder\\normal.dll:evil.exe"\n',
  'name': None,
  'source': 'atomics/T1202/T1202.yaml'},
 {'command': 'pcalua.exe',
  'name': None,
  'source': 'SysmonHunter - Indirect Command Execution'}]
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
                  'title': 'Suspicious Execution from Outlook'}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Windows event logs']},
 {'data_source': ['ID 1 & 7', 'Sysmon']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Windows event logs']}]
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
[{'Atomic Red Team Test - Indirect Command Execution': {'atomic_tests': [{'auto_generated_guid': 'cecfea7a-5f03-4cdd-8bc8-6f7c22862440',
                                                                          'description': 'The '
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
                                                                         {'auto_generated_guid': '8b34a448-40d9-4fc3-a8c8-4bb286faf7dc',
                                                                          'description': 'forfiles.exe '
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


* [Indirect Command Execution Mitigation](../mitigations/Indirect-Command-Execution-Mitigation.md)


# Actors

None
