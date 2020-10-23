
# Component Object Model

## Description

### MITRE Description

> Adversaries may use the Windows Component Object Model (COM) for local code execution. COM is an inter-process communication (IPC) component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces.(Citation: Fireeye Hunting COM June 2019) Through COM, a client object can call methods of server objects, which are typically binary Dynamic Link Libraries (DLL) or executables (EXE).(Citation: Microsoft COM)

Various COM interfaces are exposed that can be abused to invoke arbitrary execution via a variety of programming languages such as C, C++, Java, and [Visual Basic](https://attack.mitre.org/techniques/T1059/005).(Citation: Microsoft COM) Specific COM objects also exist to directly perform functions beyond code execution, such as creating a [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053), fileless download/execution, and other adversary behaviors related to privilege escalation and persistence.(Citation: Fireeye Hunting COM June 2019)(Citation: ProjectZero File Write EoP Apr 2018)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1559/001

## Potential Commands

```
powershell/lateral_movement/invoke_dcom
```

## Commands Dataset

```
[{'command': 'powershell/lateral_movement/invoke_dcom',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/lateral_movement/invoke_dcom',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Ecco',
                  'date': '2019/09/03',
                  'description': 'Detects wmiexec/dcomexec/atexec/smbexec from '
                                 'Impacket framework',
                  'detection': {'condition': '(1 of selection_*)',
                                'selection_atexec': {'CommandLine': ['cmd.exe '
                                                                     '/C '
                                                                     '*Windows\\\\Temp\\\\*&1'],
                                                     'ParentCommandLine': ['*svchost.exe '
                                                                           '-k '
                                                                           'netsvcs',
                                                                           'taskeng.exe*']},
                                'selection_other': {'CommandLine': ['*cmd.exe* '
                                                                    '/Q /c * '
                                                                    '\\\\\\\\127.0.0.1\\\\*&1*'],
                                                    'ParentImage': ['*\\wmiprvse.exe',
                                                                    '*\\mmc.exe',
                                                                    '*\\explorer.exe',
                                                                    '*\\services.exe']}},
                  'falsepositives': ['pentesters'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '10c14723-61c7-4c75-92ca-9af245723ad2',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py',
                                 'https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py',
                                 'https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py',
                                 'https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py'],
                  'status': 'experimental',
                  'tags': ['attack.lateral_movement',
                           'attack.t1047',
                           'attack.t1175'],
                  'title': 'Impacket Lateralization Detection'}},
 {'data_source': {'author': 'Karneades, Swisscom CSIRT',
                  'description': 'Detects a Windows command line executable '
                                 'started from MMC.',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': ['*\\cmd.exe',
                                                        '*\\powershell.exe',
                                                        '*\\wscript.exe',
                                                        '*\\cscript.exe',
                                                        '*\\sh.exe',
                                                        '*\\bash.exe',
                                                        '*\\reg.exe',
                                                        '*\\regsvr32.exe',
                                                        '*\\BITSADMIN*'],
                                              'ParentImage': '*\\mmc.exe'}},
                  'fields': ['CommandLine', 'Image', 'ParentCommandLine'],
                  'id': '05a2ab7e-ce11-4b63-86db-ab32e763e11d',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'status': 'experimental',
                  'tags': ['attack.lateral_movement', 'attack.t1175'],
                  'title': 'MMC Spawning Windows Shell'}},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['Authentication logs']},
 {'data_source': ['Windows event logs']},
 {'data_source': ['DLL monitoring']},
 {'data_source': ['API monitoring']},
 {'data_source': ['Packet capture']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['Sysmon ID 7', 'DLL monitoring']},
 {'data_source': ['Windows event logs']},
 {'data_source': ['API monitoring']},
 {'data_source': ['Packet capture']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1175',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/lateral_movement/invoke_dcom":  '
                                                                                 '["T1175"],',
                                            'Empire Module': 'powershell/lateral_movement/invoke_dcom',
                                            'Technique': 'Distributed '
                                                         'Component Object '
                                                         'Model'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [Application Isolation and Sandboxing](../mitigations/Application-Isolation-and-Sandboxing.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    

# Actors


* [MuddyWater](../actors/MuddyWater.md)

* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
