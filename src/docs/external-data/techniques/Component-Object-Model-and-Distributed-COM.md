
# Component Object Model and Distributed COM

## Description

### MITRE Description

> Adversaries may use the Windows Component Object Model (COM) and Distributed Component Object Model (DCOM) for local code execution or to execute on remote systems as part of lateral movement. 

COM is a component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces.(Citation: Fireeye Hunting COM June 2019) Through COM, a client object can call methods of server objects, which are typically Dynamic Link Libraries (DLL) or executables (EXE).(Citation: Microsoft COM) DCOM is transparent middleware that extends the functionality of Component Object Model (COM) (Citation: Microsoft COM) beyond a local computer using remote procedure call (RPC) technology.(Citation: Fireeye Hunting COM June 2019)

Permissions to interact with local and remote server COM objects are specified by access control lists (ACL) in the Registry. (Citation: Microsoft COM ACL)(Citation: Microsoft Process Wide Com Keys)(Citation: Microsoft System Wide Com Keys) By default, only Administrators may remotely activate and launch COM objects through DCOM.

Adversaries may abuse COM for local command and/or payload execution. Various COM interfaces are exposed that can be abused to invoke arbitrary execution via a variety of programming languages such as C, C++, Java, and VBScript.(Citation: Microsoft COM) Specific COM objects also exists to directly perform functions beyond code execution, such as creating a [Scheduled Task](https://attack.mitre.org/techniques/T1053), fileless download/execution, and other adversary behaviors such as Privilege Escalation and Persistence.(Citation: Fireeye Hunting COM June 2019)(Citation: ProjectZero File Write EoP Apr 2018)

Adversaries may use DCOM for lateral movement. Through DCOM, adversaries operating in the context of an appropriately privileged user can remotely obtain arbitrary and even direct shellcode execution through Office applications (Citation: Enigma Outlook DCOM Lateral Movement Nov 2017) as well as other Windows objects that contain insecure methods.(Citation: Enigma MMC20 COM Jan 2017)(Citation: Enigma DCOM Lateral Movement Jan 2017) DCOM can also execute macros in existing documents (Citation: Enigma Excel DCOM Sept 2017) and may also invoke [Dynamic Data Exchange](https://attack.mitre.org/techniques/T1173) (DDE) execution directly through a COM created instance of a Microsoft Office application (Citation: Cyberreason DCOM DDE Lateral Movement Nov 2017), bypassing the need for a malicious document.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM', 'User']
* Platforms: ['Windows']
* Remote: True
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1175

## Potential Commands

```
powershell/lateral_movement/invoke_dcom
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
                  'title': 'MMC Spawning Windows Shell'}}]
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

* [Lateral Movement](../tactics/Lateral-Movement.md)
    

# Mitigations

None

# Actors


* [MuddyWater](../actors/MuddyWater.md)

