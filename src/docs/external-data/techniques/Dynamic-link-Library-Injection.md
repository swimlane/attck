
# Dynamic-link Library Injection

## Description

### MITRE Description

> Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process.  

DLL injection is commonly performed by writing the path to a DLL in the virtual address space of the target process before loading the DLL by invoking a new thread. The write can be performed with native Windows API calls such as <code>VirtualAllocEx</code> and <code>WriteProcessMemory</code>, then invoked with <code>CreateRemoteThread</code> (which calls the <code>LoadLibrary</code> API responsible for loading the DLL). (Citation: Endgame Process Injection July 2017) 

Variations of this method such as reflective DLL injection (writing a self-mapping DLL into a process) and memory module (map DLL when writing into process) overcome the address relocation issue as well as the additional APIs to invoke execution (since these methods load and execute the files in memory by manually preforming the function of <code>LoadLibrary</code>).(Citation: Endgame HuntingNMemory June 2017)(Citation: Endgame Process Injection July 2017) 

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via DLL injection may also evade detection from security products since the execution is masked under a legitimate process. 

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application control', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1055/001

## Potential Commands

```
odbcconf.exe /S /A {REGSVR "C:\Users\Public\sandcat.dll"}
```

## Commands Dataset

```
[{'command': 'odbcconf.exe /S /A {REGSVR "C:\\Users\\Public\\sandcat.dll"}\n',
  'name': 'Leverage odbcconf for DLL injection',
  'source': 'data/abilities/defense-evasion/a74bc239-a196-4f7e-8d5c-fe8c0266071c.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - Leverage odbcconf for DLL injection': {'description': 'Leverage '
                                                                           'odbcconf '
                                                                           'for '
                                                                           'DLL '
                                                                           'injection',
                                                            'id': 'a74bc239-a196-4f7e-8d5c-fe8c0266071c',
                                                            'name': 'Signed '
                                                                    'Binary '
                                                                    'Execution '
                                                                    '- '
                                                                    'odbcconf',
                                                            'platforms': {'windows': {'psh': {'command': 'odbcconf.exe '
                                                                                                         '/S '
                                                                                                         '/A '
                                                                                                         '{REGSVR '
                                                                                                         '"C:\\Users\\Public\\sandcat.dll"}\n'}}},
                                                            'tactic': 'defense-evasion',
                                                            'technique': {'attack_id': 'T1055.001',
                                                                          'name': 'Process '
                                                                                  'Injection: '
                                                                                  'Dynamic-link '
                                                                                  'Library '
                                                                                  'Injection'}}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Behavior Prevention on Endpoint](../mitigations/Behavior-Prevention-on-Endpoint.md)


# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Putter Panda](../actors/Putter-Panda.md)
    
* [Turla](../actors/Turla.md)
    
* [TA505](../actors/TA505.md)
    
