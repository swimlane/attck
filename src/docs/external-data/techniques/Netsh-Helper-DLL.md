
# Netsh Helper DLL

## Description

### MITRE Description

> Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility. (Citation: TechNet Netsh) The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at <code>HKLM\SOFTWARE\Microsoft\Netsh</code>.

Adversaries can use netsh.exe helper DLLs to trigger execution of arbitrary code in a persistent manner. This execution would take place anytime netsh.exe is executed, which could happen automatically, with another persistence technique, or if other software (ex: VPN) is present on the system that executes netsh.exe as part of its normal functionality. (Citation: Github Netsh Helper CS Beacon)(Citation: Demaske Netsh Persistence)

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
* Wiki: https://attack.mitre.org/techniques/T1546/007

## Potential Commands

```
netsh.exe add helper C:\Path\file.dll
```

## Commands Dataset

```
[{'command': 'netsh.exe add helper C:\\Path\\file.dll\n',
  'name': None,
  'source': 'atomics/T1546.007/T1546.007.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Event Triggered Execution: Netsh Helper DLL': {'atomic_tests': [{'auto_generated_guid': '3244697d-5a3a-4dfc-941c-550f69f91a4d',
                                                                                           'description': 'Netsh '
                                                                                                          'interacts '
                                                                                                          'with '
                                                                                                          'other '
                                                                                                          'operating '
                                                                                                          'system '
                                                                                                          'components '
                                                                                                          'using '
                                                                                                          'dynamic-link '
                                                                                                          'library '
                                                                                                          '(DLL) '
                                                                                                          'files\n',
                                                                                           'executor': {'command': 'netsh.exe '
                                                                                                                   'add '
                                                                                                                   'helper '
                                                                                                                   '#{helper_file}\n',
                                                                                                        'name': 'command_prompt'},
                                                                                           'input_arguments': {'helper_file': {'default': 'C:\\Path\\file.dll',
                                                                                                                               'description': 'Path '
                                                                                                                                              'to '
                                                                                                                                              'DLL',
                                                                                                                               'type': 'Path'}},
                                                                                           'name': 'Netsh '
                                                                                                   'Helper '
                                                                                                   'DLL '
                                                                                                   'Registration',
                                                                                           'supported_platforms': ['windows']}],
                                                                         'attack_technique': 'T1546.007',
                                                                         'display_name': 'Event '
                                                                                         'Triggered '
                                                                                         'Execution: '
                                                                                         'Netsh '
                                                                                         'Helper '
                                                                                         'DLL'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors

None
