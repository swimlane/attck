
# Netsh Helper DLL

## Description

### MITRE Description

> Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility. (Citation: TechNet Netsh) The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at <code>HKLM\SOFTWARE\Microsoft\Netsh</code>.

Adversaries can use netsh.exe with helper DLLs to proxy execution of arbitrary code in a persistent manner when netsh.exe is executed automatically with another Persistence technique or if other persistent software is present on the system that executes netsh.exe as part of its normal functionality. Examples include some VPN software that invoke netsh.exe. (Citation: Demaske Netsh Persistence)

Proof of concept code exists to load Cobalt Strike's payload using netsh.exe helper DLLs. (Citation: Github Netsh Helper CS Beacon)

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
* Wiki: https://attack.mitre.org/techniques/T1128

## Potential Commands

```
netsh.exe add helper C:\Path\file.dll

\SOFTWARE\Microsoft\NetSh
\\Windows\\.+\\netsh.exeadd|helper
```

## Commands Dataset

```
[{'command': 'netsh.exe add helper C:\\Path\\file.dll\n',
  'name': None,
  'source': 'atomics/T1128/T1128.yaml'},
 {'command': '\\SOFTWARE\\Microsoft\\NetSh',
  'name': None,
  'source': 'SysmonHunter - Netsh Helper DLL'},
 {'command': '\\\\Windows\\\\.+\\\\netsh.exeadd|helper',
  'name': None,
  'source': 'SysmonHunter - Netsh Helper DLL'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['DLL monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['Sysmon ID 7', 'DLL monitoring']}]
```

## Potential Queries

```json
[{'name': 'Narsh Helper DLL Registry',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           'registry_key_path contains '
           '"*\\\\SOFTWARE\\\\Microsoft\\\\Netsh\\\\*"'},
 {'name': 'Netsh Helper DLL Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_path contains '
           '"netsh.exe"and process_command_line contains "*helper*")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Netsh Helper DLL': {'atomic_tests': [{'auto_generated_guid': '3244697d-5a3a-4dfc-941c-550f69f91a4d',
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
                                              'attack_technique': 'T1128',
                                              'display_name': 'Netsh Helper '
                                                              'DLL'}},
 {'SysmonHunter - T1128': {'description': None,
                           'level': 'medium',
                           'name': 'Netsh Helper DLL',
                           'phase': 'Persistence',
                           'query': [{'reg': {'path': {'pattern': '\\SOFTWARE\\Microsoft\\NetSh'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'op': 'and',
                                                              'pattern': 'add|helper'},
                                                  'image': {'pattern': '\\\\Windows\\\\.+\\\\netsh.exe'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors

None
