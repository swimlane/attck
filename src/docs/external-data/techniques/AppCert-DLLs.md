
# AppCert DLLs

## Description

### MITRE Description

> Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs Registry key under <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager</code> are loaded into every process that calls the ubiquitously used application programming interface (API) functions CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, or WinExec. (Citation: Endgame Process Injection July 2017)

Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), this value can be abused to obtain persistence and privilege escalation by causing a malicious DLL to be loaded and run in the context of separate processes on the computer.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: ['Administrator', 'SYSTEM']
* Network: None
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1182

## Potential Commands

```
\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs
\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs
```

## Commands Dataset

```
[{'command': '\\SYSTEM\\CurrentControlSet\\Control\\Session '
             'Manager\\AppCertDLLs',
  'name': None,
  'source': 'SysmonHunter - AppCert DLLs'},
 {'command': '\\SYSTEM\\CurrentControlSet\\Control\\Session '
             'Manager\\AppCertDLLs',
  'name': None,
  'source': 'SysmonHunter - AppCert DLLs'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['Loaded DLLs']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['Sysmon ID 7', 'Loaded DLLs']}]
```

## Potential Queries

```json
[{'name': 'AppCert DLLs',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           'registry_key_path contains '
           '"\\\\System\\\\CurrentControlSet\\\\Control\\\\Session '
           'Manager\\\\AppCertDlls\\\\"'}]
```

## Raw Dataset

```json
[{'SysmonHunter - T1182': {'description': None,
                           'level': 'medium',
                           'name': 'AppCert DLLs',
                           'phase': 'Persistence',
                           'query': [{'reg': {'path': {'pattern': '\\SYSTEM\\CurrentControlSet\\Control\\Session '
                                                                  'Manager\\AppCertDLLs'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'pattern': '\\SYSTEM\\CurrentControlSet\\Control\\Session '
                                                                         'Manager\\AppCertDLLs'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors


* [Honeybee](../actors/Honeybee.md)

