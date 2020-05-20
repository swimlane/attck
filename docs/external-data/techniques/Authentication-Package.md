
# Authentication Package

## Description

### MITRE Description

> Windows Authentication Package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system. (Citation: MSDN Authentication Packages)

Adversaries can use the autostart mechanism provided by LSA Authentication Packages for persistence by placing a reference to a binary in the Windows Registry location <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\</code> with the key value of <code>"Authentication Packages"=<target binary></code>. The binary will then be executed by the system when the authentication packages are loaded.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1131

## Potential Commands

```
\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages
\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages
```

## Commands Dataset

```
[{'command': '\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Authentication '
             'Packages',
  'name': None,
  'source': 'SysmonHunter - Authentication Package'},
 {'command': '\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Authentication '
             'Packages',
  'name': None,
  'source': 'SysmonHunter - Authentication Package'}]
```

## Potential Detections

```json
[{'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['Loaded DLLs']},
 {'data_source': ['DLL monitoring']},
 {'data_source': ['DLL monitoring']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['Sysmon ID 7', 'Loaded DLLs']}]
```

## Potential Queries

```json
[{'name': 'Authentication Package',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           '(registry_key_path contains '
           '"*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\*")and '
           '(process_path !contains "C:\\\\WINDOWS\\\\system32\\\\lsass.exe"or '
           'process_path !contains '
           '"C:\\\\Windows\\\\system32\\\\svchost.exe"or process_path '
           '!contains "C:\\\\Windows\\\\system32\\\\services.exe")'}]
```

## Raw Dataset

```json
[{'SysmonHunter - T1131': {'description': None,
                           'level': 'medium',
                           'name': 'Authentication Package',
                           'phase': 'Persistence',
                           'query': [{'reg': {'path': {'pattern': '\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Authentication '
                                                                  'Packages'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'pattern': '\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Authentication '
                                                                         'Packages'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors

None
