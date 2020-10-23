
# Shared Modules

## Description

### MITRE Description

> Adversaries may abuse shared modules to execute malicious payloads. The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in NTDLL.dll and is part of the Windows [Native API](https://attack.mitre.org/techniques/T1106) which is called from functions like <code>CreateProcess</code>, <code>LoadLibrary</code>, etc. of the Win32 API. (Citation: Wikipedia Windows Library Files)

The module loader can load DLLs:

* via specification of the (fully-qualified or relative) DLL pathname in the IMPORT directory;
    
* via EXPORT forwarded to another DLL, specified with (fully-qualified or relative) pathname (but without extension);
    
* via an NTFS junction or symlink program.exe.local with the fully-qualified or relative pathname of a directory containing the DLLs specified in the IMPORT directory or forwarded EXPORTs;
    
* via <code>&#x3c;file name="filename.extension" loadFrom="fully-qualified or relative pathname"&#x3e;</code> in an embedded or external "application manifest". The file name refers to an entry in the IMPORT directory or a forwarded EXPORT.

Adversaries may use this functionality as a way to execute arbitrary code on a victim system. For example, malware may execute share modules to load additional components or features.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1129

## Potential Commands

```
malware.dll
rundll32.exe
control.exe
```

## Commands Dataset

```
[{'command': 'control.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'malware.dll',
  'name': 'loaded_dll',
  'source': 'Threat Hunting Tables'},
 {'command': 'rundll32.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['DLL monitoring']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Sysmon ID 7', 'DLL monitoring']},
 {'data_source': ['API monitoring']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Threat Hunting Tables': {'chain_id': '100015',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': 'malware.dll',
                            'mitre_attack': 'T1129',
                            'mitre_caption': 'module_load',
                            'os': 'windows',
                            'parent_process': 'control.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'rundll32.exe',
                            'sub_process_2': ''}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [Execution through Module Load Mitigation](../mitigations/Execution-through-Module-Load-Mitigation.md)

* [Execution Prevention](../mitigations/Execution-Prevention.md)
    

# Actors

None
