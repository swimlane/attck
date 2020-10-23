
# Services File Permissions Weakness

## Description

### MITRE Description

> Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: ['SYSTEM', 'Administrator', 'User']
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1574/010

## Potential Commands

```
exploit/windows/local/trusted_service_path
powershell-import /path/to/PowerUp.ps1
powershell Invoke-AllChecks
Check for common privilege escalation methods:
*upload PowerUp.ps1 to victim disk*
powershell.exe -epbypass PowerUp.ps1
Invoke-AllChecks
*.exe /grant Everyone:F /T /C /Q
icacls.exe
python/situational_awareness/host/multi/SuidGuidSearch
python/situational_awareness/host/multi/WorldWriteableFileSearch
```

## Commands Dataset

```
[{'command': 'Check for common privilege escalation methods:\n'
             '*upload PowerUp.ps1 to victim disk*\n'
             'powershell.exe -epbypass PowerUp.ps1\n'
             'Invoke-AllChecks',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'powershell-import /path/to/PowerUp.ps1\n'
             'powershell Invoke-AllChecks',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'exploit/windows/local/trusted_service_path',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': '*.exe /grant Everyone:F /T /C /Q ',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'icacls.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'python/situational_awareness/host/multi/SuidGuidSearch',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/host/multi/SuidGuidSearch',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/host/multi/WorldWriteableFileSearch',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/host/multi/WorldWriteableFileSearch',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['7040', ' 7045', 'Services']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['7040', ' 7045', 'Services']}]
```

## Potential Queries

```json
[{'name': 'File System Permissions Weakness',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 7 and (module_loaded contains '
           '"\\\\Temp\\\\"or module_loaded contains "C:\\\\Users\\\\"or '
           'driver_signature_status !contains "Valid")'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'Check '
                                                                              'for '
                                                                              'common '
                                                                              'privilege '
                                                                              'escalation '
                                                                              'methods:\n'
                                                                              '*upload '
                                                                              'PowerUp.ps1 '
                                                                              'to '
                                                                              'victim '
                                                                              'disk*\n'
                                                                              'powershell.exe '
                                                                              '-epbypass '
                                                                              'PowerUp.ps1\n'
                                                                              'Invoke-AllChecks',
                                                  'Category': 'T1044',
                                                  'Cobalt Strike': 'powershell-import '
                                                                   '/path/to/PowerUp.ps1\n'
                                                                   'powershell '
                                                                   'Invoke-AllChecks',
                                                  'Description': 'PowerUp.ps1 '
                                                                 'is a '
                                                                 'powershell '
                                                                 'script from '
                                                                 'the '
                                                                 'PowerSploit '
                                                                 'project on '
                                                                 'github by '
                                                                 'PowershellMafia. '
                                                                 'The '
                                                                 'Invoke-AllChecks '
                                                                 'commandlet '
                                                                 'checks for '
                                                                 'many common '
                                                                 'privilege '
                                                                 'escalation '
                                                                 'options such '
                                                                 'as unquoted '
                                                                 'service '
                                                                 'paths, '
                                                                 'writeable '
                                                                 'service '
                                                                 'directories, '
                                                                 'service '
                                                                 'information '
                                                                 'manipulation, '
                                                                 'always '
                                                                 'install '
                                                                 'elevated, '
                                                                 'etc. Each '
                                                                 'specific '
                                                                 'kind of '
                                                                 'escalation '
                                                                 'technique '
                                                                 'supplies its '
                                                                 'own method '
                                                                 'of abusing '
                                                                 'it.',
                                                  'Metasploit': 'exploit/windows/local/trusted_service_path'}},
 {'Threat Hunting Tables': {'chain_id': '100125',
                            'commandline_string': '/grant Everyone:F /T /C /Q ',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',
                            'loaded_dll': '',
                            'mitre_attack': 'T1044',
                            'mitre_caption': 'file_systems_permissions_weakness',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'icacls.exe',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1044',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/host/multi/SuidGuidSearch":  '
                                                                                 '["T1044"],',
                                            'Empire Module': 'python/situational_awareness/host/multi/SuidGuidSearch',
                                            'Technique': 'File System '
                                                         'Permissions '
                                                         'Weakness'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1044',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/host/multi/WorldWriteableFileSearch":  '
                                                                                 '["T1044"],',
                                            'Empire Module': 'python/situational_awareness/host/multi/WorldWriteableFileSearch',
                                            'Technique': 'File System '
                                                         'Permissions '
                                                         'Weakness'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Audit](../mitigations/Audit.md)

* [User Account Management](../mitigations/User-Account-Management.md)
    
* [User Account Control](../mitigations/User-Account-Control.md)
    

# Actors

None
