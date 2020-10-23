
# Path Interception by Unquoted Path

## Description

### MITRE Description

> Adversaries may execute their own malicious payloads by hijacking vulnerable file path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.

Service paths (Citation: Microsoft CurrentControlSet Services) and shortcut paths may also be vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (e.g., <code>C:\unsafe path with space\program.exe</code> vs. <code>"C:\safe path with space\program.exe"</code>). (Citation: Help eliminate unquoted path) (stored in Windows Registry keys) An adversary can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable. For example, if the path in a shortcut is <code>C:\program files\myapp.exe</code>, an adversary may create a program at <code>C:\program.exe</code> that will be run instead of the intended program. (Citation: Windows Unquoted Services) (Citation: Windows Privilege Escalation Guide)

This technique can be used for persistence if executables are called on a regular basis, as well as privilege escalation if intercepted executables are started by a higher privileged process.

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
* Wiki: https://attack.mitre.org/techniques/T1574/009

## Potential Commands

```
exploit/windows/local/trusted_service_path
powershell-import /path/to/PowerUp.ps1
powershell Invoke-AllChecks
Check for common privilege escalation methods:
*upload PowerUp.ps1 to victim disk*
powershell.exe -epbypass PowerUp.ps1
Invoke-AllChecks
powershell/privesc/powerup/allchecks
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
 {'command': 'powershell/privesc/powerup/allchecks',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/powerup/allchecks',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['8000-8027', ' 866', 'Whitelist Failures']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['IDs ???', 'Whitelist Failures']}]
```

## Potential Queries

```json

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
                                                  'Category': 'T1034',
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
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1034',
                                            'ATT&CK Technique #2': 'T1044',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/powerup/allchecks":  '
                                                                                 '["T1034","T1044"],',
                                            'Empire Module': 'powershell/privesc/powerup/allchecks',
                                            'Technique': 'Path Interception'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)

* [Audit](../mitigations/Audit.md)
    
* [Execution Prevention](../mitigations/Execution-Prevention.md)
    

# Actors

None
