
# Services Registry Permissions Weakness

## Description

### MITRE Description

> Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services. Adversaries may use flaws in the permissions for registry to redirect from the originally specified executable to one that they control, in order to launch their own code at Service start.  Windows stores local service configuration information in the Registry under <code>HKLM\SYSTEM\CurrentControlSet\Services</code>. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe,  [PowerShell](https://attack.mitre.org/techniques/T1059/001), or [Reg](https://attack.mitre.org/software/S0075). Access to Registry keys is controlled through Access Control Lists and permissions. (Citation: Registry Key Security)

If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, then adversaries can change the service binPath/ImagePath to point to a different executable under their control. When the service starts or is restarted, then the adversary-controlled program will execute, allowing the adversary to gain persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService).

Adversaries may also alter Registry keys associated with service failure parameters (such as <code>FailureCommand</code>) that may be executed in an elevated context anytime the service fails or is intentionally corrupted.(Citation: Kansa Service related collectors)(Citation: Tweet Registry Perms Weakness) 

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application control']
* Effective Permissions: ['SYSTEM']
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1574/011

## Potential Commands

```
exploit/windows/local/trusted_service_path
powershell-import /path/to/PowerUp.ps1
powershell Invoke-AllChecks
Check for common privilege escalation methods:
*upload PowerUp.ps1 to victim disk*
powershell.exe -epbypass PowerUp.ps1
Invoke-AllChecks
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
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'}]
```

## Potential Detections

```json
[{'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['7040', ' 7045', 'Services']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['7040', ' 7045', 'Services']},
 {'data_source': ['4657', 'Windows Registry']}]
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
                                                  'Category': 'T1058',
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
                                                  'Metasploit': 'exploit/windows/local/trusted_service_path'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Restrict Registry Permissions](../mitigations/Restrict-Registry-Permissions.md)


# Actors

None
