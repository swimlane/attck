
# Service Registry Permissions Weakness

## Description

### MITRE Description

> Windows stores local service configuration information in the Registry under <code>HKLM\SYSTEM\CurrentControlSet\Services</code>. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe, [PowerShell](https://attack.mitre.org/techniques/T1086), or [Reg](https://attack.mitre.org/software/S0075). Access to Registry keys is controlled through Access Control Lists and permissions. (Citation: MSDN Registry Key Security)

If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, then adversaries can change the service binPath/ImagePath to point to a different executable under their control. When the service starts or is restarted, then the adversary-controlled program will execute, allowing the adversary to gain persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService).

Adversaries may also alter Registry keys associated with service failure parameters (such as <code>FailureCommand</code>) that may be executed in an elevated context anytime the service fails or is intentionally corrupted.(Citation: TrustedSignal Service Failure)(Citation: Twitter Service Recovery Nov 2017)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: ['SYSTEM']
* Network: None
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1058

## Potential Commands

```
Check for common privilege escalation methods:
*upload PowerUp.ps1 to victim disk*
powershell.exe -epbypass PowerUp.ps1
Invoke-AllChecks
powershell-import /path/to/PowerUp.ps1
powershell Invoke-AllChecks
exploit/windows/local/trusted_service_path
get-acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\* |FL
get-acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\weakservicename |FL

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
 {'command': 'get-acl REGISTRY::HKLM\\SYSTEM\\CurrentControlSet\\Services\\* '
             '|FL\n'
             'get-acl '
             'REGISTRY::HKLM\\SYSTEM\\CurrentControlSet\\Services\\weakservicename '
             '|FL\n',
  'name': None,
  'source': 'atomics/T1058/T1058.yaml'}]
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
                                                  'Metasploit': 'exploit/windows/local/trusted_service_path'}},
 {'Atomic Red Team Test - Service Registry Permissions Weakness': {'atomic_tests': [{'auto_generated_guid': 'f7536d63-7fd4-466f-89da-7e48d550752a',
                                                                                     'description': 'Service '
                                                                                                    'registry '
                                                                                                    'permissions '
                                                                                                    'weakness '
                                                                                                    'check '
                                                                                                    'and '
                                                                                                    'then '
                                                                                                    'which '
                                                                                                    'can '
                                                                                                    'lead '
                                                                                                    'to '
                                                                                                    'privilege '
                                                                                                    'escalation '
                                                                                                    'with '
                                                                                                    'ImagePath. '
                                                                                                    'eg. \n'
                                                                                                    'reg '
                                                                                                    'add '
                                                                                                    '"HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{weak_service_name}" '
                                                                                                    '/v '
                                                                                                    'ImagePath '
                                                                                                    '/d '
                                                                                                    '"C:\\temp\\AtomicRedteam.exe"\n',
                                                                                     'executor': {'command': 'get-acl '
                                                                                                             'REGISTRY::HKLM\\SYSTEM\\CurrentControlSet\\Services\\* '
                                                                                                             '|FL\n'
                                                                                                             'get-acl '
                                                                                                             'REGISTRY::HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{weak_service_name} '
                                                                                                             '|FL\n',
                                                                                                  'elevation_required': False,
                                                                                                  'name': 'powershell'},
                                                                                     'input_arguments': {'weak_service_name': {'default': 'weakservicename',
                                                                                                                               'description': 'weak '
                                                                                                                                              'service '
                                                                                                                                              'check',
                                                                                                                               'type': 'String'}},
                                                                                     'name': 'Service '
                                                                                             'Registry '
                                                                                             'Permissions '
                                                                                             'Weakness',
                                                                                     'supported_platforms': ['windows']}],
                                                                   'attack_technique': 'T1058',
                                                                   'display_name': 'Service '
                                                                                   'Registry '
                                                                                   'Permissions '
                                                                                   'Weakness'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors

None
