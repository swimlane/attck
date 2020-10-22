
# Domain Trust Discovery

## Description

### MITRE Description

> Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain.(Citation: Microsoft Trusts) Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct [SID-History Injection](https://attack.mitre.org/techniques/T1134/005), [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003), and [Kerberoasting](https://attack.mitre.org/techniques/T1558/003).(Citation: AdSecurity Forging Trust Tickets)(Citation: Harmj0y Domain Trusts) Domain trusts can be enumerated using the `DSEnumerateDomainTrusts()` Win32 API call, .NET methods, and LDAP.(Citation: Harmj0y Domain Trusts) The Windows utility [Nltest](https://attack.mitre.org/software/S0359) is known to be used by adversaries to enumerate domain trusts.(Citation: Microsoft Operation Wilysupply)

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
* Wiki: https://attack.mitre.org/techniques/T1482

## Potential Commands

```
dsquery * -filter "(objectClass=trustedDomain)" -attr *

nltest /domain_trusts

Import-Module "$env:TEMP\PowerView.ps1"
Get-NetDomainTrust
Get-NetForestTrust
Get-ADDomain
Get-ADGroupMember Administrators -Recursive

{'windows': {'psh': {'command': 'Import-Module .\\powerview.ps1 -Force;\nGet-NetDomain | ConvertTo-Json -Depth 1\n', 'parsers': {'plugins.stockpile.app.parsers.json': [{'source': 'domain.ad.forest', 'json_key': 'Forest', 'json_type': ['str']}, {'source': 'domain.ad.name', 'json_key': 'Name', 'json_type': ['str']}]}, 'payloads': ['powerview.ps1']}}}
```

## Commands Dataset

```
[{'command': 'dsquery * -filter "(objectClass=trustedDomain)" -attr *\n',
  'name': None,
  'source': 'atomics/T1482/T1482.yaml'},
 {'command': 'nltest /domain_trusts\n',
  'name': None,
  'source': 'atomics/T1482/T1482.yaml'},
 {'command': 'Import-Module "$env:TEMP\\PowerView.ps1"\n'
             'Get-NetDomainTrust\n'
             'Get-NetForestTrust\n'
             'Get-ADDomain\n'
             'Get-ADGroupMember Administrators -Recursive\n',
  'name': None,
  'source': 'atomics/T1482/T1482.yaml'},
 {'command': {'windows': {'psh': {'command': 'Import-Module .\\powerview.ps1 '
                                             '-Force;\n'
                                             'Get-NetDomain | ConvertTo-Json '
                                             '-Depth 1\n',
                                  'parsers': {'plugins.stockpile.app.parsers.json': [{'json_key': 'Forest',
                                                                                      'json_type': ['str'],
                                                                                      'source': 'domain.ad.forest'},
                                                                                     {'json_key': 'Name',
                                                                                      'json_type': ['str'],
                                                                                      'source': 'domain.ad.name'}]},
                                  'payloads': ['powerview.ps1']}}},
  'name': 'Determine the Windows Domain of a computer',
  'source': 'data/abilities/discovery/6131397e-7765-424e-a594-3d7fb2d93a6a.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Domain Trust Discovery': {'atomic_tests': [{'auto_generated_guid': '4700a710-c821-4e17-a3ec-9e4c81d6845f',
                                                                      'description': 'Uses '
                                                                                     'the '
                                                                                     'dsquery '
                                                                                     'command '
                                                                                     'to '
                                                                                     'discover '
                                                                                     'domain '
                                                                                     'trusts.\n'
                                                                                     'Requires '
                                                                                     'the '
                                                                                     'installation '
                                                                                     'of '
                                                                                     'dsquery '
                                                                                     'via '
                                                                                     'Windows '
                                                                                     'RSAT '
                                                                                     'or '
                                                                                     'the '
                                                                                     'Windows '
                                                                                     'Server '
                                                                                     'AD '
                                                                                     'DS '
                                                                                     'role.\n',
                                                                      'executor': {'command': 'dsquery '
                                                                                              '* '
                                                                                              '-filter '
                                                                                              '"(objectClass=trustedDomain)" '
                                                                                              '-attr '
                                                                                              '*\n',
                                                                                   'name': 'command_prompt'},
                                                                      'name': 'Windows '
                                                                              '- '
                                                                              'Discover '
                                                                              'domain '
                                                                              'trusts '
                                                                              'with '
                                                                              'dsquery',
                                                                      'supported_platforms': ['windows']},
                                                                     {'auto_generated_guid': '2e22641d-0498-48d2-b9ff-c71e496ccdbe',
                                                                      'dependencies': [{'description': 'nltest.exe '
                                                                                                       'from '
                                                                                                       'RSAT '
                                                                                                       'must '
                                                                                                       'be '
                                                                                                       'present '
                                                                                                       'on '
                                                                                                       'disk\n',
                                                                                        'get_prereq_command': 'echo '
                                                                                                              'Sorry '
                                                                                                              'RSAT '
                                                                                                              'must '
                                                                                                              'be '
                                                                                                              'installed '
                                                                                                              'manually\n',
                                                                                        'prereq_command': 'WHERE '
                                                                                                          'nltest.exe '
                                                                                                          '>NUL '
                                                                                                          '2>&1\n'}],
                                                                      'description': 'Uses '
                                                                                     'the '
                                                                                     'nltest '
                                                                                     'command '
                                                                                     'to '
                                                                                     'discover '
                                                                                     'domain '
                                                                                     'trusts.\n'
                                                                                     'Requires '
                                                                                     'the '
                                                                                     'installation '
                                                                                     'of '
                                                                                     'nltest '
                                                                                     'via '
                                                                                     'Windows '
                                                                                     'RSAT '
                                                                                     'or '
                                                                                     'the '
                                                                                     'Windows '
                                                                                     'Server '
                                                                                     'AD '
                                                                                     'DS '
                                                                                     'role.\n'
                                                                                     'This '
                                                                                     'technique '
                                                                                     'has '
                                                                                     'been '
                                                                                     'used '
                                                                                     'by '
                                                                                     'the '
                                                                                     'Trickbot '
                                                                                     'malware '
                                                                                     'family.\n',
                                                                      'executor': {'command': 'nltest '
                                                                                              '/domain_trusts\n',
                                                                                   'name': 'command_prompt'},
                                                                      'name': 'Windows '
                                                                              '- '
                                                                              'Discover '
                                                                              'domain '
                                                                              'trusts '
                                                                              'with '
                                                                              'nltest',
                                                                      'supported_platforms': ['windows']},
                                                                     {'auto_generated_guid': 'c58fbc62-8a62-489e-8f2d-3565d7d96f30',
                                                                      'dependencies': [{'description': 'PowerView '
                                                                                                       'PowerShell '
                                                                                                       'script '
                                                                                                       'must '
                                                                                                       'exist '
                                                                                                       'on '
                                                                                                       'disk\n',
                                                                                        'get_prereq_command': 'Invoke-WebRequest '
                                                                                                              '"https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1" '
                                                                                                              '-OutFile '
                                                                                                              '"$env:TEMP\\PowerView.ps1"\n',
                                                                                        'prereq_command': 'if '
                                                                                                          '(Test-Path '
                                                                                                          '$env:TEMP\\PowerView.ps1) '
                                                                                                          '{exit '
                                                                                                          '0} '
                                                                                                          'else '
                                                                                                          '{exit '
                                                                                                          '1}\n'},
                                                                                       {'description': 'RSAT '
                                                                                                       'PowerShell '
                                                                                                       'AD '
                                                                                                       'admin '
                                                                                                       'cmdlets '
                                                                                                       'must '
                                                                                                       'be '
                                                                                                       'installed\n',
                                                                                        'get_prereq_command': 'Write-Host '
                                                                                                              '"Sorry '
                                                                                                              'RSAT '
                                                                                                              'must '
                                                                                                              'be '
                                                                                                              'installed '
                                                                                                              'manually"\n',
                                                                                        'prereq_command': 'if '
                                                                                                          '((Get-Command '
                                                                                                          '"Get-ADDomain" '
                                                                                                          '-ErrorAction '
                                                                                                          'Ignore) '
                                                                                                          '-And '
                                                                                                          '(Get-Command '
                                                                                                          '"Get-ADGroupMember" '
                                                                                                          '-ErrorAction '
                                                                                                          'Ignore)) '
                                                                                                          '{ '
                                                                                                          'exit '
                                                                                                          '0 '
                                                                                                          '} '
                                                                                                          'else '
                                                                                                          '{ '
                                                                                                          'exit '
                                                                                                          '1 '
                                                                                                          '}\n'}],
                                                                      'dependency_executor_name': 'powershell',
                                                                      'description': 'Use '
                                                                                     'powershell '
                                                                                     'to '
                                                                                     'enumerate '
                                                                                     'AD '
                                                                                     'information.\n'
                                                                                     'Requires '
                                                                                     'the '
                                                                                     'installation '
                                                                                     'of '
                                                                                     'PowerShell '
                                                                                     'AD '
                                                                                     'admin '
                                                                                     'cmdlets '
                                                                                     'via '
                                                                                     'Windows '
                                                                                     'RSAT '
                                                                                     'or '
                                                                                     'the '
                                                                                     'Windows '
                                                                                     'Server '
                                                                                     'AD '
                                                                                     'DS '
                                                                                     'role.\n',
                                                                      'executor': {'command': 'Import-Module '
                                                                                              '"$env:TEMP\\PowerView.ps1"\n'
                                                                                              'Get-NetDomainTrust\n'
                                                                                              'Get-NetForestTrust\n'
                                                                                              'Get-ADDomain\n'
                                                                                              'Get-ADGroupMember '
                                                                                              'Administrators '
                                                                                              '-Recursive\n',
                                                                                   'name': 'powershell'},
                                                                      'name': 'Powershell '
                                                                              'enumerate '
                                                                              'domains '
                                                                              'and '
                                                                              'forests',
                                                                      'supported_platforms': ['windows']}],
                                                    'attack_technique': 'T1482',
                                                    'display_name': 'Domain '
                                                                    'Trust '
                                                                    'Discovery'}},
 {'Mitre Stockpile - Determine the Windows Domain of a computer': {'description': 'Determine '
                                                                                  'the '
                                                                                  'Windows '
                                                                                  'Domain '
                                                                                  'of '
                                                                                  'a '
                                                                                  'computer',
                                                                   'id': '6131397e-7765-424e-a594-3d7fb2d93a6a',
                                                                   'name': 'GetDomain',
                                                                   'platforms': {'windows': {'psh': {'command': 'Import-Module '
                                                                                                                '.\\powerview.ps1 '
                                                                                                                '-Force;\n'
                                                                                                                'Get-NetDomain '
                                                                                                                '| '
                                                                                                                'ConvertTo-Json '
                                                                                                                '-Depth '
                                                                                                                '1\n',
                                                                                                     'parsers': {'plugins.stockpile.app.parsers.json': [{'json_key': 'Forest',
                                                                                                                                                         'json_type': ['str'],
                                                                                                                                                         'source': 'domain.ad.forest'},
                                                                                                                                                        {'json_key': 'Name',
                                                                                                                                                         'json_type': ['str'],
                                                                                                                                                         'source': 'domain.ad.name'}]},
                                                                                                     'payloads': ['powerview.ps1']}}},
                                                                   'tactic': 'discovery',
                                                                   'technique': {'attack_id': 'T1482',
                                                                                 'name': 'Domain '
                                                                                         'Trust '
                                                                                         'Discovery'}}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [Domain Trust Discovery Mitigation](../mitigations/Domain-Trust-Discovery-Mitigation.md)

* [Network Segmentation](../mitigations/Network-Segmentation.md)
    
* [Audit](../mitigations/Audit.md)
    

# Actors


* [Wizard Spider](../actors/Wizard-Spider.md)

