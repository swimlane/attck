
# Domain Trust Discovery

## Description

### MITRE Description

> Adversaries may attempt to gather information on domain trust relationships that may be used to identify [Lateral Movement](https://attack.mitre.org/tactics/TA0008) opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain.(Citation: Microsoft Trusts) Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct [SID-History Injection](https://attack.mitre.org/techniques/T1178), [Pass the Ticket](https://attack.mitre.org/techniques/T1097), and [Kerberoasting](https://attack.mitre.org/techniques/T1208).(Citation: AdSecurity Forging Trust Tickets)(Citation: Harmj0y Domain Trusts) Domain trusts can be enumerated using the DSEnumerateDomainTrusts() Win32 API call, .NET methods, and LDAP.(Citation: Harmj0y Domain Trusts) The Windows utility [Nltest](https://attack.mitre.org/software/S0359) is known to be used by adversaries to enumerate domain trusts.(Citation: Microsoft Operation Wilysupply)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1482

## Potential Commands

```
dsquery * -filter "(objectClass=trustedDomain)" -attr *

nltest /domain_trusts

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
 {'command': 'Get-NetDomainTrust\n'
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
[{'Atomic Red Team Test - Domain Trust Discovery': {'atomic_tests': [{'description': 'Uses '
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
                                                                     {'description': 'Uses '
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
                                                                     {'description': 'Use '
                                                                                     'powershell '
                                                                                     'to '
                                                                                     'enumerate '
                                                                                     'AD '
                                                                                     'information\n',
                                                                      'executor': {'command': 'Get-NetDomainTrust\n'
                                                                                              'Get-NetForestTrust\n'
                                                                                              'Get-ADDomain\n'
                                                                                              'Get-ADGroupMember '
                                                                                              'Administrators '
                                                                                              '-Recursive\n',
                                                                                   'elevation_required': False,
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

None

# Actors

None
