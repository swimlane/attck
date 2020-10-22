
# Valid Accounts

## Description

### MITRE Description

> Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.

The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise. (Citation: TechNet Credential Theft)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Firewall', 'Host intrusion prevention systems', 'Network intrusion detection system', 'Application control', 'System access controls', 'Anti-virus']
* Effective Permissions: ['User', 'Administrator']
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure', 'SaaS', 'Office 365', 'Azure AD']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1078

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': {'author': 'juju4',
                  'description': 'Detect remote login by Administrator user '
                                 'depending on internal pattern',
                  'detection': {'condition': 'selection',
                                'selection': {'AccountName': 'Admin-*',
                                              'AuthenticationPackageName': 'Negotiate',
                                              'EventID': 4624,
                                              'LogonType': 10}},
                  'falsepositives': ['Legitimate administrative activity'],
                  'id': '0f63e1ef-1eb9-4226-9d54-8927ca08520a',
                  'level': 'low',
                  'logsource': {'definition': 'Requirements: Identifiable '
                                              'administrators usernames '
                                              '(pattern or special unique '
                                              'character. ex: "Admin-*"), '
                                              'internal policy mandating use '
                                              'only as secondary account',
                                'product': 'windows',
                                'service': 'security'},
                  'references': ['https://car.mitre.org/wiki/CAR-2016-04-005'],
                  'status': 'experimental',
                  'tags': ['attack.lateral_movement',
                           'attack.t1078',
                           'car.2016-04-005'],
                  'title': 'Admin User Remote Logon'}},
 {'data_source': {'author': '@neu5ron',
                  'description': 'Detects scenario where if a user is assigned '
                                 'the SeEnableDelegationPrivilege right in '
                                 'Active Directory it would allow control of '
                                 'other AD user objects.',
                  'detection': {'condition': 'all of them',
                                'keywords': {'Message': ['*SeEnableDelegationPrivilege*']},
                                'selection': {'EventID': 4704}},
                  'falsepositives': ['Unknown'],
                  'id': '311b6ce2-7890-4383-a8c2-663a9f6b43cd',
                  'level': 'high',
                  'logsource': {'definition': 'Requirements: Audit Policy : '
                                              'Policy Change > Audit '
                                              'Authorization Policy Change, '
                                              'Group Policy : Computer '
                                              'Configuration\\Windows '
                                              'Settings\\Security '
                                              'Settings\\Advanced Audit Policy '
                                              'Configuration\\Audit '
                                              'Policies\\Policy Change\\Audit '
                                              'Authorization Policy Change',
                                'product': 'windows',
                                'service': 'security'},
                  'references': ['https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/'],
                  'tags': ['attack.privilege_escalation', 'attack.t1078'],
                  'title': 'Enabled User Right in AD to Control User Objects'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'This method uses uncommon error codes on '
                                 'failed logons to determine suspicious '
                                 'activity and tampering with accounts that '
                                 'have been disabled or somehow restricted.',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': [4625, 4776],
                                              'Status': ['0xC0000072',
                                                         '0xC000006F',
                                                         '0xC0000070',
                                                         '0xC0000413',
                                                         '0xC000018C',
                                                         '0xC000015B']}},
                  'falsepositives': ['User using a disabled account'],
                  'id': '9eb99343-d336-4020-a3cd-67f3819e68ee',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'modified': '2019/03/01',
                  'references': ['https://twitter.com/SBousseaden/status/1101431884540710913'],
                  'tags': ['attack.persistence',
                           'attack.privilege_escalation',
                           'attack.t1078'],
                  'title': 'Account Tampering - Suspicious Failed Logon '
                           'Reasons'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects suspicious failed logins with '
                                 'different user accounts from a single source '
                                 'system',
                  'detection': {'condition': ['selection1 | count(UserName) by '
                                              'WorkstationName > 3',
                                              'selection2 | count(UserName) by '
                                              'Workstation > 3'],
                                'selection1': {'EventID': [529, 4625],
                                               'UserName': '*',
                                               'WorkstationName': '*'},
                                'selection2': {'EventID': 4776,
                                               'UserName': '*',
                                               'Workstation': '*'},
                                'timeframe': '24h'},
                  'falsepositives': ['Terminal servers',
                                     'Jump servers',
                                     'Other multiuser systems like Citrix '
                                     'server farms',
                                     'Workstations with frequently changing '
                                     'users'],
                  'id': 'e98374a6-e2d9-4076-9b5c-11bdb2569995',
                  'level': 'medium',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'tags': ['attack.persistence',
                           'attack.privilege_escalation',
                           'attack.t1078'],
                  'title': 'Multiple Failed Logins with Different Accounts '
                           'from Single Source System'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects interactive console logons to',
                  'detection': {'condition': 'selection and not filter',
                                'filter': {'ComputerName': '%Workstations%',
                                           'LogonProcessName': 'Advapi'},
                                'selection': {'ComputerName': ['%ServerSystems%',
                                                               '%DomainControllers%'],
                                              'EventID': [528, 529, 4624, 4625],
                                              'LogonType': 2}},
                  'falsepositives': ['Administrative activity via KVM or ILO '
                                     'board'],
                  'id': '3ff152b2-1388-4984-9cd9-a323323fdadf',
                  'level': 'medium',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'tags': ['attack.lateral_movement', 'attack.t1078'],
                  'title': 'Interactive Logon to Server Systems'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'This rule triggers on user accounts that are '
                                 'added to the local Administrators group, '
                                 'which could be legitimate activity or a sign '
                                 'of privilege escalation activity',
                  'detection': {'condition': 'selection and (1 of '
                                             'selection_group*) and not filter',
                                'filter': {'SubjectUserName': '*$'},
                                'selection': {'EventID': 4732},
                                'selection_group1': {'GroupName': 'Administrators'},
                                'selection_group2': {'GroupSid': 'S-1-5-32-544'}},
                  'falsepositives': ['Legitimate administrative activity'],
                  'id': 'c265cf08-3f99-46c1-8d59-328247057d57',
                  'level': 'medium',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'status': 'stable',
                  'tags': ['attack.privilege_escalation', 'attack.t1078'],
                  'title': 'User Added to Local Administrators'}},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['4688', 'Process Execution']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Initial Access](../tactics/Initial-Access.md)
    
* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Valid Accounts Mitigation](../mitigations/Valid-Accounts-Mitigation.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Password Policies](../mitigations/Password-Policies.md)
    
* [Application Developer Guidance](../mitigations/Application-Developer-Guidance.md)
    

# Actors


* [PittyTiger](../actors/PittyTiger.md)

* [Carbanak](../actors/Carbanak.md)
    
* [FIN8](../actors/FIN8.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [FIN4](../actors/FIN4.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [APT33](../actors/APT33.md)
    
* [FIN5](../actors/FIN5.md)
    
* [APT28](../actors/APT28.md)
    
* [FIN10](../actors/FIN10.md)
    
* [Suckfly](../actors/Suckfly.md)
    
* [FIN6](../actors/FIN6.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT18](../actors/APT18.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [OilRig](../actors/OilRig.md)
    
* [APT39](../actors/APT39.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
* [Silence](../actors/Silence.md)
    
* [Wizard Spider](../actors/Wizard-Spider.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
