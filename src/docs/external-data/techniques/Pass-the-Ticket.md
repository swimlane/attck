
# Pass the Ticket

## Description

### MITRE Description

> Adversaries may “pass the ticket” using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system.

In this technique, valid Kerberos tickets for [Valid Accounts](https://attack.mitre.org/techniques/T1078) are captured by [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). A user's service tickets or ticket granting ticket (TGT) may be obtained, depending on the level of access. A service ticket allows for access to a particular resource, whereas a TGT can be used to request service tickets from the Ticket Granting Service (TGS) to access any resource the user has privileges to access.(Citation: ADSecurity AD Kerberos Attacks)(Citation: GentilKiwi Pass the Ticket)

[Silver Ticket](https://attack.mitre.org/techniques/T1558/002) can be obtained for services that use Kerberos as an authentication mechanism and are used to generate tickets to access that particular resource and the system that hosts the resource (e.g., SharePoint).(Citation: ADSecurity AD Kerberos Attacks)

[Golden Ticket](https://attack.mitre.org/techniques/T1558/001) can be obtained for the domain using the Key Distribution Service account KRBTGT account NTLM hash, which enables generation of TGTs for any account in Active Directory.(Citation: Campbell 2014)

## Aliases

```

```

## Additional Attributes

* Bypass: ['System Access Controls']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1550/003

## Potential Commands

```
mimikatz # kerberos::ptt #{user_name}@atomic.local
mimikatz # kerberos::ptt Administrator@#{domain}
```

## Commands Dataset

```
[{'command': 'mimikatz # kerberos::ptt Administrator@#{domain}\n',
  'name': None,
  'source': 'atomics/T1550.003/T1550.003.yaml'},
 {'command': 'mimikatz # kerberos::ptt #{user_name}@atomic.local\n',
  'name': None,
  'source': 'atomics/T1550.003/T1550.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Use Alternate Authentication Material: Pass the Ticket': {'atomic_tests': [{'auto_generated_guid': 'dbf38128-7ba7-4776-bedf-cc2eed432098',
                                                                                                      'description': 'Similar '
                                                                                                                     'to '
                                                                                                                     'PTH, '
                                                                                                                     'but '
                                                                                                                     'attacking '
                                                                                                                     'Kerberos\n',
                                                                                                      'executor': {'command': 'mimikatz '
                                                                                                                              '# '
                                                                                                                              'kerberos::ptt '
                                                                                                                              '#{user_name}@#{domain}\n',
                                                                                                                   'name': 'command_prompt'},
                                                                                                      'input_arguments': {'domain': {'default': 'atomic.local',
                                                                                                                                     'description': 'domain',
                                                                                                                                     'type': 'string'},
                                                                                                                          'user_name': {'default': 'Administrator',
                                                                                                                                        'description': 'username',
                                                                                                                                        'type': 'string'}},
                                                                                                      'name': 'Mimikatz '
                                                                                                              'Kerberos '
                                                                                                              'Ticket '
                                                                                                              'Attack',
                                                                                                      'supported_platforms': ['windows']}],
                                                                                    'attack_technique': 'T1550.003',
                                                                                    'display_name': 'Use '
                                                                                                    'Alternate '
                                                                                                    'Authentication '
                                                                                                    'Material: '
                                                                                                    'Pass '
                                                                                                    'the '
                                                                                                    'Ticket'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Lateral Movement](../tactics/Lateral-Movement.md)
    

# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Active Directory Configuration](../mitigations/Active-Directory-Configuration.md)
    
* [Password Policies](../mitigations/Password-Policies.md)
    

# Actors


* [APT29](../actors/APT29.md)

* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [APT32](../actors/APT32.md)
    
