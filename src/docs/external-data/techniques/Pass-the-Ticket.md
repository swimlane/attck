
# Pass the Ticket

## Description

### MITRE Description

> Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system.

In this technique, valid Kerberos tickets for [Valid Accounts](https://attack.mitre.org/techniques/T1078) are captured by [Credential Dumping](https://attack.mitre.org/techniques/T1003). A user's service tickets or ticket granting ticket (TGT) may be obtained, depending on the level of access. A service ticket allows for access to a particular resource, whereas a TGT can be used to request service tickets from the Ticket Granting Service (TGS) to access any resource the user has privileges to access. (Citation: ADSecurity AD Kerberos Attacks) (Citation: GentilKiwi Pass the Ticket)

Silver Tickets can be obtained for services that use Kerberos as an authentication mechanism and are used to generate tickets to access that particular resource and the system that hosts the resource (e.g., SharePoint). (Citation: ADSecurity AD Kerberos Attacks)

Golden Tickets can be obtained for the domain using the Key Distribution Service account KRBTGT account NTLM hash, which enables generation of TGTs for any account in Active Directory. (Citation: Campbell 2014)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1097

## Potential Commands

```
mimikatz # kerberos::ptt Administrator@#{domain}

mimikatz # kerberos::ptt #{user_name}@atomic.local

```

## Commands Dataset

```
[{'command': 'mimikatz # kerberos::ptt Administrator@#{domain}\n',
  'name': None,
  'source': 'atomics/T1097/T1097.yaml'},
 {'command': 'mimikatz # kerberos::ptt #{user_name}@atomic.local\n',
  'name': None,
  'source': 'atomics/T1097/T1097.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows local account manipulation\n'
           'description: win7 test\n'
           'references:\n'
           'tags: T1087 / T1069\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4624 # account login\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Account domain: '. * *' # May be "
           'understood with reference to exemplary log\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4672 # Special Login\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Account domain: _ # account field '
           'is empty\n'
           '\xa0\xa0\xa0\xa0timeframe: last 5s\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: MS14-068-PYKEK\n'
           'description: windows server 2008 / windows 7\n'
           'references: '
           'https://www.blackhat.com/docs/us-15/materials/us-15-Metcalf-Red-Vs-Blue-Modern-Active-Directory-Attacks-Detection-And-Protection-wp.pdf\n'
           'tags: T1097\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: Security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4624 # account login\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Account Domain: '* *.' # New "
           'Registration> Account domain (under normal circumstances, account '
           'should be a domain ABC, when there KEKEO attack, the account '
           'domain ABC.COM)\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4672 # administrator '
           'login\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Account Domain: # accounts domain '
           '(under normal circumstances, account should be a domain ABC, when '
           'there KEKEO attack, the account field is empty)\n'
           '\xa0\xa0\xa0\xa0selection3:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4768 #Kerberos TGS '
           'request\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Supplied Realm Name: '* *.' # "
           'Field names provided (under normal circumstances, provide the name '
           'of the field should be ABC, when there KEKEO attack, the field '
           'name has been provided for the ABC.COM)\n'
           '\xa0\xa0\xa0\xa0timeframe: last 5s\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: MS14-068-PYKEK\n'
           'description: windows server 2008 / windows 7\n'
           'references: '
           'https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/golden_ticket.md\n'
           'tags: T1097\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: Security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4624 # account login\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Account Domain: '* *.' # New "
           'Registration> Account domain (under normal circumstances, account '
           'should be a domain ABC, when there PYKEK attack, the account '
           'domain ABC.COM)\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Account Name: '*' # new login> "
           'account name (different from the account security identification '
           'of this condition are complex to implement)\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4672 # administrator '
           'login\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Account Domain: '* *.' # Account "
           'field (under normal circumstances, should account field ABC, when '
           'present PYKEK attack domain account ABC.COM)\n'
           '\xa0\xa0\xa0\xa0selection3:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4768 #Kerberos TGS '
           'request\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Supplied Realm Name: '* *.' # "
           'Field names provided (under normal circumstances, provide the name '
           'of the field should be ABC, when there PYKEK attack, the field '
           'name has been provided for the ABC.COM)\n'
           '\xa0\xa0\xa0\xa0timeframe: last 5s\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Pass the Ticket': {'atomic_tests': [{'description': 'Similar '
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
                                             'attack_technique': 'T1097',
                                             'display_name': 'Pass the '
                                                             'Ticket'}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations

None

# Actors


* [Ke3chang](../actors/Ke3chang.md)

* [APT29](../actors/APT29.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [APT32](../actors/APT32.md)
    
