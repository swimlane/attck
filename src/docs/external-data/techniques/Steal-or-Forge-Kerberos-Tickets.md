
# Steal or Forge Kerberos Tickets

## Description

### MITRE Description

> Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003). 

Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as “realms”, there are three basic participants: client, service, and Key Distribution Center (KDC).(Citation: ADSecurity Kerberos Ring Decoder) Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated. The KDC is responsible for both authentication and ticket granting.  Attackers may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access.

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
* Wiki: https://attack.mitre.org/techniques/T1558

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: kerberos weak encryption\n'
           'description: domain environment test\n'
           'references: https://adsecurity.org/?p=3458\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection:\n'
           '        EventID: 4769 #kerberos Service Ticket Request\n'
           '        TicketOptions: 0x40810000 # Additional information> Ticket '
           'Options\n'
           '        TicketEncryptiontype: 0x17 # Additional information> '
           'Ticket Encryption Type\n'
           '    reduction:\n'
           "        - ServiceName: '$ *' # service name> service information\n"
           '    condition: selection and not reduction\n'
           'level: medium'}]
```

## Raw Dataset

```json

```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Password Policies](../mitigations/Password-Policies.md)

* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)
    
* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Active Directory Configuration](../mitigations/Active-Directory-Configuration.md)
    

# Actors

None
