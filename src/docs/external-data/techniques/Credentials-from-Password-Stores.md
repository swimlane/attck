
# Credentials from Password Stores

## Description

### MITRE Description

> Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications that store passwords to make it easier for users manage and maintain. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1555

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
           'title: windows system web browser to obtain the voucher\n'
           'description: windows server 2016 test results\n'
           'references: No\n'
           'tags: T1555-003\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection:\n'
           '        EventID: 4663 # trying to access the object.\n'
           '        Objectserver: Security # Object> Object Server\n'
           '        Objecttype: file # Object> Object Type\n'
           '        Objectname:\n'
           "           - 'C: \\ users \\ * \\ appdata \\ roaming \\ opera "
           "software \\ opera stable \\ login data' # Object> object name "
           'Opera\n'
           "           - 'C: \\ Users \\ IEUser \\ AppData \\ Roaming \\ "
           "Mozilla \\ Firefox \\ Profiles \\ kushu3sd.default \\ key4.db' "
           '#Firefox\n'
           "           - 'C: \\ Users \\ IEUser \\ AppData \\ Roaming \\ "
           "Mozilla \\ Firefox \\ Profiles \\ kushu3sd.default \\ logins.json' "
           '#Firefox\n'
           "           - 'C: \\ Users \\ IEUser \\ AppData \\ Local \\ Google "
           "\\ Chrome \\ User Data \\ Default \\ Login Data' #Chrome\n"
           '        Access: ReadData (or listdirectory) # access request '
           'information> Access\n'
           '    condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json

```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Password Policies](../mitigations/Password-Policies.md)


# Actors


* [Stealth Falcon](../actors/Stealth-Falcon.md)

* [Turla](../actors/Turla.md)
    
* [APT33](../actors/APT33.md)
    
* [Leafminer](../actors/Leafminer.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [OilRig](../actors/OilRig.md)
    
* [APT39](../actors/APT39.md)
    
