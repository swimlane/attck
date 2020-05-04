
# SID-History Injection

## Description

### MITRE Description

> The Windows security identifier (SID) is a unique value that identifies a user or group account. SIDs are used by Windows security in both security descriptors and access tokens. (Citation: Microsoft SID) An account can hold additional SIDs in the SID-History Active Directory attribute (Citation: Microsoft SID-History Attribute), allowing inter-operable account migration between domains (e.g., all values in SID-History are included in access tokens).

Adversaries may use this mechanism for privilege escalation. With Domain Administrator (or equivalent) rights, harvested or well-known SID values (Citation: Microsoft Well Known SIDs Jun 2017) may be inserted into SID-History to enable impersonation of arbitrary users/groups such as Enterprise Administrators. This manipulation may result in elevated access to local resources and/or access to otherwise inaccessible domains via lateral movement techniques such as [Remote Services](https://attack.mitre.org/techniques/T1021), [Windows Admin Shares](https://attack.mitre.org/techniques/T1077), or [Windows Remote Management](https://attack.mitre.org/techniques/T1028).

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1178

## Potential Commands

```
powershell/persistence/misc/add_sid_history
powershell/persistence/misc/add_sid_history
```

## Commands Dataset

```
[{'command': 'powershell/persistence/misc/add_sid_history',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/misc/add_sid_history',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: Windows SID History permission to create a domain '
           'controller back door\n'
           'description: domain environment test\n'
           'references: https://adsecurity.org/?p=1772\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0--4766 # attempt to add SID '
           'History to an account failed.\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0--4765 # SID history has been '
           'added to the account.\n'
           '\xa0\xa0\xa0\xa0condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1178',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/misc/add_sid_history":  '
                                                                                 '["T1178"],',
                                            'Empire Module': 'powershell/persistence/misc/add_sid_history',
                                            'Technique': 'SID-History '
                                                         'Injection'}}]
```

# Tactics


* [Privilege Escalation](../tactics/Privilege-Escalation.md)


# Mitigations

None

# Actors

None
