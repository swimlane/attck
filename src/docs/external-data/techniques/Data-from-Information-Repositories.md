
# Data from Information Repositories

## Description

### MITRE Description

> Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a wide variety of data that may aid adversaries in further objectives, or direct access to the target information.

Adversaries may also collect information from shared storage repositories hosted on cloud infrastructure or in software-as-a-service (SaaS) applications, as storage is one of the more fundamental requirements for cloud services and systems.

The following is a brief list of example information that may hold potential value to an adversary and may also be found on an information repository:

* Policies, procedures, and standards
* Physical / logical network diagrams
* System architecture diagrams
* Technical system documentation
* Testing / development credentials
* Work / project schedules
* Source code snippets
* Links to network shares and other internal resources

Specific common information repositories include:

### Microsoft SharePoint
Found in many enterprise networks and often used to store and share significant amounts of documentation.

### Atlassian Confluence
Often found in development environments alongside Atlassian JIRA, Confluence is generally used to store development-related documentation.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'Windows', 'macOS', 'SaaS', 'AWS', 'GCP', 'Azure']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1213

## Potential Commands

```
powershell/situational_awareness/host/findtrusteddocuments
powershell/situational_awareness/host/findtrusteddocuments
```

## Commands Dataset

```
[{'command': 'powershell/situational_awareness/host/findtrusteddocuments',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/host/findtrusteddocuments',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1213',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/host/findtrusteddocuments":  '
                                                                                 '["T1213"],',
                                            'Empire Module': 'powershell/situational_awareness/host/findtrusteddocuments',
                                            'Technique': 'Data from '
                                                         'Information '
                                                         'Repositories'}}]
```

# Tactics


* [Collection](../tactics/Collection.md)


# Mitigations

None

# Actors


* [APT28](../actors/APT28.md)

* [Ke3chang](../actors/Ke3chang.md)
    
