
# Redundant Access

## Description

### MITRE Description

> **This technique has been deprecated. Please use [Create Account](https://attack.mitre.org/techniques/T1136), [Web Shell](https://attack.mitre.org/techniques/T1505/003), and [External Remote Services](https://attack.mitre.org/techniques/T1133) where appropriate.**

Adversaries may use more than one remote access tool with varying command and control protocols or credentialed access to remote services so they can maintain access if an access mechanism is detected or mitigated. 

If one type of tool is detected and blocked or removed as a response but the organization did not gain a full understanding of the adversary's tools and access, then the adversary will be able to retain access to the network. Adversaries may also attempt to gain access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use [External Remote Services](https://attack.mitre.org/techniques/T1133) such as external VPNs as a way to maintain access despite interruptions to remote access tools deployed within a target network.(Citation: Mandiant APT1) Adversaries may also retain access through cloud-based infrastructure and applications.

Use of a [Web Shell](https://attack.mitre.org/techniques/T1100) is one such way to maintain access to a network through an externally accessible Web server.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Network intrusion detection system', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure', 'Office 365', 'SaaS', 'Azure AD']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1108

## Potential Commands

```
powershell/persistence/misc/skeleton_key
powershell/persistence/misc/skeleton_key
powershell/persistence/powerbreach/deaduser
powershell/persistence/powerbreach/deaduser
powershell/persistence/powerbreach/eventlog
powershell/persistence/powerbreach/eventlog
powershell/persistence/powerbreach/resolver
powershell/persistence/powerbreach/resolver
```

## Commands Dataset

```
[{'command': 'powershell/persistence/misc/skeleton_key',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/misc/skeleton_key',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/powerbreach/deaduser',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/powerbreach/deaduser',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/powerbreach/eventlog',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/powerbreach/eventlog',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/powerbreach/resolver',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/powerbreach/resolver',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Login - 4624', 'Auth Logs']},
 {'data_source': ['LMD - B9', 'Binary file metadata']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['Packet capture']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Login - 4624', 'Auth Logs']},
 {'data_source': ['LOG-MD - B9', 'Binary file metadata']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['Packet capture']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1108',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/misc/skeleton_key":  '
                                                                                 '["T1108"],',
                                            'Empire Module': 'powershell/persistence/misc/skeleton_key',
                                            'Technique': 'Redundant Access'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1108',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/powerbreach/deaduser":  '
                                                                                 '["T1108"],',
                                            'Empire Module': 'powershell/persistence/powerbreach/deaduser',
                                            'Technique': 'Redundant Access'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1108',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/powerbreach/eventlog":  '
                                                                                 '["T1108"],',
                                            'Empire Module': 'powershell/persistence/powerbreach/eventlog',
                                            'Technique': 'Redundant Access'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1108',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/powerbreach/resolver":  '
                                                                                 '["T1108"],',
                                            'Empire Module': 'powershell/persistence/powerbreach/resolver',
                                            'Technique': 'Redundant Access'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Persistence](../tactics/Persistence.md)
    

# Mitigations


* [Redundant Access Mitigation](../mitigations/Redundant-Access-Mitigation.md)

* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)
    

# Actors

None
