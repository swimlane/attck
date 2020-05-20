
# LLMNR/NBT-NS Poisoning and Relay

## Description

### MITRE Description

> Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. NBT-NS identifies systems on a local network by their NetBIOS name. (Citation: Wikipedia LLMNR) (Citation: TechNet NetBIOS)

Adversaries can spoof an authoritative source for name resolution on a victim network by responding to LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic as if they know the identity of the requested host, effectively poisoning the service so that the victims will communicate with the adversary controlled system. If the requested host belongs to a resource that requires identification/authentication, the username and NTLMv2 hash will then be sent to the adversary controlled system. The adversary can then collect the hash information sent over the wire through tools that monitor the ports for traffic or through [Network Sniffing](https://attack.mitre.org/techniques/T1040) and crack the hashes offline through [Brute Force](https://attack.mitre.org/techniques/T1110) to obtain the plaintext passwords. In some cases where an adversary has access to a system that is in the authentication path between systems or when automated scans that use credentials attempt to authenticate to an adversary controlled system, the NTLMv2 hashes can be intercepted and relayed to access and execute code against a target system. The relay step can happen in conjunction with poisoning but may also be independent of it. (Citation: byt3bl33d3r NTLM Relaying)(Citation: Secure Ideas SMB Relay)

Several tools exist that can be used to poison name services within local networks such as NBNSpoof, Metasploit, and [Responder](https://attack.mitre.org/software/S0174). (Citation: GitHub NBNSpoof) (Citation: Rapid7 LLMNR Spoofer) (Citation: GitHub Responder)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1171

## Potential Commands

```
powershell/collection/inveigh
powershell/collection/inveigh
powershell/lateral_movement/inveigh_relay
powershell/lateral_movement/inveigh_relay
```

## Commands Dataset

```
[{'command': 'powershell/collection/inveigh',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/inveigh',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/lateral_movement/inveigh_relay',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/lateral_movement/inveigh_relay',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': '@SBousseaden, Florian Roth',
                  'date': '2019/11/15',
                  'description': 'Detects logon events that have '
                                 'characteristics of events generated during '
                                 'an attack with RottenPotato and the like',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 4624,
                                              'LogonType': 3,
                                              'SourceNetworkAddress': '127.0.0.1',
                                              'TargetUserName': 'ANONYMOUS_LOGON',
                                              'WorkstationName': '-'}},
                  'falsepositives': ['Unknown'],
                  'id': '16f5d8ca-44bd-47c8-acbe-6fc95a16c12f',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'references': ['https://twitter.com/SBousseaden/status/1195284233729777665'],
                  'status': 'experimental',
                  'tags': ['attack.privilege_escalation',
                           'attack.credential_access',
                           'attack.t1171'],
                  'title': 'RottenPotato Like Attack Pattern'}},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1171',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/inveigh":  '
                                                                                 '["T1171"],',
                                            'Empire Module': 'powershell/collection/inveigh',
                                            'Technique': 'LLMNR/NBT-NS '
                                                         'Poisoning'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1171',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/lateral_movement/inveigh_relay":  '
                                                                                 '["T1171"],',
                                            'Empire Module': 'powershell/lateral_movement/inveigh_relay',
                                            'Technique': 'LLMNR/NBT-NS '
                                                         'Poisoning'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations

None

# Actors

None
