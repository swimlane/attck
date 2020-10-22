
# Data Obfuscation

## Description

### MITRE Description

> Adversaries may obfuscate command and control traffic to make it more difficult to detect. Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols. 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1001

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['FW Logs']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['Packet capture']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['FW Logs']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['Packet capture']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations


* [Data Obfuscation Mitigation](../mitigations/Data-Obfuscation-Mitigation.md)

* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)
    

# Actors


* [Axiom](../actors/Axiom.md)

