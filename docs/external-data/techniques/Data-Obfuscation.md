
# Data Obfuscation

## Description

### MITRE Description

> Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, commingling legitimate traffic with C2 communications traffic, or using a non-standard data encoding system, such as a modified Base64 encoding for the message body of an HTTP request.

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

None

# Actors


* [APT28](../actors/APT28.md)

* [Axiom](../actors/Axiom.md)
    
