
# Custom Command and Control Protocol

## Description

### MITRE Description

> Adversaries may communicate using a custom command and control protocol instead of encapsulating commands/data in an existing [Standard Application Layer Protocol](https://attack.mitre.org/techniques/T1071). Implementations include mimicking well-known protocols or developing custom protocols (including raw sockets) on top of fundamental protocols provided by TCP/IP/another standard network stack.

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
* Wiki: https://attack.mitre.org/techniques/T1094

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']}]
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


* [OilRig](../actors/OilRig.md)

* [PLATINUM](../actors/PLATINUM.md)
    
* [APT37](../actors/APT37.md)
    
* [APT32](../actors/APT32.md)
    
