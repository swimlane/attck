
# Scheduled Transfer

## Description

### MITRE Description

> Data exfiltration may be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability.

When scheduled exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as Exfiltration Over Command and Control Channel and Exfiltration Over Alternative Protocol.

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
* Wiki: https://attack.mitre.org/techniques/T1029

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
 {'data_source': ['100-200', 'Scheduled Tasks']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['100-200', 'Scheduled Tasks']},
 {'data_source': ['Netflow/Enclave netflow']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Exfiltration](../tactics/Exfiltration.md)


# Mitigations

None

# Actors

None
