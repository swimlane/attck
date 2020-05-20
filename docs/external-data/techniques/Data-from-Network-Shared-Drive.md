
# Data from Network Shared Drive

## Description

### MITRE Description

> Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration.

Adversaries may search network shares on computers they have compromised to find files of interest. Interactive command shells may be in use, and common functionality within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1039

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5140/5145', 'Share connection']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5140/5145', 'Share connection']},
 {'data_source': ['4663', 'File monitoring']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Collection](../tactics/Collection.md)


# Mitigations

None

# Actors


* [menuPass](../actors/menuPass.md)

* [Sowbug](../actors/Sowbug.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
