
# Data from Removable Media

## Description

### MITRE Description

> Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration.

Adversaries may search connected removable media on computers they have compromised to find files of interest. Interactive command shells may be in use, and common functionality within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information. Some adversaries may also use [Automated Collection](https://attack.mitre.org/techniques/T1119) on removable media.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1025

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

```

## Raw Dataset

```json

```

# Tactics


* [Collection](../tactics/Collection.md)


# Mitigations

None

# Actors


* [APT28](../actors/APT28.md)

* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
* [Turla](../actors/Turla.md)
    
* [Machete](../actors/Machete.md)
    
