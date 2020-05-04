
# Indicator Removal from Tools

## Description

### MITRE Description

> If a malicious tool is detected and quarantined or otherwise curtailed, an adversary may be able to determine why the malicious tool was detected (the indicator), modify the tool by removing the indicator, and use the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems.

A good example of this is when malware is detected with a file signature and quarantined by anti-virus software. An adversary who can determine that the malware was quarantined because of its file signature may use [Software Packing](https://attack.mitre.org/techniques/T1045) or otherwise modify the file so it has a different signature, and then re-use the malware.

## Additional Attributes

* Bypass: ['Log analysis', 'Host intrusion prevention systems', 'Anti-virus']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1066

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


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [Deep Panda](../actors/Deep-Panda.md)

* [Patchwork](../actors/Patchwork.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Turla](../actors/Turla.md)
    
* [APT3](../actors/APT3.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
