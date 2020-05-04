
# Code Signing

## Description

### MITRE Description

> Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. (Citation: Wikipedia Code Signing) However, adversaries are known to use code signing certificates to masquerade malware and tools as legitimate binaries (Citation: Janicab). The certificates used during an operation may be created, forged, or stolen by the adversary. (Citation: Securelist Digital Certificates) (Citation: Symantec Digital Certificates)

Code signing to verify software on first run can be used on modern Windows and macOS/OS X systems. It is not used on Linux due to the decentralized nature of the platform. (Citation: Wikipedia Code Signing)

Code signing certificates may be used to bypass security policies that require signed code to execute on a system.

## Additional Attributes

* Bypass: ['Windows User Account Control']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1116

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


* [FIN7](../actors/FIN7.md)

* [Darkhotel](../actors/Darkhotel.md)
    
* [Winnti Group](../actors/Winnti-Group.md)
    
* [CopyKittens](../actors/CopyKittens.md)
    
* [Molerats](../actors/Molerats.md)
    
* [APT37](../actors/APT37.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [Suckfly](../actors/Suckfly.md)
    
* [TA505](../actors/TA505.md)
    
* [FIN6](../actors/FIN6.md)
    
* [APT41](../actors/APT41.md)
    
