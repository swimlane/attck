
# Match Legitimate Name or Location

## Description

### MITRE Description

> Adversaries may match or approximate the name or location of legitimate files when naming/placing their files. This is done for the sake of evading defenses and observation. This may be done by placing an executable in a commonly trusted directory (ex: under System32) or giving it the name of a legitimate, trusted program (ex: svchost.exe). Alternatively, the filename given may be a close approximation of legitimate programs or something innocuous.

Adversaries may also use the same icon of the file they are trying to mimic.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application control by file name or path']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1036/005

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


* [Code Signing](../mitigations/Code-Signing.md)

* [Execution Prevention](../mitigations/Execution-Prevention.md)
    
* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    

# Actors


* [MuddyWater](../actors/MuddyWater.md)

* [Carbanak](../actors/Carbanak.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Poseidon Group](../actors/Poseidon-Group.md)
    
* [admin@338](../actors/admin@338.md)
    
* [APT1](../actors/APT1.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [APT32](../actors/APT32.md)
    
* [Sowbug](../actors/Sowbug.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [menuPass](../actors/menuPass.md)
    
* [APT41](../actors/APT41.md)
    
* [Silence](../actors/Silence.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Whitefly](../actors/Whitefly.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
* [APT39](../actors/APT39.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
* [Rocke](../actors/Rocke.md)
    
