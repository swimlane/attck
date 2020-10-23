
# Python

## Description

### MITRE Description

> Adversaries may abuse Python commands and scripts for execution. Python is a very popular scripting/programming language, with capabilities to perform many functions. Python can be executed interactively from the command-line (via the <code>python.exe</code> interpreter) or via scripts (.py) that can be written and distributed to different systems. Python code can also be compiled into binary executables.

Python comes with many built-in packages to interact with the underlying system, such as file operations and device I/O. Adversaries can use these libraries to download and execute commands or other scripts as well as perform various malicious behaviors.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM', 'root']
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1059/006

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


* [Execution](../tactics/Execution.md)


# Mitigations


* [Limit Software Installation](../mitigations/Limit-Software-Installation.md)

* [Execution Prevention](../mitigations/Execution-Prevention.md)
    
* [Audit](../mitigations/Audit.md)
    
* [Antivirus/Antimalware](../mitigations/Antivirus-Antimalware.md)
    

# Actors


* [Machete](../actors/Machete.md)

* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [APT39](../actors/APT39.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Rocke](../actors/Rocke.md)
    
