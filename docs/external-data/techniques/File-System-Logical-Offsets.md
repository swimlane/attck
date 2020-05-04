
# File System Logical Offsets

## Description

### MITRE Description

> Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique bypasses Windows file access controls as well as file system monitoring tools. (Citation: Hakobyan 2009)

Utilities, such as NinjaCopy, exist to perform these actions in PowerShell. (Citation: Github PowerSploit Ninjacopy)

## Additional Attributes

* Bypass: ['File monitoring', 'File system access controls']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1006

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

None
