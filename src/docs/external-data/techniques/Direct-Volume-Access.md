
# Direct Volume Access

## Description

### MITRE Description

> Adversaries may directly access a volume to bypass file access controls and file system monitoring. Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique bypasses Windows file access controls as well as file system monitoring tools. (Citation: Hakobyan 2009)

Utilities, such as NinjaCopy, exist to perform these actions in PowerShell. (Citation: Github PowerSploit Ninjacopy)

## Aliases

```

```

## Additional Attributes

* Bypass: ['File monitoring', 'File system access controls']
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: None
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
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['200-500', ' 4100-4104', 'PowerShell logs']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['200-500', ' 4100-4104', 'PowerShell logs']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['API monitoring']}]
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


* [File System Logical Offsets Mitigation](../mitigations/File-System-Logical-Offsets-Mitigation.md)


# Actors

None
