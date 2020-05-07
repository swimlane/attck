
# Bootkit

## Description

### MITRE Description

> A bootkit is a malware variant that modifies the boot sectors of a hard drive, including the Master Boot Record (MBR) and Volume Boot Record (VBR). (Citation: MTrends 2016)

Adversaries may use bootkits to persist on systems at a layer below the operating system, which may make it difficult to perform full remediation unless an organization suspects one was used and can act accordingly.

### Master Boot Record
The MBR is the section of disk that is first loaded after completing hardware initialization by the BIOS. It is the location of the boot loader. An adversary who has raw access to the boot drive may overwrite this area, diverting execution during startup from the normal boot loader to adversary code. (Citation: Lau 2011)

### Volume Boot Record
The MBR passes control of the boot process to the VBR. Similar to the case of MBR, an adversary who has raw access to the boot drive may overwrite the VBR to divert execution during startup to adversary code.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Linux', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1067

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': {'author': '@neu5ron',
                  'date': '2019/02/07',
                  'description': 'Detects, possibly, malicious unauthorized '
                                 'usage of bcdedit.exe',
                  'detection': {'condition': 'selection',
                                'selection': {'NewProcessName': '*\\bcdedit.exe',
                                              'ProcessCommandLine': ['*delete*',
                                                                     '*deletevalue*',
                                                                     '*import*']}},
                  'id': 'c9fbe8e9-119d-40a6-9b59-dd58a5d84429',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.t1070',
                           'attack.persistence',
                           'attack.t1067'],
                  'title': 'Possible Ransomware or unauthorized MBR '
                           'modifications'}}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

* [APT28](../actors/APT28.md)
    
* [APT41](../actors/APT41.md)
    
