
# Indicator Removal from Tools

## Description

### MITRE Description

> If a malicious tool is detected and quarantined or otherwise curtailed, an adversary may be able to determine why the malicious tool was detected (the indicator), modify the tool by removing the indicator, and use the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems.

A good example of this is when malware is detected with a file signature and quarantined by anti-virus software. An adversary who can determine that the malware was quarantined because of its file signature may use [Software Packing](https://attack.mitre.org/techniques/T1045) or otherwise modify the file so it has a different signature, and then re-use the malware.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Log analysis', 'Host intrusion prevention systems', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
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
[{'data_source': {'author': 'Thomas Patzke',
                  'description': 'Detects renaming of file while deletion with '
                                 'SDelete tool',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': [4656, 4663, 4658],
                                              'ObjectName': ['*.AAA',
                                                             '*.ZZZ']}},
                  'falsepositives': ['Legitime usage of SDelete'],
                  'id': '39a80702-d7ca-4a83-b776-525b1f86a36d',
                  'level': 'medium',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'references': ['https://jpcertcc.github.io/ToolAnalysisResultSheet',
                                 'https://www.jpcert.or.jp/english/pub/sr/ir_research.html',
                                 'https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.t1107',
                           'attack.t1066',
                           'attack.s0195'],
                  'title': 'Secure Deletion with SDelete'}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['Anti-virus']},
 {'data_source': ['B9', 'Binary file metadata']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['LOG-MD - B9', 'Binary file metadata']},
 {'data_source': ['Anti-virus']}]
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
    
