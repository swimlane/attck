
# Data Transfer Size Limits

## Description

### MITRE Description

> An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1030

## Potential Commands

```
cd /tmp/
dd if=/dev/urandom of=/tmp/victim-whole-file bs=25M count=1
split -b 5000000 /tmp/victim-whole-file
ls -l

```

## Commands Dataset

```
[{'command': 'cd /tmp/\n'
             'dd if=/dev/urandom of=/tmp/victim-whole-file bs=25M count=1\n'
             'split -b 5000000 /tmp/victim-whole-file\n'
             'ls -l\n',
  'name': None,
  'source': 'atomics/T1030/T1030.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Data Transfer Size Limits': {'atomic_tests': [{'description': 'Take '
                                                                                        'a '
                                                                                        'file/directory, '
                                                                                        'split '
                                                                                        'it '
                                                                                        'into '
                                                                                        '5Mb '
                                                                                        'chunks\n',
                                                                         'executor': {'command': 'cd '
                                                                                                 '/tmp/\n'
                                                                                                 'dd '
                                                                                                 'if=/dev/urandom '
                                                                                                 'of=/tmp/victim-whole-file '
                                                                                                 'bs=25M '
                                                                                                 'count=1\n'
                                                                                                 'split '
                                                                                                 '-b '
                                                                                                 '5000000 '
                                                                                                 '/tmp/victim-whole-file\n'
                                                                                                 'ls '
                                                                                                 '-l\n',
                                                                                      'elevation_required': False,
                                                                                      'name': 'sh'},
                                                                         'name': 'Data '
                                                                                 'Transfer '
                                                                                 'Size '
                                                                                 'Limits',
                                                                         'supported_platforms': ['macos',
                                                                                                 'linux']}],
                                                       'attack_technique': 'T1030',
                                                       'display_name': 'Data '
                                                                       'Transfer '
                                                                       'Size '
                                                                       'Limits'}}]
```

# Tactics


* [Exfiltration](../tactics/Exfiltration.md)


# Mitigations

None

# Actors


* [Threat Group-3390](../actors/Threat-Group-3390.md)

