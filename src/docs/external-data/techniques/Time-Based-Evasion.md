
# Time Based Evasion

## Description

### MITRE Description

> Adversaries may employ various time-based methods to detect and avoid virtualization and analysis environments. This may include timers or other triggers to avoid a virtual machine environment (VME) or sandbox, specifically those that are automated or only operate for a limited amount of time.

Adversaries may employ various time-based evasions, such as delaying malware functionality upon initial execution using programmatic sleep commands or native system scheduling functionality (ex: [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)). Delays may also be based on waiting for specific victim conditions to be met (ex: system time, events, etc.) or employ scheduled [Multi-Stage Channels](https://attack.mitre.org/techniques/T1104) to avoid analysis and scrutiny. 

## Aliases

```

```

## Additional Attributes

* Bypass: ['Host forensic analysis', 'Signature-based detection', 'Static File Analysis', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1497/003

## Potential Commands

```
sleep 60
```

## Commands Dataset

```
[{'command': 'sleep 60',
  'name': 'Pause all operations to avoid making noise',
  'source': 'data/abilities/defense-evasion/36eecb80-ede3-442b-8774-956e906aff02.yml'},
 {'command': 'sleep 60',
  'name': 'Pause all operations to avoid making noise',
  'source': 'data/abilities/defense-evasion/36eecb80-ede3-442b-8774-956e906aff02.yml'},
 {'command': 'sleep 60',
  'name': 'Pause all operations to avoid making noise',
  'source': 'data/abilities/defense-evasion/36eecb80-ede3-442b-8774-956e906aff02.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - Pause all operations to avoid making noise': {'description': 'Pause '
                                                                                  'all '
                                                                                  'operations '
                                                                                  'to '
                                                                                  'avoid '
                                                                                  'making '
                                                                                  'noise',
                                                                   'id': '36eecb80-ede3-442b-8774-956e906aff02',
                                                                   'name': '1-min '
                                                                           'sleep',
                                                                   'platforms': {'darwin': {'sh': {'command': 'sleep '
                                                                                                              '60'}},
                                                                                 'linux': {'sh': {'command': 'sleep '
                                                                                                             '60'}},
                                                                                 'windows': {'psh': {'command': 'sleep '
                                                                                                                '60'}}},
                                                                   'tactic': 'defense-evasion',
                                                                   'technique': {'attack_id': 'T1497.003',
                                                                                 'name': 'Virtualization/Sandbox '
                                                                                         'Evasion: '
                                                                                         'Time '
                                                                                         'Based '
                                                                                         'Evasion'}}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Discovery](../tactics/Discovery.md)
    

# Mitigations

None

# Actors

None
