
# Resource Hijacking

## Description

### MITRE Description

> Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems which may impact system and/or hosted service availability. 

One common purpose for Resource Hijacking is to validate transactions of cryptocurrency networks and earn virtual currency. Adversaries may consume enough system resources to negatively impact and/or cause affected machines to become unresponsive.(Citation: Kaspersky Lazarus Under The Hood Blog 2017) Servers and cloud-based(Citation: CloudSploit - Unused AWS Regions) systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for Resource Hijacking and cryptocurrency mining.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1496

## Potential Commands

```
yes > /dev/null

{'darwin': {'sh': {'command': 'brew install sox >/dev/null 2>&1;\nsox -d recording.wav trim 0 15 >/dev/null 2>&1;\n', 'timeout': 120}}}
```

## Commands Dataset

```
[{'command': 'yes > /dev/null\n',
  'name': None,
  'source': 'atomics/T1496/T1496.yaml'},
 {'command': {'darwin': {'sh': {'command': 'brew install sox >/dev/null 2>&1;\n'
                                           'sox -d recording.wav trim 0 15 '
                                           '>/dev/null 2>&1;\n',
                                'timeout': 120}}},
  'name': 'Install sox and record microphone for n-seconds',
  'source': 'data/abilities/impact/78524da1-f347-4fbb-9295-209f1f408330.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Resource Hijacking': {'atomic_tests': [{'auto_generated_guid': '904a5a0e-fb02-490d-9f8d-0e256eb37549',
                                                                  'description': 'This '
                                                                                 'test '
                                                                                 'simulates '
                                                                                 'a '
                                                                                 'high '
                                                                                 'CPU '
                                                                                 'load '
                                                                                 'as '
                                                                                 'you '
                                                                                 'might '
                                                                                 'observe '
                                                                                 'during '
                                                                                 'cryptojacking '
                                                                                 'attacks.\n'
                                                                                 'End '
                                                                                 'the '
                                                                                 'test '
                                                                                 'by '
                                                                                 'using '
                                                                                 'CTRL/CMD+C '
                                                                                 'to '
                                                                                 'break.\n',
                                                                  'executor': {'command': 'yes '
                                                                                          '> '
                                                                                          '/dev/null\n',
                                                                               'name': 'bash'},
                                                                  'name': 'macOS/Linux '
                                                                          '- '
                                                                          'Simulate '
                                                                          'CPU '
                                                                          'Load '
                                                                          'with '
                                                                          'Yes',
                                                                  'supported_platforms': ['macos',
                                                                                          'linux']}],
                                                'attack_technique': 'T1496',
                                                'display_name': 'Resource '
                                                                'Hijacking'}},
 {'Mitre Stockpile - Install sox and record microphone for n-seconds': {'description': 'Install '
                                                                                       'sox '
                                                                                       'and '
                                                                                       'record '
                                                                                       'microphone '
                                                                                       'for '
                                                                                       'n-seconds',
                                                                        'id': '78524da1-f347-4fbb-9295-209f1f408330',
                                                                        'name': 'Record '
                                                                                'microphone',
                                                                        'platforms': {'darwin': {'sh': {'command': 'brew '
                                                                                                                   'install '
                                                                                                                   'sox '
                                                                                                                   '>/dev/null '
                                                                                                                   '2>&1;\n'
                                                                                                                   'sox '
                                                                                                                   '-d '
                                                                                                                   'recording.wav '
                                                                                                                   'trim '
                                                                                                                   '0 '
                                                                                                                   '15 '
                                                                                                                   '>/dev/null '
                                                                                                                   '2>&1;\n',
                                                                                                        'timeout': 120}}},
                                                                        'tactic': 'impact',
                                                                        'technique': {'attack_id': 'T1496',
                                                                                      'name': 'Resource '
                                                                                              'Hijacking'}}}]
```

# Tactics


* [Impact](../tactics/Impact.md)


# Mitigations


* [Resource Hijacking Mitigation](../mitigations/Resource-Hijacking-Mitigation.md)


# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

* [APT41](../actors/APT41.md)
    
* [Rocke](../actors/Rocke.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
