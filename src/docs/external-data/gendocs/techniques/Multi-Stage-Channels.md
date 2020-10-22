
# Multi-Stage Channels

## Description

### MITRE Description

> Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult.

Remote access tools will call back to the first-stage command and control server for instructions. The first stage may have automated capabilities to collect basic host information, update tools, and upload additional files. A second remote access tool (RAT) could be uploaded at that point to redirect the host to the second-stage command and control server. The second stage will likely be more fully featured and allow the adversary to interact with the system through a reverse shell and additional RAT features.

The different stages will likely be hosted separately with no overlapping infrastructure. The loader may also have backup first-stage callbacks or [Fallback Channels](https://attack.mitre.org/techniques/T1008) in case the original first-stage communication path is discovered and blocked.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1104

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['Network device logs']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['Network device logs']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations


* [Multi-Stage Channels Mitigation](../mitigations/Multi-Stage-Channels-Mitigation.md)

* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)
    

# Actors


* [APT3](../actors/APT3.md)

* [MuddyWater](../actors/MuddyWater.md)
    
* [APT41](../actors/APT41.md)
    
