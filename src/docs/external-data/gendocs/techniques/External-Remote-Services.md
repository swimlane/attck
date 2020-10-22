
# External Remote Services

## Description

### MITRE Description

> Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) can also be used externally.

Access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.(Citation: Volexity Virtual Private Keylogging) Access to remote services may be used as a redundant or persistent access mechanism during an operation.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1133

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['4624', 'Authentication logs']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Initial Access](../tactics/Initial-Access.md)

* [Persistence](../tactics/Persistence.md)
    

# Mitigations


* [External Remote Services Mitigation](../mitigations/External-Remote-Services-Mitigation.md)

* [Limit Access to Resource Over Network](../mitigations/Limit-Access-to-Resource-Over-Network.md)
    
* [Network Segmentation](../mitigations/Network-Segmentation.md)
    
* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    
* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)
    

# Actors


* [APT18](../actors/APT18.md)

* [OilRig](../actors/OilRig.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [FIN5](../actors/FIN5.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
