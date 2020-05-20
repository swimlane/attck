
# External Remote Services

## Description

### MITRE Description

> Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1028) can also be used externally.

Adversaries may use remote services to initially access and/or persist within a network. (Citation: Volexity Virtual Private Keylogging) Access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network. Access to remote services may be used as part of [Redundant Access](https://attack.mitre.org/techniques/T1108) during an operation.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
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

None

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
    
