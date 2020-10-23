
# Commonly Used Port

## Description

### MITRE Description

> **This technique has been deprecated. Please use [Non-Standard Port](https://attack.mitre.org/techniques/T1571) where appropriate.**

Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection. They may use commonly open ports such as

* TCP:80 (HTTP)
* TCP:443 (HTTPS)
* TCP:25 (SMTP)
* TCP/UDP:53 (DNS)

They may use the protocol associated with the port or a completely different protocol. 

For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), examples of common ports are 

* TCP/UDP:135 (RPC)
* TCP/UDP:22 (SSH)
* TCP/UDP:3389 (RDP)

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
* Wiki: https://attack.mitre.org/techniques/T1043

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


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations


* [Commonly Used Port Mitigation](../mitigations/Commonly-Used-Port-Mitigation.md)

* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)
    
* [Network Segmentation](../mitigations/Network-Segmentation.md)
    

# Actors


* [Magic Hound](../actors/Magic-Hound.md)

* [FIN8](../actors/FIN8.md)
    
* [APT19](../actors/APT19.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT37](../actors/APT37.md)
    
* [APT3](../actors/APT3.md)
    
* [APT18](../actors/APT18.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [FIN7](../actors/FIN7.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [APT29](../actors/APT29.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [APT28](../actors/APT28.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Machete](../actors/Machete.md)
    
