
# Man-in-the-Middle

## Description

### MITRE Description

> Adversaries may attempt to position themselves between two or more networked devices using a man-in-the-middle (MiTM) technique to support follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040) or [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002). By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.(Citation: Rapid7 MiTM Basics)

Adversaries may leverage the MiTM position to attempt to modify traffic, such as in [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002). Adversaries can also stop traffic from flowing to the appropriate destination, causing denial of service.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows', 'macOS', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1557

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


* [Collection](../tactics/Collection.md)

* [Credential Access](../tactics/Credential-Access.md)
    

# Mitigations


* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)

* [Filter Network Traffic](../mitigations/Filter-Network-Traffic.md)
    
* [Limit Access to Resource Over Network](../mitigations/Limit-Access-to-Resource-Over-Network.md)
    
* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)
    
* [Network Segmentation](../mitigations/Network-Segmentation.md)
    

# Actors

None
