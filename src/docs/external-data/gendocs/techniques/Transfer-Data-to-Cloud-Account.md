
# Transfer Data to Cloud Account

## Description

### MITRE Description

> Adversaries may exfiltrate data by transferring the data, including backups of cloud environments, to another cloud account they control on the same service to avoid typical file transfers/downloads and network-based exfiltration detection.

A defender who is monitoring for large transfers to outside the cloud environment through normal file transfers or over command and control channels may not be watching for data transfers to another account within the same cloud provider. Such transfers may utilize existing cloud provider APIs and the internal address space of the cloud provider to blend into normal traffic or avoid data transfers over external network interfaces.

Incidents have been observed where adversaries have created backups of cloud instances and transferred them to separate accounts.(Citation: DOJ GRU Indictment Jul 2018) 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: ['User']
* Platforms: ['Azure', 'AWS', 'GCP']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1537

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


* [Exfiltration](../tactics/Exfiltration.md)


# Mitigations


* [Filter Network Traffic](../mitigations/Filter-Network-Traffic.md)

* [User Account Management](../mitigations/User-Account-Management.md)
    
* [Password Policies](../mitigations/Password-Policies.md)
    

# Actors

None
