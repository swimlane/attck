
# Additional Azure Service Principal Credentials

## Description

### MITRE Description

> Adversaries may add adversary-controlled credentials for Azure Service Principals in addition to existing legitimate credentials(Citation: Create Azure Service Principal) to maintain persistent access to victim Azure accounts.(Citation: Blue Cloud of Death)(Citation: Blue Cloud of Death Video) Azure Service Principals support both password and certificate credentials.(Citation: Why AAD Service Principals) With sufficient permissions, there are a variety of ways to add credentials including the Azure Portal, Azure command line interface, and Azure or Az [PowerShell](https://attack.mitre.org/techniques/T1059/001) modules.(Citation: Demystifying Azure AD Service Principals)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Azure AD', 'Azure']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1098/001

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


* [Persistence](../tactics/Persistence.md)


# Mitigations


* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)

* [Network Segmentation](../mitigations/Network-Segmentation.md)
    
* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)
    

# Actors

None
