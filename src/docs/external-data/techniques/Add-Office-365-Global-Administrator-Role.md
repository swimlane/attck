
# Add Office 365 Global Administrator Role

## Description

### MITRE Description

> An adversary may add the Global Administrator role to an adversary-controlled account to maintain persistent access to an Office 365 tenant.(Citation: Microsoft Support O365 Add Another Admin, October 2019)(Citation: Microsoft O365 Admin Roles) With sufficient permissions, a compromised account can gain almost unlimited access to data and settings (including the ability to reset the passwords of other admins) via the global admin role.(Citation: Microsoft O365 Admin Roles) 

This account modification may immediately follow [Create Account](https://attack.mitre.org/techniques/T1136) or other malicious account activity.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Office 365']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1098/003

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

* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)
    

# Actors

None
