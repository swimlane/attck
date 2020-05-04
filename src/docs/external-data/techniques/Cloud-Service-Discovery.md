
# Cloud Service Discovery

## Description

### MITRE Description

> An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ depending on if it's platform-as-a-service (PaaS), infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS). Many different services exist throughout the various cloud providers and can include continuous integration and continuous delivery (CI/CD), Lambda Functions, Azure AD, etc. Adversaries may attempt to discover information about the services enabled throughout the environment.

Pacu, an open source AWS exploitation framework, supports several methods for discovering cloud services.(Citation: GitHub Pacu)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['AWS', 'GCP', 'Azure', 'Azure AD', 'Office 365', 'SaaS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1526

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


* [Discovery](../tactics/Discovery.md)


# Mitigations

None

# Actors

None
