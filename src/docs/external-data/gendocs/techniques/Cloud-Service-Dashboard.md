
# Cloud Service Dashboard

## Description

### MITRE Description

> An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features. For example, the GCP Command Center can be used to view all assets, findings of potential security risks, and to run additional queries, such as finding public IP addresses and open ports.(Citation: Google Command Center Dashboard)

Depending on the configuration of the environment, an adversary may be able to enumerate more information via the graphical dashboard than an API. This allows the adversary to gain information without making any API requests.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['AWS', 'GCP', 'Azure', 'Azure AD', 'Office 365']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1538

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


* [User Account Management](../mitigations/User-Account-Management.md)


# Actors

None
