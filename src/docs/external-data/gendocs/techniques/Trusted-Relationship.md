
# Trusted Relationship

## Description

### MITRE Description

> Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship exploits an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.

Organizations often grant elevated access to second or third-party external providers in order to allow them to manage internal systems as well as cloud-based environments. Some examples of these relationships include IT services contractors, managed security providers, infrastructure contractors (e.g. HVAC, elevators, physical security). The third-party provider's access may be intended to be limited to the infrastructure being maintained, but may exist on the same network as the rest of the enterprise. As such, [Valid Accounts](https://attack.mitre.org/techniques/T1078) used by the other party for access to internal network systems may be compromised and used.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'Windows', 'macOS', 'AWS', 'GCP', 'Azure', 'SaaS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1199

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['Application Logs']},
 {'data_source': ['Authentication logs']},
 {'data_source': ['Third-party application logs']},
 {'data_source': ['Application Logs']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['Third-party application logs']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Initial Access](../tactics/Initial-Access.md)


# Mitigations


* [Trusted Relationship Mitigation](../mitigations/Trusted-Relationship-Mitigation.md)

* [User Account Control](../mitigations/User-Account-Control.md)
    
* [Network Segmentation](../mitigations/Network-Segmentation.md)
    

# Actors


* [menuPass](../actors/menuPass.md)

* [APT28](../actors/APT28.md)
    
