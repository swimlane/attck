
# Remote Service Session Hijacking

## Description

### MITRE Description

> Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service.

Adversaries may commandeer these sessions to carry out actions on remote systems. [Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563) differs from use of [Remote Services](https://attack.mitre.org/techniques/T1021) because it hijacks an existing session rather than creating a new session using [Valid Accounts](https://attack.mitre.org/techniques/T1078).(Citation: RDP Hijacking Medium)(Citation: Breach Post-mortem SSH Hijack)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['SYSTEM', 'root']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1563

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


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Network Segmentation](../mitigations/Network-Segmentation.md)
    
* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    

# Actors

None
