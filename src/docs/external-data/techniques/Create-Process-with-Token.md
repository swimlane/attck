
# Create Process with Token

## Description

### MITRE Description

> Adversaries may create a new process with a duplicated token to escalate privileges and bypass access controls. An adversary can duplicate a desired access token with <code>DuplicateToken(Ex)</code> and use it with <code>CreateProcessWithTokenW</code> to create a new process running under the security context of the impersonated user. This is useful for creating a new process under the security context of a different user.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Windows User Account Control', 'System access controls', 'File system access controls']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1134/002

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


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)

* [User Account Management](../mitigations/User-Account-Management.md)
    

# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

* [Turla](../actors/Turla.md)
    
