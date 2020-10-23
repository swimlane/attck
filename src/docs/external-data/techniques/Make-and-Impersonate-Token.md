
# Make and Impersonate Token

## Description

### MITRE Description

> Adversaries may make and impersonate tokens to escalate privileges and bypass access controls. If an adversary has a username and password but the user is not logged onto the system, the adversary can then create a logon session for the user using the <code>LogonUser</code> function. The function will return a copy of the new session's access token and the adversary can use <code>SetThreadToken</code> to assign the token to a thread.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Windows User Account Control', 'System access controls', 'File system access controls']
* Effective Permissions: ['SYSTEM']
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1134/003

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

None
