
# Unsecured Credentials

## Description

### MITRE Description

> Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. [Bash History](https://attack.mitre.org/techniques/T1552/003)), operating system or application-specific repositories (e.g. [Credentials in Registry](https://attack.mitre.org/techniques/T1552/002)), or other specialized files/artifacts (e.g. [Private Keys](https://attack.mitre.org/techniques/T1552/004)).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure', 'Office 365', 'Azure AD', 'SaaS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1552

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


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Audit](../mitigations/Audit.md)

* [Active Directory Configuration](../mitigations/Active-Directory-Configuration.md)
    
* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    
* [User Training](../mitigations/User-Training.md)
    
* [Filter Network Traffic](../mitigations/Filter-Network-Traffic.md)
    
* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Password Policies](../mitigations/Password-Policies.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    
* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)
    
* [Update Software](../mitigations/Update-Software.md)
    

# Actors

None
