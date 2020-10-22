
# Impair Defenses

## Description

### MITRE Description

> Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may also span both native defenses as well as supplemental capabilities installed by users and administrators.

Adversaries could also target event aggregation and analysis mechanisms, or otherwise disrupt these procedures by altering other system components.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti-virus', 'Signature-based detection', 'Host intrusion prevention systems', 'File monitoring', 'Digital Certificate Validation', 'Host forensic analysis', 'Log analysis', 'Firewall']
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Linux', 'Windows', 'macOS', 'AWS', 'GCP', 'Azure']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1562

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


# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)

* [User Account Management](../mitigations/User-Account-Management.md)
    
* [Restrict Registry Permissions](../mitigations/Restrict-Registry-Permissions.md)
    

# Actors

None
