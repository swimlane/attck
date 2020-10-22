
# Lateral Tool Transfer

## Description

### MITRE Description

> Adversaries may transfer tools or other files between systems in a compromised environment. Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Adversaries may copy files laterally between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) or [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001). Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1570

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


* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)

* [Filter Network Traffic](../mitigations/Filter-Network-Traffic.md)
    

# Actors


* [FIN10](../actors/FIN10.md)

* [Turla](../actors/Turla.md)
    
* [Wizard Spider](../actors/Wizard-Spider.md)
    
* [APT32](../actors/APT32.md)
    
