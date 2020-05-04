
# Valid Accounts

## Description

### MITRE Description

> Adversaries may steal the credentials of a specific user or service account using Credential Access techniques or capture credentials earlier in their reconnaissance process through social engineering for means of gaining Initial Access. 

Accounts that an adversary may use can fall into three categories: default, local, and domain accounts. Default accounts are those that are built-into an OS such as Guest or Administrator account on Windows systems or default factory/provider set accounts on other types of systems, software, or devices. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. (Citation: Microsoft Local Accounts Feb 2019) Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.

Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.

Default accounts are also not limited to Guest and Administrator on client machines, they also include accounts that are preset for equipment such as network devices and computer applications whether they are internal, open source, or COTS. Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary. Similarly, adversaries may also utilize publicly disclosed private keys, or stolen private keys, to legitimately connect to remote environments via [Remote Services](https://attack.mitre.org/techniques/T1021) (Citation: Metasploit SSH Module)

The overlap of account access, credentials, and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise. (Citation: TechNet Credential Theft)

## Additional Attributes

* Bypass: ['Firewall', 'Host intrusion prevention systems', 'Network intrusion detection system', 'Process whitelisting', 'System access controls', 'Anti-virus']
* Effective Permissions: ['User', 'Administrator']
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure', 'SaaS', 'Office 365']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1078

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

* [Initial Access](../tactics/Initial-Access.md)
    
* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors


* [PittyTiger](../actors/PittyTiger.md)

* [Carbanak](../actors/Carbanak.md)
    
* [FIN8](../actors/FIN8.md)
    
* [menuPass](../actors/menuPass.md)
    
* [APT3](../actors/APT3.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [FIN4](../actors/FIN4.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [APT33](../actors/APT33.md)
    
* [FIN5](../actors/FIN5.md)
    
* [APT28](../actors/APT28.md)
    
* [FIN10](../actors/FIN10.md)
    
* [Suckfly](../actors/Suckfly.md)
    
* [FIN6](../actors/FIN6.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT18](../actors/APT18.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [APT32](../actors/APT32.md)
    
* [Threat Group-1314](../actors/Threat-Group-1314.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Stolen Pencil](../actors/Stolen-Pencil.md)
    
* [APT39](../actors/APT39.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
