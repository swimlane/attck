
# Net

## Description

### MITRE Description

> The [Net](https://attack.mitre.org/software/S0039) utility is a component of the Windows operating system. It is used in command-line operations for control of users, groups, services, and network connections. (Citation: Microsoft Net Utility)

[Net](https://attack.mitre.org/software/S0039) has a great deal of functionality, (Citation: Savill 1999) much of which is useful for an adversary, such as gathering system and network information for Discovery, moving laterally through [Windows Admin Shares](https://attack.mitre.org/techniques/T1077) using <code>net use</code> commands, and interacting with services. The net1.exe utility is executed for certain functionality when net.exe is run and can be used directly in commands such as <code>net1 user</code>.

## Aliases

```
intentionally left blank
```

## Additional Attributes

* Type: tool
* Wiki: https://attack.mitre.org/software/S0039

# Techniques


* [Service Execution](../techniques/Service-Execution.md)

* [Network Share Discovery](../techniques/Network-Share-Discovery.md)
    
* [Account Discovery](../techniques/Account-Discovery.md)
    
* [Create Account](../techniques/Create-Account.md)
    
* [Windows Admin Shares](../techniques/Windows-Admin-Shares.md)
    
* [Permission Groups Discovery](../techniques/Permission-Groups-Discovery.md)
    
* [System Service Discovery](../techniques/System-Service-Discovery.md)
    
* [Remote System Discovery](../techniques/Remote-System-Discovery.md)
    
* [System Network Connections Discovery](../techniques/System-Network-Connections-Discovery.md)
    
* [Password Policy Discovery](../techniques/Password-Policy-Discovery.md)
    
* [System Time Discovery](../techniques/System-Time-Discovery.md)
    
* [Network Share Connection Removal](../techniques/Network-Share-Connection-Removal.md)
    

# Actors


* [Orangeworm](../actors/Orangeworm.md)

* [menuPass](../actors/menuPass.md)
    
* [Naikon](../actors/Naikon.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Deep Panda](../actors/Deep-Panda.md)
    
* [Threat Group-1314](../actors/Threat-Group-1314.md)
    
* [admin@338](../actors/admin@338.md)
    
* [APT38](../actors/APT38.md)
    
* [APT1](../actors/APT1.md)
    
* [Turla](../actors/Turla.md)
    
* [APT32](../actors/APT32.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [APT33](../actors/APT33.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
