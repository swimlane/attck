
# Drive-by Compromise

## Description

### MITRE Description

> Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring [Application Access Token](https://attack.mitre.org/techniques/T1550/001).

Multiple ways of delivering exploit code to a browser exist, including:

* A legitimate website is compromised where adversaries have injected some form of malicious code such as JavaScript, iFrames, and cross-site scripting.
* Malicious ads are paid for and served through legitimate ad providers.
* Built-in web application interfaces are leveraged for the insertion of any other kind of object that can be used to display web content or contain a script that executes on the visiting client (e.g. forum posts, comments, and other user controllable web content).

Often the website used by an adversary is one visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted attack is referred to a strategic web compromise or watering hole attack. There are several known examples of this occurring.(Citation: Shadowserver Strategic Web Compromise)

Typical drive-by compromise process:

1. A user visits a website that is used to host the adversary controlled content.
2. Scripts automatically execute, typically searching versions of the browser and plugins for a potentially vulnerable version. 
    * The user may be required to assist in this process by enabling scripting or active website components and ignoring warning dialog boxes.
3. Upon finding a vulnerable version, exploit code is delivered to the browser.
4. If exploitation is successful, then it will give the adversary code execution on the user's system unless other protections are in place.
    * In some cases a second visit to the website after the initial scan is required before exploit code is delivered.

Unlike [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190), the focus of this technique is to exploit software on a client endpoint upon visiting a website. This will commonly give an adversary access to systems on the internal network instead of external systems that may be in a DMZ.

Adversaries may also use compromised websites to deliver a user to a malicious application designed to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s, like OAuth tokens, to gain access to protected applications and information. These malicious applications have been delivered through popups on legitimate websites.(Citation: Volexity OceanLotus Nov 2017)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows', 'Linux', 'macOS', 'SaaS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1189

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['Web proxy']},
 {'data_source': ['Network intrusion detection system']},
 {'data_source': ['SSL/TLS inspection']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Network device logs']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['Web proxy']},
 {'data_source': ['Network intrusion detection system']},
 {'data_source': ['SSL/TLS inspection']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Network device logs']}]
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


* [Drive-by Compromise Mitigation](../mitigations/Drive-by-Compromise-Mitigation.md)

* [Update Software](../mitigations/Update-Software.md)
    
* [Restrict Web-Based Content](../mitigations/Restrict-Web-Based-Content.md)
    
* [Application Isolation and Sandboxing](../mitigations/Application-Isolation-and-Sandboxing.md)
    
* [Exploit Protection](../mitigations/Exploit-Protection.md)
    

# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Elderwood](../actors/Elderwood.md)
    
* [Leafminer](../actors/Leafminer.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [APT37](../actors/APT37.md)
    
* [Dark Caracal](../actors/Dark-Caracal.md)
    
* [APT19](../actors/APT19.md)
    
* [PLATINUM](../actors/PLATINUM.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT32](../actors/APT32.md)
    
* [APT38](../actors/APT38.md)
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [RTM](../actors/RTM.md)
    
* [Windshift](../actors/Windshift.md)
    
* [Turla](../actors/Turla.md)
    
