
# Commonly Used Port

## Description

### MITRE Description

> Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection. They may use commonly open ports such as

* TCP:80 (HTTP)
* TCP:443 (HTTPS)
* TCP:25 (SMTP)
* TCP/UDP:53 (DNS)

They may use the protocol associated with the port or a completely different protocol. 

For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), examples of common ports are 

* TCP/UDP:135 (RPC)
* TCP/UDP:22 (SSH)
* TCP/UDP:3389 (RDP)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1043

## Potential Commands

```
!=powershell.exe
nslookup
!=cmd.exe
nslookup
powershell/lateral_movement/invoke_sshcommand
powershell/lateral_movement/invoke_sshcommand
```

## Commands Dataset

```
[{'command': '!=powershell.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'nslookup',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': '!=cmd.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'nslookup',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell/lateral_movement/invoke_sshcommand',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/lateral_movement/invoke_sshcommand',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Threat Hunting Tables': {'chain_id': '100051',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1043',
                            'mitre_caption': 'commonly_used_port',
                            'os': 'windows',
                            'parent_process': '!=powershell.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'nslookup',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100052',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1043',
                            'mitre_caption': 'commonly_used_port',
                            'os': 'windows',
                            'parent_process': '!=cmd.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'nslookup',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1043',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/lateral_movement/invoke_sshcommand":  '
                                                                                 '["T1043"],',
                                            'Empire Module': 'powershell/lateral_movement/invoke_sshcommand',
                                            'Technique': 'Commonly Used Port'}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations

None

# Actors


* [Magic Hound](../actors/Magic-Hound.md)

* [FIN8](../actors/FIN8.md)
    
* [APT19](../actors/APT19.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT37](../actors/APT37.md)
    
* [APT3](../actors/APT3.md)
    
* [APT32](../actors/APT32.md)
    
* [APT18](../actors/APT18.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [FIN7](../actors/FIN7.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [APT29](../actors/APT29.md)
    
* [APT33](../actors/APT33.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [APT28](../actors/APT28.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Machete](../actors/Machete.md)
    
