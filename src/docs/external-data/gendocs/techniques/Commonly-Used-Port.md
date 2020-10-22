
# Commonly Used Port

## Description

### MITRE Description

> **This technique has been deprecated. Please use [Non-Standard Port](https://attack.mitre.org/techniques/T1571) where appropriate.**

Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection. They may use commonly open ports such as

* TCP:80 (HTTP)
* TCP:443 (HTTPS)
* TCP:25 (SMTP)
* TCP/UDP:53 (DNS)

They may use the protocol associated with the port or a completely different protocol. 

For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), examples of common ports are 

* TCP/UDP:135 (RPC)
* TCP/UDP:22 (SSH)
* TCP/UDP:3389 (RDP)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
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
[{'data_source': {'author': 'Patrick Bareiss',
                  'date': '2019/04/07',
                  'description': 'Normally, DNS logs contain a limited amount '
                                 'of different dns queries for a single '
                                 'domain. This rule detects a high amount of '
                                 'queries for a single domain, which can be an '
                                 'indicator that DNS is used to transfer data.',
                  'detection': {'condition': 'selection | count(dns_query) by '
                                             'parent_domain > 1000',
                                'selection': {'parent_domain': '*'}},
                  'falsepositives': ['Valid software, which uses dns for '
                                     'transferring data'],
                  'id': '1ec4b281-aa65-46a2-bdae-5fd830ed914e',
                  'level': 'high',
                  'logsource': {'product': 'dns'},
                  'references': ['https://zeltser.com/c2-dns-tunneling/',
                                 'https://patrick-bareiss.com/detect-c2-traffic-over-dns-using-sigma/'],
                  'status': 'experimental',
                  'tags': ['attack.t1043'],
                  'title': 'Possible DNS Tunneling'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2017/03/19',
                  'description': 'Detects programs that connect to typical '
                                 'malware back connect ports based on '
                                 'statistical analysis from two different '
                                 'sandbox system databases',
                  'detection': {'condition': 'selection and not ( filter1 or '
                                             'filter2 )',
                                'filter1': {'Image': '*\\Program Files*'},
                                'filter2': {'DestinationIp': ['10.*',
                                                              '192.168.*',
                                                              '172.16.*',
                                                              '172.17.*',
                                                              '172.18.*',
                                                              '172.19.*',
                                                              '172.20.*',
                                                              '172.21.*',
                                                              '172.22.*',
                                                              '172.23.*',
                                                              '172.24.*',
                                                              '172.25.*',
                                                              '172.26.*',
                                                              '172.27.*',
                                                              '172.28.*',
                                                              '172.29.*',
                                                              '172.30.*',
                                                              '172.31.*',
                                                              '127.*'],
                                            'DestinationIsIpv6': 'false'},
                                'selection': {'DestinationPort': ['4443',
                                                                  '2448',
                                                                  '8143',
                                                                  '1777',
                                                                  '1443',
                                                                  '243',
                                                                  '65535',
                                                                  '13506',
                                                                  '3360',
                                                                  '200',
                                                                  '198',
                                                                  '49180',
                                                                  '13507',
                                                                  '6625',
                                                                  '4444',
                                                                  '4438',
                                                                  '1904',
                                                                  '13505',
                                                                  '13504',
                                                                  '12102',
                                                                  '9631',
                                                                  '5445',
                                                                  '2443',
                                                                  '777',
                                                                  '13394',
                                                                  '13145',
                                                                  '12103',
                                                                  '5552',
                                                                  '3939',
                                                                  '3675',
                                                                  '666',
                                                                  '473',
                                                                  '5649',
                                                                  '4455',
                                                                  '4433',
                                                                  '1817',
                                                                  '100',
                                                                  '65520',
                                                                  '1960',
                                                                  '1515',
                                                                  '743',
                                                                  '700',
                                                                  '14154',
                                                                  '14103',
                                                                  '14102',
                                                                  '12322',
                                                                  '10101',
                                                                  '7210',
                                                                  '4040',
                                                                  '9943'],
                                              'EventID': 3,
                                              'Initiated': 'true'}},
                  'falsepositives': ['unknown'],
                  'id': '4b89abaa-99fe-4232-afdd-8f9aa4d20382',
                  'level': 'medium',
                  'logsource': {'definition': 'Use the following config to '
                                              'generate the necessary Event ID '
                                              '10 Process Access events: '
                                              '<ProcessAccess '
                                              'onmatch="include"><CallTrace '
                                              'condition="contains">VBE7.DLL</CallTrace></ProcessAccess><ProcessAccess '
                                              'onmatch="exclude"><CallTrace '
                                              'condition="excludes">UNKNOWN</CallTrace></ProcessAccess>',
                                'product': 'windows',
                                'service': 'sysmon'},
                  'references': ['https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo'],
                  'status': 'experimental',
                  'tags': ['attack.command_and_control', 'attack.t1043'],
                  'title': 'Suspicious Typical Malware Back Connect Ports'}},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']}]
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


* [Commonly Used Port Mitigation](../mitigations/Commonly-Used-Port-Mitigation.md)

* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)
    
* [Network Segmentation](../mitigations/Network-Segmentation.md)
    

# Actors


* [Magic Hound](../actors/Magic-Hound.md)

* [FIN8](../actors/FIN8.md)
    
* [APT19](../actors/APT19.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT37](../actors/APT37.md)
    
* [APT3](../actors/APT3.md)
    
* [APT18](../actors/APT18.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [FIN7](../actors/FIN7.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [APT29](../actors/APT29.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [APT28](../actors/APT28.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Machete](../actors/Machete.md)
    
