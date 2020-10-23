
# Proxy

## Description

### MITRE Description

> Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use these types of proxies to manage command and control communications, reduce the number of simultaneous outbound network connections, provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion. Adversaries may chain together multiple proxies to further disguise the source of malicious traffic.

Adversaries can also take advantage of routing schemes in Content Delivery Networks (CDNs) to proxy command and control traffic.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1090

## Potential Commands

```
python/management/multi/socks
```

## Commands Dataset

```
[{'command': 'python/management/multi/socks',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/management/multi/socks',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Markus Neis',
                  'date': '2019/01/29',
                  'description': 'Allow Incoming Connections by Port or '
                                 'Application on Windows Firewall',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['*netsh firewall '
                                                              'add*']}},
                  'falsepositives': ['Legitimate administration'],
                  'id': 'cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://attack.mitre.org/software/S0246/ '
                                 '(Lazarus HARDRAIN)',
                                 'https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf'],
                  'status': 'experimental',
                  'tags': ['attack.lateral_movement',
                           'attack.command_and_control',
                           'attack.t1090'],
                  'title': 'Netsh'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2019/01/29',
                  'description': 'Detects netsh commands that configure a port '
                                 'forwarding',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['netsh interface '
                                                              'portproxy add '
                                                              'v4tov4 *']}},
                  'falsepositives': ['Legitimate administration'],
                  'id': '322ed9ec-fcab-4f67-9a34-e7c6aef43614',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html'],
                  'status': 'experimental',
                  'tags': ['attack.lateral_movement',
                           'attack.command_and_control',
                           'attack.t1090'],
                  'title': 'Netsh Port Forwarding'}},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['Packet capture']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['Packet capture']}]
```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: netsh port forwarding\n'
           'description: windows server 2016\n'
           'tags: T1090-001\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection:\n'
           '        EventID: 4688 # have created a new process.\n'
           "        Newprocessname: 'C: \\ Windows \\ System32 \\ netsh.exe' # "
           'new process name\n'
           "        Creatorprocessname: 'C: \\ Windows \\ System32 \\ cmd.exe' "
           '# creator process name\n'
           '        Processcommandline: "netsh interface portproxy add v4tov4 '
           '*" # process command line arguments\n'
           '    condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1090',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/management/multi/socks":  '
                                                                                 '["T1090"],',
                                            'Empire Module': 'python/management/multi/socks',
                                            'Technique': 'Connection Proxy'}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations


* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)

* [Filter Network Traffic](../mitigations/Filter-Network-Traffic.md)
    
* [SSL/TLS Inspection](../mitigations/SSL-TLS-Inspection.md)
    

# Actors


* [Turla](../actors/Turla.md)

* [APT41](../actors/APT41.md)
    
* [Wizard Spider](../actors/Wizard-Spider.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
