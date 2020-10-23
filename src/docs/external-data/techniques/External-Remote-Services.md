
# External Remote Services

## Description

### MITRE Description

> Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) can also be used externally.

Access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.(Citation: Volexity Virtual Private Keylogging) Access to remote services may be used as a redundant or persistent access mechanism during an operation.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1133

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['4624', 'Authentication logs']}]
```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: landing from the public network failure behavior\n'
           'description: log on from a public IP network boundary may indicate '
           'firewall or configuration errors.\n'
           'author: NVISO 12306Br0 (translation + test)\n'
           'date: 2020/05/06\n'
           'tags:\n'
           '    - attack.initial_access\n'
           '    - attack.persistence\n'
           '    - attack.t1078\n'
           '    - attack.t1190\n'
           '    - attack.t1133\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection:\n'
           '        EventID: 4625 # landing failed\n'
           '    unknown:\n'
           "        IpAddress | contains: '-'\n"
           '    privatev4:\n'
           '        IpAddress | startswith:\n'
           "            -. '10 '# 10.0.0.0 / 8\n"
           "            - '. 192.168' # 192.168.0.0 / 16\n"
           "            - '. 172.16' # 172.16.0.0 / 12\n"
           "            - '172.17.'\n"
           "            - '172.18.'\n"
           "            - '172.19.'\n"
           "            - '172.20.'\n"
           "            - '172.21.'\n"
           "            - '172.22.'\n"
           "            - '172.23.'\n"
           "            - '172.24.'\n"
           "            - '172.25.'\n"
           "            - '172.26.'\n"
           "            - '172.27.'\n"
           "            - '172.28.'\n"
           "            - '172.29.'\n"
           "            - '172.30.'\n"
           "            - '172.31.'\n"
           "            - '127.' # 127.0.0.0 / 8\n"
           "            - '. 169.254' # 169.254.0.0 / 16\n"
           '    privatev6:\n'
           "        - IpAddress: ':: 1' #loopback\n"
           '        - IpAddress | startswith:\n'
           "            - 'fe80 ::' # link-local\n"
           "            - 'fc00 ::' #unique local\n"
           '    condition: selection and not (unknown or privatev4 or '
           'privatev6)\n'
           'falsepositives:\n'
           '    - legal attempt to log on the Internet\n'
           '    - IPv4 to IPv6 mapping of IP\n'
           'level: medium'}]
```

## Raw Dataset

```json

```

# Tactics


* [Initial Access](../tactics/Initial-Access.md)

* [Persistence](../tactics/Persistence.md)
    

# Mitigations


* [External Remote Services Mitigation](../mitigations/External-Remote-Services-Mitigation.md)

* [Limit Access to Resource Over Network](../mitigations/Limit-Access-to-Resource-Over-Network.md)
    
* [Network Segmentation](../mitigations/Network-Segmentation.md)
    
* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    
* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)
    

# Actors


* [APT18](../actors/APT18.md)

* [OilRig](../actors/OilRig.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [FIN5](../actors/FIN5.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
