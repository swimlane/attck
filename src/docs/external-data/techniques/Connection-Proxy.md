
# Connection Proxy

## Description

### MITRE Description

> Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use these types of proxies to manage command and control communications, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion.

External connection proxies are used to mask the destination of C2 traffic and are typically implemented with port redirectors. Compromised systems outside of the victim environment may be used for these purposes, as well as purchased infrastructure such as cloud-based resources or virtual private servers. Proxies may be chosen based on the low likelihood that a connection to them from a compromised system would be investigated. Victim systems would communicate directly with the external proxy on the internet and then the proxy would forward communications to the C2 server.

Internal connection proxies can be used to consolidate internal connections from compromised systems. Adversaries may use a compromised internal system as a proxy in order to conceal the true destination of C2 traffic. The proxy can redirect traffic from compromised systems inside the network to an external C2 server making discovery of malicious traffic difficult. Additionally, the network can be used to relay information from one system to another in order to avoid broadcasting traffic to all systems.

## Additional Attributes

* Bypass: ['Log Analysis', 'Firewall']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1090

## Potential Commands

```
export #{proxy_scheme}_proxy=127.0.0.1:8080

export http_proxy=#{proxy_server}

None
None
netsh interface portproxy add v4tov4 listenport=#{listenport} connectport=#{connectport} connectaddress=127.0.0.1
python/management/multi/socks
python/management/multi/socks
```

## Commands Dataset

```
[{'command': 'export #{proxy_scheme}_proxy=127.0.0.1:8080\n',
  'name': None,
  'source': 'atomics/T1090/T1090.yaml'},
 {'command': 'export http_proxy=#{proxy_server}\n',
  'name': None,
  'source': 'atomics/T1090/T1090.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1090/T1090.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1090/T1090.yaml'},
 {'command': 'netsh interface portproxy add v4tov4 listenport=#{listenport} '
             'connectport=#{connectport} connectaddress=127.0.0.1',
  'name': None,
  'source': 'atomics/T1090/T1090.yaml'},
 {'command': 'python/management/multi/socks',
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
                  'title': 'Netsh Port Forwarding'}}]
```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: netsh port forwarding\n'
           'description: windows server 2016\n'
           'tags: T1090\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ netsh.exe' # new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ Windows "
           "\\ System32 \\ cmd.exe' # creator process name\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: "netsh '
           'interface portproxy add v4tov4 *" # process command line '
           'arguments\n'
           '\xa0\xa0\xa0\xa0condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Connection Proxy': {'atomic_tests': [{'description': 'Enable '
                                                                               'traffic '
                                                                               'redirection.\n'
                                                                               '\n'
                                                                               'Note '
                                                                               'that '
                                                                               'this '
                                                                               'test '
                                                                               'may '
                                                                               'conflict '
                                                                               'with '
                                                                               'pre-existing '
                                                                               'system '
                                                                               'configuration.\n',
                                                                'executor': {'cleanup_command': 'unset '
                                                                                                'http_proxy\n'
                                                                                                'unset '
                                                                                                'https_proxy\n',
                                                                             'command': 'export '
                                                                                        '#{proxy_scheme}_proxy=#{proxy_server}\n',
                                                                             'name': 'sh'},
                                                                'input_arguments': {'proxy_scheme': {'default': 'http',
                                                                                                     'description': 'Protocol '
                                                                                                                    'to '
                                                                                                                    'proxy '
                                                                                                                    '(http '
                                                                                                                    'or '
                                                                                                                    'https)',
                                                                                                     'type': 'string'},
                                                                                    'proxy_server': {'default': '127.0.0.1:8080',
                                                                                                     'description': 'Proxy '
                                                                                                                    'server '
                                                                                                                    'URL '
                                                                                                                    '(host:port)',
                                                                                                     'type': 'url'}},
                                                                'name': 'Connection '
                                                                        'Proxy',
                                                                'supported_platforms': ['macos',
                                                                                        'linux']},
                                                               {'description': 'Adds '
                                                                               'a '
                                                                               'registry '
                                                                               'key '
                                                                               'to '
                                                                               'set '
                                                                               'up '
                                                                               'a '
                                                                               'proxy '
                                                                               'on '
                                                                               'the '
                                                                               'endpoint '
                                                                               'at '
                                                                               'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\n'
                                                                               'Upon '
                                                                               'execution '
                                                                               'there '
                                                                               'will '
                                                                               'be '
                                                                               'a '
                                                                               'new '
                                                                               'proxy '
                                                                               'entry '
                                                                               'in '
                                                                               'netsh\n'
                                                                               'netsh '
                                                                               'interface '
                                                                               'portproxy '
                                                                               'show '
                                                                               'all\n',
                                                                'executor': {'cleanup_command': 'netsh '
                                                                                                'interface '
                                                                                                'portproxy '
                                                                                                'delete '
                                                                                                'v4tov4 '
                                                                                                'listenport=#{listenport}',
                                                                             'command': 'netsh '
                                                                                        'interface '
                                                                                        'portproxy '
                                                                                        'add '
                                                                                        'v4tov4 '
                                                                                        'listenport=#{listenport} '
                                                                                        'connectport=#{connectport} '
                                                                                        'connectaddress=#{connectaddress}',
                                                                             'elevation_required': True,
                                                                             'name': 'powershell'},
                                                                'input_arguments': {'connectaddress': {'default': '127.0.0.1',
                                                                                                       'description': 'Specifies '
                                                                                                                      'the '
                                                                                                                      'IPv4 '
                                                                                                                      'address '
                                                                                                                      'to '
                                                                                                                      'which '
                                                                                                                      'to '
                                                                                                                      'connect. '
                                                                                                                      'Acceptable '
                                                                                                                      'values '
                                                                                                                      'are '
                                                                                                                      'IP '
                                                                                                                      'address, '
                                                                                                                      'computer '
                                                                                                                      'NetBIOS '
                                                                                                                      'name, '
                                                                                                                      'or '
                                                                                                                      'computer '
                                                                                                                      'DNS '
                                                                                                                      'name. '
                                                                                                                      'If '
                                                                                                                      'an '
                                                                                                                      'address '
                                                                                                                      'is '
                                                                                                                      'not '
                                                                                                                      'specified, '
                                                                                                                      'the '
                                                                                                                      'default '
                                                                                                                      'is '
                                                                                                                      'the '
                                                                                                                      'local '
                                                                                                                      'computer.',
                                                                                                       'type': 'string'},
                                                                                    'connectport': {'default': 1337,
                                                                                                    'description': 'Specifies '
                                                                                                                   'the '
                                                                                                                   'IPv4 '
                                                                                                                   'port, '
                                                                                                                   'by '
                                                                                                                   'port '
                                                                                                                   'number '
                                                                                                                   'or '
                                                                                                                   'service '
                                                                                                                   'name, '
                                                                                                                   'to '
                                                                                                                   'which '
                                                                                                                   'to '
                                                                                                                   'connect. '
                                                                                                                   'If '
                                                                                                                   'connectport '
                                                                                                                   'is '
                                                                                                                   'not '
                                                                                                                   'specified, '
                                                                                                                   'the '
                                                                                                                   'default '
                                                                                                                   'is '
                                                                                                                   'the '
                                                                                                                   'value '
                                                                                                                   'of '
                                                                                                                   'listenport '
                                                                                                                   'on '
                                                                                                                   'the '
                                                                                                                   'local '
                                                                                                                   'computer.',
                                                                                                    'type': 'string'},
                                                                                    'listenport': {'default': 1337,
                                                                                                   'description': 'Specifies '
                                                                                                                  'the '
                                                                                                                  'IPv4 '
                                                                                                                  'port, '
                                                                                                                  'by '
                                                                                                                  'port '
                                                                                                                  'number '
                                                                                                                  'or '
                                                                                                                  'service '
                                                                                                                  'name, '
                                                                                                                  'on '
                                                                                                                  'which '
                                                                                                                  'to '
                                                                                                                  'listen.',
                                                                                                   'type': 'string'}},
                                                                'name': 'portproxy '
                                                                        'reg '
                                                                        'key',
                                                                'supported_platforms': ['windows']}],
                                              'attack_technique': 'T1090',
                                              'display_name': 'Connection '
                                                              'Proxy'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1090',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/management/multi/socks":  '
                                                                                 '["T1090"],',
                                            'Empire Module': 'python/management/multi/socks',
                                            'Technique': 'Connection Proxy'}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)

* [Defense Evasion](../tactics/Defense-Evasion.md)
    

# Mitigations

None

# Actors


* [APT3](../actors/APT3.md)

* [menuPass](../actors/menuPass.md)
    
* [Strider](../actors/Strider.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [APT28](../actors/APT28.md)
    
* [APT39](../actors/APT39.md)
    
* [Turla](../actors/Turla.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
