
# Internal Proxy

## Description

### MITRE Description

> Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use internal proxies to manage command and control communications inside a compromised environment, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between infected systems to avoid suspicion. Internal proxy connections may use common peer-to-peer (p2p) networking protocols, such as SMB, to better blend in with the environment.

By using a compromised internal system as a proxy, adversaries may conceal the true destination of C2 traffic while reducing the need for numerous connections to external systems.

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
* Wiki: https://attack.mitre.org/techniques/T1090/001

## Potential Commands

```
netsh interface portproxy add v4tov4 listenport=#{listenport} connectport=#{connectport} connectaddress=127.0.0.1
export #{proxy_scheme}_proxy=127.0.0.1:8080
networksetup -setwebproxy #{interface} 127.0.0.1 #{proxy_port}
networksetup -setsecurewebproxy #{interface} 127.0.0.1 #{proxy_port}
networksetup -setwebproxy Wi-Fi #{proxy_server} #{proxy_port}
networksetup -setsecurewebproxy Wi-Fi #{proxy_server} #{proxy_port}
netsh interface portproxy add v4tov4 listenport=1337 connectport=#{connectport} connectaddress=#{connectaddress}
export http_proxy=#{proxy_server}
netsh interface portproxy add v4tov4 listenport=#{listenport} connectport=1337 connectaddress=#{connectaddress}
```

## Commands Dataset

```
[{'command': 'export #{proxy_scheme}_proxy=127.0.0.1:8080\n',
  'name': None,
  'source': 'atomics/T1090.001/T1090.001.yaml'},
 {'command': 'export http_proxy=#{proxy_server}\n',
  'name': None,
  'source': 'atomics/T1090.001/T1090.001.yaml'},
 {'command': 'networksetup -setwebproxy #{interface} 127.0.0.1 #{proxy_port}\n'
             'networksetup -setsecurewebproxy #{interface} 127.0.0.1 '
             '#{proxy_port}\n',
  'name': None,
  'source': 'atomics/T1090.001/T1090.001.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1090.001/T1090.001.yaml'},
 {'command': 'networksetup -setwebproxy Wi-Fi #{proxy_server} #{proxy_port}\n'
             'networksetup -setsecurewebproxy Wi-Fi #{proxy_server} '
             '#{proxy_port}\n',
  'name': None,
  'source': 'atomics/T1090.001/T1090.001.yaml'},
 {'command': 'netsh interface portproxy add v4tov4 listenport=#{listenport} '
             'connectport=#{connectport} connectaddress=127.0.0.1',
  'name': None,
  'source': 'atomics/T1090.001/T1090.001.yaml'},
 {'command': 'netsh interface portproxy add v4tov4 listenport=#{listenport} '
             'connectport=1337 connectaddress=#{connectaddress}',
  'name': None,
  'source': 'atomics/T1090.001/T1090.001.yaml'},
 {'command': 'netsh interface portproxy add v4tov4 listenport=1337 '
             'connectport=#{connectport} connectaddress=#{connectaddress}',
  'name': None,
  'source': 'atomics/T1090.001/T1090.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Proxy: Internal Proxy': {'atomic_tests': [{'auto_generated_guid': '0ac21132-4485-4212-a681-349e8a6637cd',
                                                                     'description': 'Enable '
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
                                                                    {'auto_generated_guid': '648d68c1-8bcd-4486-9abe-71c6655b6a2c',
                                                                     'description': 'Enable '
                                                                                    'traffic '
                                                                                    'redirection '
                                                                                    'on '
                                                                                    'macOS '
                                                                                    'UI '
                                                                                    '(not '
                                                                                    'terminal).\n'
                                                                                    'The '
                                                                                    'test '
                                                                                    'will '
                                                                                    'modify '
                                                                                    'and '
                                                                                    'enable '
                                                                                    'the '
                                                                                    '"Web '
                                                                                    'Proxy" '
                                                                                    'and '
                                                                                    '"Secure '
                                                                                    'Web '
                                                                                    'Proxy" '
                                                                                    'settings  '
                                                                                    'in '
                                                                                    'System '
                                                                                    'Preferences '
                                                                                    '=> '
                                                                                    'Network '
                                                                                    '=> '
                                                                                    'Advanced '
                                                                                    '=> '
                                                                                    'Proxies '
                                                                                    'for '
                                                                                    'the '
                                                                                    'specified '
                                                                                    'network '
                                                                                    'interface.\n'
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
                                                                     'executor': {'cleanup_command': 'networksetup '
                                                                                                     '-setwebproxystate '
                                                                                                     '#{interface} '
                                                                                                     'off\n'
                                                                                                     'networksetup '
                                                                                                     '-setsecurewebproxystate '
                                                                                                     '#{interface} '
                                                                                                     'off  \n',
                                                                                  'command': 'networksetup '
                                                                                             '-setwebproxy '
                                                                                             '#{interface} '
                                                                                             '#{proxy_server} '
                                                                                             '#{proxy_port}\n'
                                                                                             'networksetup '
                                                                                             '-setsecurewebproxy '
                                                                                             '#{interface} '
                                                                                             '#{proxy_server} '
                                                                                             '#{proxy_port}\n',
                                                                                  'name': 'sh'},
                                                                     'input_arguments': {'interface': {'default': 'Wi-Fi',
                                                                                                       'description': 'Protocol '
                                                                                                                      'to '
                                                                                                                      'proxy '
                                                                                                                      '(http '
                                                                                                                      'or '
                                                                                                                      'https)',
                                                                                                       'type': 'string'},
                                                                                         'proxy_port': {'default': 8080,
                                                                                                        'description': 'Proxy '
                                                                                                                       'server '
                                                                                                                       'port',
                                                                                                        'type': 'string'},
                                                                                         'proxy_server': {'default': '127.0.0.1',
                                                                                                          'description': 'Proxy '
                                                                                                                         'server '
                                                                                                                         'URL '
                                                                                                                         '(host)',
                                                                                                          'type': 'string'}},
                                                                     'name': 'Connection '
                                                                             'Proxy '
                                                                             'for '
                                                                             'macOS '
                                                                             'UI',
                                                                     'supported_platforms': ['macos']},
                                                                    {'auto_generated_guid': 'b8223ea9-4be2-44a6-b50a-9657a3d4e72a',
                                                                     'description': 'Adds '
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
                                                                                                     'listenport=#{listenport} '
                                                                                                     '-ErrorAction '
                                                                                                     'Ignore '
                                                                                                     '| '
                                                                                                     'Out-Null',
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
                                                                                         'connectport': {'default': '1337',
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
                                                                                         'listenport': {'default': '1337',
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
                                                   'attack_technique': 'T1090.001',
                                                   'display_name': 'Proxy: '
                                                                   'Internal '
                                                                   'Proxy'}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations


* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)


# Actors


* [Strider](../actors/Strider.md)

* [APT39](../actors/APT39.md)
    
