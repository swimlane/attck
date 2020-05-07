
# Network Service Scanning

## Description

### MITRE Description

> Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system. 

Within cloud environments, adversaries may attempt to discover services running on other cloud hosts or cloud services enabled within the environment. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM', 'User']
* Platforms: ['Linux', 'Windows', 'macOS', 'AWS', 'GCP', 'Azure']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1046

## Potential Commands

```
for port in {1..65535};
do
  echo >/dev/tcp/192.168.1.1/$port && echo "port $port is open" || echo "port $port is closed" : ;
done

nmap -sS 192.168.1.0/24 -p #{port}
telnet #{host} #{port}
nc -nv #{host} #{port}

None
nmap -sS #{network_range} -p #{port}
telnet 192.168.1.1 #{port}
nc -nv 192.168.1.1 #{port}

{'darwin': {'sh': {'command': 'nmap -sV -p #{remote.host.port} #{remote.host.ip}\n'}}, 'linux': {'sh': {'command': 'nmap -sV -p #{remote.host.port} #{remote.host.ip}\n'}}}
{'darwin': {'sh': {'command': 'python3 scanner.py -i #{remote.host.ip}\n', 'parsers': {'plugins.stockpile.app.parsers.scan': [{'source': 'remote.host.ip', 'edge': 'has_open_port', 'target': 'remote.host.port'}]}, 'payloads': ['scanner.py']}}, 'linux': {'sh': {'command': 'python3 scanner.py -i #{remote.host.ip}\n', 'parsers': {'plugins.stockpile.app.parsers.scan': [{'source': 'remote.host.ip', 'edge': 'has_open_port', 'target': 'remote.host.port'}]}, 'payloads': ['scanner.py']}}}
{'windows': {'psh': {'command': '$local_addr = (Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -ne "Disconnected" }).IPv4Address.IPAddress;\n$temp = $local_addr.split(\'.\')[0..2];\n$construct = $temp[0] + \'.\' + $temp[1] + \'.\' + $temp[2] + ".";\n1..255 | % { $a = $_; write-host "------"; write-host "$construct$a";\n22,53,80,445 | % { $socket = new-object system.net.sockets.tcpclient;\n$Connection = $socket.beginconnect("$construct$a", $_, $null, $null);\n$Connection.AsyncWaitHandle.waitOne(50,$false) | out-null;\nif ($socket.connected -eq $true) { echo "Port $_ is open!"};\n$socket.Close | Out-Null; }}\n'}}}
rcpping.exe -s 127.0.0.1 -t ncacn_np
rcpping.exe -s 127.0.0.1 -e 1234 -a privacy -u NTLM
powershell/recon/find_fruit
powershell/recon/find_fruit
powershell/situational_awareness/network/get_sql_instance_domain
powershell/situational_awareness/network/get_sql_instance_domain
powershell/situational_awareness/network/get_sql_server_info
powershell/situational_awareness/network/get_sql_server_info
powershell/situational_awareness/network/portscan
powershell/situational_awareness/network/portscan
python/situational_awareness/network/find_fruit
python/situational_awareness/network/find_fruit
python/situational_awareness/network/port_scan
python/situational_awareness/network/port_scan
```

## Commands Dataset

```
[{'command': 'for port in {1..65535};\n'
             'do\n'
             '  echo >/dev/tcp/192.168.1.1/$port && echo "port $port is open" '
             '|| echo "port $port is closed" : ;\n'
             'done\n',
  'name': None,
  'source': 'atomics/T1046/T1046.yaml'},
 {'command': 'nmap -sS 192.168.1.0/24 -p #{port}\n'
             'telnet #{host} #{port}\n'
             'nc -nv #{host} #{port}\n',
  'name': None,
  'source': 'atomics/T1046/T1046.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1046/T1046.yaml'},
 {'command': 'nmap -sS #{network_range} -p #{port}\n'
             'telnet 192.168.1.1 #{port}\n'
             'nc -nv 192.168.1.1 #{port}\n',
  'name': None,
  'source': 'atomics/T1046/T1046.yaml'},
 {'command': {'darwin': {'sh': {'command': 'nmap -sV -p #{remote.host.port} '
                                           '#{remote.host.ip}\n'}},
              'linux': {'sh': {'command': 'nmap -sV -p #{remote.host.port} '
                                          '#{remote.host.ip}\n'}}},
  'name': 'Uses nmap to fingerprint services that were network accessible',
  'source': 'data/abilities/discovery/3a2ce3d5-e9e2-4344-ae23-470432ff8687.yml'},
 {'command': {'darwin': {'sh': {'command': 'python3 scanner.py -i '
                                           '#{remote.host.ip}\n',
                                'parsers': {'plugins.stockpile.app.parsers.scan': [{'edge': 'has_open_port',
                                                                                    'source': 'remote.host.ip',
                                                                                    'target': 'remote.host.port'}]},
                                'payloads': ['scanner.py']}},
              'linux': {'sh': {'command': 'python3 scanner.py -i '
                                          '#{remote.host.ip}\n',
                               'parsers': {'plugins.stockpile.app.parsers.scan': [{'edge': 'has_open_port',
                                                                                   'source': 'remote.host.ip',
                                                                                   'target': 'remote.host.port'}]},
                               'payloads': ['scanner.py']}}},
  'name': 'Use dropped scanner to find open popular ports',
  'source': 'data/abilities/discovery/47abe1f5-55a5-46cc-8cad-506dac8ea6d9.yml'},
 {'command': {'windows': {'psh': {'command': '$local_addr = '
                                             '(Get-NetIPConfiguration | '
                                             'Where-Object '
                                             '{$_.NetAdapter.Status -ne '
                                             '"Disconnected" '
                                             '}).IPv4Address.IPAddress;\n'
                                             '$temp = '
                                             "$local_addr.split('.')[0..2];\n"
                                             "$construct = $temp[0] + '.' + "
                                             "$temp[1] + '.' + $temp[2] + "
                                             '".";\n'
                                             '1..255 | % { $a = $_; write-host '
                                             '"------"; write-host '
                                             '"$construct$a";\n'
                                             '22,53,80,445 | % { $socket = '
                                             'new-object '
                                             'system.net.sockets.tcpclient;\n'
                                             '$Connection = '
                                             '$socket.beginconnect("$construct$a", '
                                             '$_, $null, $null);\n'
                                             '$Connection.AsyncWaitHandle.waitOne(50,$false) '
                                             '| out-null;\n'
                                             'if ($socket.connected -eq $true) '
                                             '{ echo "Port $_ is open!"};\n'
                                             '$socket.Close | Out-Null; '
                                             '}}\n'}}},
  'name': 'Scans the local network for common open ports',
  'source': 'data/abilities/discovery/5a4cb2be-2684-4801-9355-3a90c91e0004.yml'},
 {'command': 'rcpping.exe -s 127.0.0.1 -t ncacn_np',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'rcpping.exe -s 127.0.0.1 -e 1234 -a privacy -u NTLM',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell/recon/find_fruit',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/recon/find_fruit',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/get_sql_instance_domain',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/get_sql_instance_domain',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/get_sql_server_info',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/get_sql_server_info',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/portscan',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/portscan',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/find_fruit',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/find_fruit',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/port_scan',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/port_scan',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'description': 'Detects a JAVA process running with remote '
                                 'debugging allowing more than just localhost '
                                 'to connect',
                  'detection': {'condition': 'selection and not exclusion',
                                'exclusion': [{'CommandLine': '*address=127.0.0.1*'},
                                              {'CommandLine': '*address=localhost*'}],
                                'selection': {'CommandLine': '*transport=dt_socket,address=*'}},
                  'falsepositives': ['unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '8f88e3f6-2a49-48f5-a5c4-2f7eedf78710',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'tags': ['attack.discovery', 'attack.t1046'],
                  'title': 'Java Running with Remote Debugging'}}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Network Service Scanning': {'atomic_tests': [{'description': 'Scan '
                                                                                       'ports '
                                                                                       'to '
                                                                                       'check '
                                                                                       'for '
                                                                                       'listening '
                                                                                       'ports.\n'
                                                                                       '\n'
                                                                                       'Upon '
                                                                                       'successful '
                                                                                       'execution, '
                                                                                       'sh '
                                                                                       'will '
                                                                                       'perform '
                                                                                       'a '
                                                                                       'network '
                                                                                       'connection '
                                                                                       'against '
                                                                                       'a '
                                                                                       'single '
                                                                                       'host '
                                                                                       '(192.168.1.1) '
                                                                                       'and '
                                                                                       'determine '
                                                                                       'what '
                                                                                       'ports '
                                                                                       'are '
                                                                                       'open '
                                                                                       'in '
                                                                                       'the '
                                                                                       'range '
                                                                                       'of '
                                                                                       '1-65535. '
                                                                                       'Results '
                                                                                       'will '
                                                                                       'be '
                                                                                       'via '
                                                                                       'stdout.\n',
                                                                        'executor': {'command': 'for '
                                                                                                'port '
                                                                                                'in '
                                                                                                '{1..65535};\n'
                                                                                                'do\n'
                                                                                                '  '
                                                                                                'echo '
                                                                                                '>/dev/tcp/192.168.1.1/$port '
                                                                                                '&& '
                                                                                                'echo '
                                                                                                '"port '
                                                                                                '$port '
                                                                                                'is '
                                                                                                'open" '
                                                                                                '|| '
                                                                                                'echo '
                                                                                                '"port '
                                                                                                '$port '
                                                                                                'is '
                                                                                                'closed" '
                                                                                                ': '
                                                                                                ';\n'
                                                                                                'done\n',
                                                                                     'elevation_required': False,
                                                                                     'name': 'sh'},
                                                                        'name': 'Port '
                                                                                'Scan',
                                                                        'supported_platforms': ['linux',
                                                                                                'macos']},
                                                                       {'dependencies': [{'description': 'Check '
                                                                                                         'if '
                                                                                                         'nmap '
                                                                                                         'command '
                                                                                                         'exists '
                                                                                                         'on '
                                                                                                         'the '
                                                                                                         'machine\n',
                                                                                          'get_prereq_command': 'echo '
                                                                                                                '"Install '
                                                                                                                'nmap '
                                                                                                                'on '
                                                                                                                'the '
                                                                                                                'machine '
                                                                                                                'to '
                                                                                                                'run '
                                                                                                                'the '
                                                                                                                'test."; '
                                                                                                                'exit '
                                                                                                                '1;\n',
                                                                                          'prereq_command': 'if '
                                                                                                            '[ '
                                                                                                            '-x '
                                                                                                            '"$(command '
                                                                                                            '-v '
                                                                                                            'nmap)" '
                                                                                                            ']; '
                                                                                                            'then '
                                                                                                            'exit '
                                                                                                            '0; '
                                                                                                            'else '
                                                                                                            'exit '
                                                                                                            '1;\n'}],
                                                                        'dependency_executor_name': 'sh',
                                                                        'description': 'Scan '
                                                                                       'ports '
                                                                                       'to '
                                                                                       'check '
                                                                                       'for '
                                                                                       'listening '
                                                                                       'ports '
                                                                                       'with '
                                                                                       'Nmap.\n'
                                                                                       '\n'
                                                                                       'Upon '
                                                                                       'successful '
                                                                                       'execution, '
                                                                                       'sh '
                                                                                       'will '
                                                                                       'utilize '
                                                                                       'nmap, '
                                                                                       'telnet, '
                                                                                       'and '
                                                                                       'nc '
                                                                                       'to '
                                                                                       'contact '
                                                                                       'a '
                                                                                       'single '
                                                                                       'or '
                                                                                       'range '
                                                                                       'of '
                                                                                       'adresseses '
                                                                                       'on '
                                                                                       'port '
                                                                                       '80 '
                                                                                       'to '
                                                                                       'determine '
                                                                                       'if '
                                                                                       'listening. '
                                                                                       'Results '
                                                                                       'will '
                                                                                       'be '
                                                                                       'via '
                                                                                       'stdout.\n',
                                                                        'executor': {'command': 'nmap '
                                                                                                '-sS '
                                                                                                '#{network_range} '
                                                                                                '-p '
                                                                                                '#{port}\n'
                                                                                                'telnet '
                                                                                                '#{host} '
                                                                                                '#{port}\n'
                                                                                                'nc '
                                                                                                '-nv '
                                                                                                '#{host} '
                                                                                                '#{port}\n',
                                                                                     'name': 'sh'},
                                                                        'input_arguments': {'host': {'default': '192.168.1.1',
                                                                                                     'description': 'Host '
                                                                                                                    'to '
                                                                                                                    'scan.',
                                                                                                     'type': 'string'},
                                                                                            'network_range': {'default': '192.168.1.0/24',
                                                                                                              'description': 'Network '
                                                                                                                             'Range '
                                                                                                                             'to '
                                                                                                                             'Scan.',
                                                                                                              'type': 'string'},
                                                                                            'port': {'default': 80,
                                                                                                     'description': 'Ports '
                                                                                                                    'to '
                                                                                                                    'scan.',
                                                                                                     'type': 'string'}},
                                                                        'name': 'Port '
                                                                                'Scan '
                                                                                'Nmap',
                                                                        'supported_platforms': ['linux',
                                                                                                'macos']}],
                                                      'attack_technique': 'T1046',
                                                      'display_name': 'Network '
                                                                      'Service '
                                                                      'Scanning'}},
 {'Mitre Stockpile - Uses nmap to fingerprint services that were network accessible': {'description': 'Uses '
                                                                                                      'nmap '
                                                                                                      'to '
                                                                                                      'fingerprint '
                                                                                                      'services '
                                                                                                      'that '
                                                                                                      'were '
                                                                                                      'network '
                                                                                                      'accessible',
                                                                                       'id': '3a2ce3d5-e9e2-4344-ae23-470432ff8687',
                                                                                       'name': 'Fingerprint '
                                                                                               'network '
                                                                                               'services',
                                                                                       'platforms': {'darwin': {'sh': {'command': 'nmap '
                                                                                                                                  '-sV '
                                                                                                                                  '-p '
                                                                                                                                  '#{remote.host.port} '
                                                                                                                                  '#{remote.host.ip}\n'}},
                                                                                                     'linux': {'sh': {'command': 'nmap '
                                                                                                                                 '-sV '
                                                                                                                                 '-p '
                                                                                                                                 '#{remote.host.port} '
                                                                                                                                 '#{remote.host.ip}\n'}}},
                                                                                       'tactic': 'discovery',
                                                                                       'technique': {'attack_id': 'T1046',
                                                                                                     'name': 'Network '
                                                                                                             'Service '
                                                                                                             'Scanning'}}},
 {'Mitre Stockpile - Use dropped scanner to find open popular ports': {'description': 'Use '
                                                                                      'dropped '
                                                                                      'scanner '
                                                                                      'to '
                                                                                      'find '
                                                                                      'open '
                                                                                      'popular '
                                                                                      'ports',
                                                                       'id': '47abe1f5-55a5-46cc-8cad-506dac8ea6d9',
                                                                       'name': 'Scan '
                                                                               'IP '
                                                                               'for '
                                                                               'ports',
                                                                       'platforms': {'darwin': {'sh': {'command': 'python3 '
                                                                                                                  'scanner.py '
                                                                                                                  '-i '
                                                                                                                  '#{remote.host.ip}\n',
                                                                                                       'parsers': {'plugins.stockpile.app.parsers.scan': [{'edge': 'has_open_port',
                                                                                                                                                           'source': 'remote.host.ip',
                                                                                                                                                           'target': 'remote.host.port'}]},
                                                                                                       'payloads': ['scanner.py']}},
                                                                                     'linux': {'sh': {'command': 'python3 '
                                                                                                                 'scanner.py '
                                                                                                                 '-i '
                                                                                                                 '#{remote.host.ip}\n',
                                                                                                      'parsers': {'plugins.stockpile.app.parsers.scan': [{'edge': 'has_open_port',
                                                                                                                                                          'source': 'remote.host.ip',
                                                                                                                                                          'target': 'remote.host.port'}]},
                                                                                                      'payloads': ['scanner.py']}}},
                                                                       'tactic': 'discovery',
                                                                       'technique': {'attack_id': 'T1046',
                                                                                     'name': 'Network '
                                                                                             'Service '
                                                                                             'Scanning'}}},
 {'Mitre Stockpile - Scans the local network for common open ports': {'description': 'Scans '
                                                                                     'the '
                                                                                     'local '
                                                                                     'network '
                                                                                     'for '
                                                                                     'common '
                                                                                     'open '
                                                                                     'ports',
                                                                      'id': '5a4cb2be-2684-4801-9355-3a90c91e0004',
                                                                      'name': 'Network '
                                                                              'Service '
                                                                              'Scanning',
                                                                      'platforms': {'windows': {'psh': {'command': '$local_addr '
                                                                                                                   '= '
                                                                                                                   '(Get-NetIPConfiguration '
                                                                                                                   '| '
                                                                                                                   'Where-Object '
                                                                                                                   '{$_.NetAdapter.Status '
                                                                                                                   '-ne '
                                                                                                                   '"Disconnected" '
                                                                                                                   '}).IPv4Address.IPAddress;\n'
                                                                                                                   '$temp '
                                                                                                                   '= '
                                                                                                                   "$local_addr.split('.')[0..2];\n"
                                                                                                                   '$construct '
                                                                                                                   '= '
                                                                                                                   '$temp[0] '
                                                                                                                   '+ '
                                                                                                                   "'.' "
                                                                                                                   '+ '
                                                                                                                   '$temp[1] '
                                                                                                                   '+ '
                                                                                                                   "'.' "
                                                                                                                   '+ '
                                                                                                                   '$temp[2] '
                                                                                                                   '+ '
                                                                                                                   '".";\n'
                                                                                                                   '1..255 '
                                                                                                                   '| '
                                                                                                                   '% '
                                                                                                                   '{ '
                                                                                                                   '$a '
                                                                                                                   '= '
                                                                                                                   '$_; '
                                                                                                                   'write-host '
                                                                                                                   '"------"; '
                                                                                                                   'write-host '
                                                                                                                   '"$construct$a";\n'
                                                                                                                   '22,53,80,445 '
                                                                                                                   '| '
                                                                                                                   '% '
                                                                                                                   '{ '
                                                                                                                   '$socket '
                                                                                                                   '= '
                                                                                                                   'new-object '
                                                                                                                   'system.net.sockets.tcpclient;\n'
                                                                                                                   '$Connection '
                                                                                                                   '= '
                                                                                                                   '$socket.beginconnect("$construct$a", '
                                                                                                                   '$_, '
                                                                                                                   '$null, '
                                                                                                                   '$null);\n'
                                                                                                                   '$Connection.AsyncWaitHandle.waitOne(50,$false) '
                                                                                                                   '| '
                                                                                                                   'out-null;\n'
                                                                                                                   'if '
                                                                                                                   '($socket.connected '
                                                                                                                   '-eq '
                                                                                                                   '$true) '
                                                                                                                   '{ '
                                                                                                                   'echo '
                                                                                                                   '"Port '
                                                                                                                   '$_ '
                                                                                                                   'is '
                                                                                                                   'open!"};\n'
                                                                                                                   '$socket.Close '
                                                                                                                   '| '
                                                                                                                   'Out-Null; '
                                                                                                                   '}}\n'}}},
                                                                      'tactic': 'discovery',
                                                                      'technique': {'attack_id': 'T1046',
                                                                                    'name': 'Network '
                                                                                            'Service '
                                                                                            'Scanning'}}},
 {'Threat Hunting Tables': {'chain_id': '100213',
                            'commandline_string': '-s 127.0.0.1 -t ncacn_np',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': 'https://github.com/api0cradle/LOLBAS/blob/master/OSBinaries/Rpcping.md',
                            'loaded_dll': '',
                            'mitre_attack': 'T1046',
                            'mitre_caption': 'network_service_scanning',
                            'os': 'windows',
                            'parent_process': 'rcpping.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100214',
                            'commandline_string': '-s 127.0.0.1 -e 1234 -a '
                                                  'privacy -u NTLM',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': 'https://github.com/api0cradle/LOLBAS/blob/master/OSBinaries/Rpcping.md',
                            'loaded_dll': '',
                            'mitre_attack': 'T1046',
                            'mitre_caption': 'network_service_scanning',
                            'os': 'windows',
                            'parent_process': 'rcpping.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1046',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/recon/find_fruit":  '
                                                                                 '["T1046"],',
                                            'Empire Module': 'powershell/recon/find_fruit',
                                            'Technique': 'Network Service '
                                                         'Scanning'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1046',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/get_sql_instance_domain":  '
                                                                                 '["T1046"],',
                                            'Empire Module': 'powershell/situational_awareness/network/get_sql_instance_domain',
                                            'Technique': 'Network Service '
                                                         'Scanning'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1046',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/get_sql_server_info":  '
                                                                                 '["T1046"],',
                                            'Empire Module': 'powershell/situational_awareness/network/get_sql_server_info',
                                            'Technique': 'Network Service '
                                                         'Scanning'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1046',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/portscan":  '
                                                                                 '["T1046"],',
                                            'Empire Module': 'powershell/situational_awareness/network/portscan',
                                            'Technique': 'Network Service '
                                                         'Scanning'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1046',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/find_fruit":  '
                                                                                 '["T1046"],',
                                            'Empire Module': 'python/situational_awareness/network/find_fruit',
                                            'Technique': 'Network Service '
                                                         'Scanning'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1046',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/port_scan":  '
                                                                                 '["T1046"],',
                                            'Empire Module': 'python/situational_awareness/network/port_scan',
                                            'Technique': 'Network Service '
                                                         'Scanning'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations

None

# Actors


* [Leafminer](../actors/Leafminer.md)

* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Suckfly](../actors/Suckfly.md)
    
* [OilRig](../actors/OilRig.md)
    
* [FIN6](../actors/FIN6.md)
    
* [APT32](../actors/APT32.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [menuPass](../actors/menuPass.md)
    
* [APT39](../actors/APT39.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [APT41](../actors/APT41.md)
    
