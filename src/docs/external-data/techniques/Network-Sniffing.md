
# Network Sniffing

## Description

### MITRE Description

> Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.

Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as [LLMNR/NBT-NS Poisoning and Relay](https://attack.mitre.org/techniques/T1171), can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.

Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (ex: IP addressing, hostnames, VLAN IDs) necessary for follow-on Lateral Movement and/or Defense Evasion activities.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1040

## Potential Commands

```
tcpdump -c 5 -nnni ens33
tshark -c 5 -i ens33

tcpdump -c 5 -nnni en0A
tshark -c 5 -i en0A

"c:\Program Files\Wireshark\tshark.exe" -i Ethernet0 -c 5
c:\windump.exe

& "c:\Program Files\Wireshark\tshark.exe" -i Ethernet0 -c 5
& c:\windump.exe

{'windows': {'psh': {'command': 'New-NetEventSession -Name "PCAP" -CaptureMode SaveToFile -LocalFilePath "$ENV:UserProfile\\Desktop\\pcap.etl" -MaxFileSize 0\nAdd-NetEventPacketCaptureProvider -SessionName "PCAP"\nStart-NetEventSession -Name "PCAP"\nStart-Sleep -s 60\nStop-NetEventSession -Name "PCAP"\nGet-Content "$ENV:UserProfile\\Desktop\\pcap.etl"\n', 'cleanup': 'Remove-NetEventSession -Name "Capture"\nRemove-Item $ENV:UserProfile\\Desktop\\pcap.etl\nRemove-Item $ENV:UserProfile\\Desktop\\pcap.cab\n'}}, 'darwin': {'sh': {'command': 'tcpdump -i en0 & sleep 5; kill $!\n'}}}
powershell/collection/packet_capture
powershell/collection/packet_capture
python/collection/linux/sniffer
python/collection/linux/sniffer
python/collection/osx/sniffer
python/collection/osx/sniffer
```

## Commands Dataset

```
[{'command': 'tcpdump -c 5 -nnni ens33\ntshark -c 5 -i ens33\n',
  'name': None,
  'source': 'atomics/T1040/T1040.yaml'},
 {'command': 'tcpdump -c 5 -nnni en0A\ntshark -c 5 -i en0A\n',
  'name': None,
  'source': 'atomics/T1040/T1040.yaml'},
 {'command': '"c:\\Program Files\\Wireshark\\tshark.exe" -i Ethernet0 -c 5\n'
             'c:\\windump.exe\n',
  'name': None,
  'source': 'atomics/T1040/T1040.yaml'},
 {'command': '& "c:\\Program Files\\Wireshark\\tshark.exe" -i Ethernet0 -c 5\n'
             '& c:\\windump.exe\n',
  'name': None,
  'source': 'atomics/T1040/T1040.yaml'},
 {'command': {'darwin': {'sh': {'command': 'tcpdump -i en0 & sleep 5; kill '
                                           '$!\n'}},
              'windows': {'psh': {'cleanup': 'Remove-NetEventSession -Name '
                                             '"Capture"\n'
                                             'Remove-Item '
                                             '$ENV:UserProfile\\Desktop\\pcap.etl\n'
                                             'Remove-Item '
                                             '$ENV:UserProfile\\Desktop\\pcap.cab\n',
                                  'command': 'New-NetEventSession -Name "PCAP" '
                                             '-CaptureMode SaveToFile '
                                             '-LocalFilePath '
                                             '"$ENV:UserProfile\\Desktop\\pcap.etl" '
                                             '-MaxFileSize 0\n'
                                             'Add-NetEventPacketCaptureProvider '
                                             '-SessionName "PCAP"\n'
                                             'Start-NetEventSession -Name '
                                             '"PCAP"\n'
                                             'Start-Sleep -s 60\n'
                                             'Stop-NetEventSession -Name '
                                             '"PCAP"\n'
                                             'Get-Content '
                                             '"$ENV:UserProfile\\Desktop\\pcap.etl"\n'}}},
  'name': 'Perform a packet capture',
  'source': 'data/abilities/credential-access/1b4fb81c-8090-426c-93ab-0a633e7a16a7.yml'},
 {'command': 'powershell/collection/packet_capture',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/packet_capture',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/sniffer',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/sniffer',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/sniffer',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/sniffer',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Network Sniffing',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains '
           '"tshark.exe"or process_path contains "windump.exe"or process_path '
           'contains "logman.exe"or process_path contains "tcpdump.exe"or '
           'process_path contains "wprui.exe"or process_path contains '
           '"wpr.exe")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Network Sniffing': {'atomic_tests': [{'description': 'Perform '
                                                                               'a '
                                                                               'PCAP. '
                                                                               'Wireshark '
                                                                               'will '
                                                                               'be '
                                                                               'required '
                                                                               'for '
                                                                               'tshark. '
                                                                               'TCPdump '
                                                                               'may '
                                                                               'already '
                                                                               'be '
                                                                               'installed.\n'
                                                                               '\n'
                                                                               'Upon '
                                                                               'successful '
                                                                               'execution, '
                                                                               'tshark '
                                                                               'or '
                                                                               'tcpdump '
                                                                               'will '
                                                                               'execute '
                                                                               'and '
                                                                               'capture '
                                                                               '5 '
                                                                               'packets '
                                                                               'on '
                                                                               'interface '
                                                                               'ens33. \n',
                                                                'executor': {'command': 'tcpdump '
                                                                                        '-c '
                                                                                        '5 '
                                                                                        '-nnni '
                                                                                        '#{interface}\n'
                                                                                        'tshark '
                                                                                        '-c '
                                                                                        '5 '
                                                                                        '-i '
                                                                                        '#{interface}\n',
                                                                             'elevation_required': True,
                                                                             'name': 'bash'},
                                                                'input_arguments': {'interface': {'default': 'ens33',
                                                                                                  'description': 'Specify '
                                                                                                                 'interface '
                                                                                                                 'to '
                                                                                                                 'perform '
                                                                                                                 'PCAP '
                                                                                                                 'on.',
                                                                                                  'type': 'String'}},
                                                                'name': 'Packet '
                                                                        'Capture '
                                                                        'Linux',
                                                                'supported_platforms': ['linux']},
                                                               {'description': 'Perform '
                                                                               'a '
                                                                               'PCAP '
                                                                               'on '
                                                                               'macOS. '
                                                                               'This '
                                                                               'will '
                                                                               'require '
                                                                               'Wireshark/tshark '
                                                                               'to '
                                                                               'be '
                                                                               'installed. '
                                                                               'TCPdump '
                                                                               'may '
                                                                               'already '
                                                                               'be '
                                                                               'installed.\n'
                                                                               '\n'
                                                                               'Upon '
                                                                               'successful '
                                                                               'execution, '
                                                                               'tshark '
                                                                               'or '
                                                                               'tcpdump '
                                                                               'will '
                                                                               'execute '
                                                                               'and '
                                                                               'capture '
                                                                               '5 '
                                                                               'packets '
                                                                               'on '
                                                                               'interface '
                                                                               'en0A.\n',
                                                                'executor': {'command': 'tcpdump '
                                                                                        '-c '
                                                                                        '5 '
                                                                                        '-nnni '
                                                                                        '#{interface}\n'
                                                                                        'tshark '
                                                                                        '-c '
                                                                                        '5 '
                                                                                        '-i '
                                                                                        '#{interface}\n',
                                                                             'elevation_required': True,
                                                                             'name': 'bash'},
                                                                'input_arguments': {'interface': {'default': 'en0A',
                                                                                                  'description': 'Specify '
                                                                                                                 'interface '
                                                                                                                 'to '
                                                                                                                 'perform '
                                                                                                                 'PCAP '
                                                                                                                 'on.',
                                                                                                  'type': 'String'}},
                                                                'name': 'Packet '
                                                                        'Capture '
                                                                        'macOS',
                                                                'supported_platforms': ['macos']},
                                                               {'description': 'Perform '
                                                                               'a '
                                                                               'packet '
                                                                               'capture '
                                                                               'using '
                                                                               'the '
                                                                               'windows '
                                                                               'command '
                                                                               'prompt. '
                                                                               'This '
                                                                               'will '
                                                                               'require '
                                                                               'a '
                                                                               'host '
                                                                               'that '
                                                                               'has '
                                                                               'Wireshark/Tshark\n'
                                                                               'installed, '
                                                                               'along '
                                                                               'with '
                                                                               'WinPCAP. '
                                                                               'Windump '
                                                                               'will '
                                                                               'require '
                                                                               'the '
                                                                               'windump '
                                                                               'executable.\n'
                                                                               '\n'
                                                                               'Upon '
                                                                               'successful '
                                                                               'execution, '
                                                                               'tshark '
                                                                               'will '
                                                                               'execute '
                                                                               'and '
                                                                               'capture '
                                                                               '5 '
                                                                               'packets '
                                                                               'on '
                                                                               'interface '
                                                                               'Ethernet0.\n',
                                                                'executor': {'command': '"c:\\Program '
                                                                                        'Files\\Wireshark\\tshark.exe" '
                                                                                        '-i '
                                                                                        '#{interface} '
                                                                                        '-c '
                                                                                        '5\n'
                                                                                        'c:\\windump.exe\n',
                                                                             'elevation_required': True,
                                                                             'name': 'command_prompt'},
                                                                'input_arguments': {'interface': {'default': 'Ethernet0',
                                                                                                  'description': 'Specify '
                                                                                                                 'interface '
                                                                                                                 'to '
                                                                                                                 'perform '
                                                                                                                 'PCAP '
                                                                                                                 'on.',
                                                                                                  'type': 'String'}},
                                                                'name': 'Packet '
                                                                        'Capture '
                                                                        'Windows '
                                                                        'Command '
                                                                        'Prompt',
                                                                'supported_platforms': ['windows']},
                                                               {'description': 'Perform '
                                                                               'a '
                                                                               'packet '
                                                                               'capture '
                                                                               'using '
                                                                               'PowerShell '
                                                                               'with '
                                                                               'windump '
                                                                               'or '
                                                                               'tshark. '
                                                                               'This '
                                                                               'will '
                                                                               'require '
                                                                               'a '
                                                                               'host '
                                                                               'that '
                                                                               'has '
                                                                               'Wireshark/Tshark\n'
                                                                               'installed, '
                                                                               'along '
                                                                               'with '
                                                                               'WinPCAP. '
                                                                               'Windump '
                                                                               'will '
                                                                               'require '
                                                                               'the '
                                                                               'windump '
                                                                               'executable.\n'
                                                                               '\n'
                                                                               'Upon '
                                                                               'successful '
                                                                               'execution, '
                                                                               'tshark '
                                                                               'will '
                                                                               'spawn '
                                                                               'from '
                                                                               'powershell '
                                                                               'and '
                                                                               'capture '
                                                                               '5 '
                                                                               'packets '
                                                                               'on '
                                                                               'interface '
                                                                               'Ethernet0.\n',
                                                                'executor': {'command': '& '
                                                                                        '"c:\\Program '
                                                                                        'Files\\Wireshark\\tshark.exe" '
                                                                                        '-i '
                                                                                        '#{interface} '
                                                                                        '-c '
                                                                                        '5\n'
                                                                                        '& '
                                                                                        'c:\\windump.exe\n',
                                                                             'elevation_required': True,
                                                                             'name': 'powershell'},
                                                                'input_arguments': {'interface': {'default': 'Ethernet0',
                                                                                                  'description': 'Specify '
                                                                                                                 'interface '
                                                                                                                 'to '
                                                                                                                 'perform '
                                                                                                                 'PCAP '
                                                                                                                 'on.',
                                                                                                  'type': 'String'}},
                                                                'name': 'Packet '
                                                                        'Capture '
                                                                        'PowerShell',
                                                                'supported_platforms': ['windows']}],
                                              'attack_technique': 'T1040',
                                              'display_name': 'Network '
                                                              'Sniffing'}},
 {'Mitre Stockpile - Perform a packet capture': {'description': 'Perform a '
                                                                'packet '
                                                                'capture',
                                                 'id': '1b4fb81c-8090-426c-93ab-0a633e7a16a7',
                                                 'name': 'Sniff network '
                                                         'traffic',
                                                 'platforms': {'darwin': {'sh': {'command': 'tcpdump '
                                                                                            '-i '
                                                                                            'en0 '
                                                                                            '& '
                                                                                            'sleep '
                                                                                            '5; '
                                                                                            'kill '
                                                                                            '$!\n'}},
                                                               'windows': {'psh': {'cleanup': 'Remove-NetEventSession '
                                                                                              '-Name '
                                                                                              '"Capture"\n'
                                                                                              'Remove-Item '
                                                                                              '$ENV:UserProfile\\Desktop\\pcap.etl\n'
                                                                                              'Remove-Item '
                                                                                              '$ENV:UserProfile\\Desktop\\pcap.cab\n',
                                                                                   'command': 'New-NetEventSession '
                                                                                              '-Name '
                                                                                              '"PCAP" '
                                                                                              '-CaptureMode '
                                                                                              'SaveToFile '
                                                                                              '-LocalFilePath '
                                                                                              '"$ENV:UserProfile\\Desktop\\pcap.etl" '
                                                                                              '-MaxFileSize '
                                                                                              '0\n'
                                                                                              'Add-NetEventPacketCaptureProvider '
                                                                                              '-SessionName '
                                                                                              '"PCAP"\n'
                                                                                              'Start-NetEventSession '
                                                                                              '-Name '
                                                                                              '"PCAP"\n'
                                                                                              'Start-Sleep '
                                                                                              '-s '
                                                                                              '60\n'
                                                                                              'Stop-NetEventSession '
                                                                                              '-Name '
                                                                                              '"PCAP"\n'
                                                                                              'Get-Content '
                                                                                              '"$ENV:UserProfile\\Desktop\\pcap.etl"\n'}}},
                                                 'tactic': 'credential-access',
                                                 'technique': {'attack_id': 'T1040',
                                                               'name': 'Network '
                                                                       'Sniffing'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1040',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/packet_capture":  '
                                                                                 '["T1040"],',
                                            'Empire Module': 'powershell/collection/packet_capture',
                                            'Technique': 'Network Sniffing'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1040',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/linux/sniffer":  '
                                                                                 '["T1040"],',
                                            'Empire Module': 'python/collection/linux/sniffer',
                                            'Technique': 'Network Sniffing'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1040',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/sniffer":  '
                                                                                 '["T1040"],',
                                            'Empire Module': 'python/collection/osx/sniffer',
                                            'Technique': 'Network Sniffing'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)

* [Discovery](../tactics/Discovery.md)
    

# Mitigations

None

# Actors


* [APT28](../actors/APT28.md)

* [Stolen Pencil](../actors/Stolen-Pencil.md)
    
* [APT33](../actors/APT33.md)
    
