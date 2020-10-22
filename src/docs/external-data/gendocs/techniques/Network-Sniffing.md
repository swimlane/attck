
# Network Sniffing

## Description

### MITRE Description

> Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.

Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as [LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001), can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.

Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1040

## Potential Commands

```
tcpdump -c 5 -nnni ens33
tshark -c 5 -i ens33

sudo tcpdump -c 5 -nnni en0A    
if [ -x "$(command -v tshark)" ]; then sudo tshark -c 5 -i en0A; fi;

"c:\Program Files\Wireshark\tshark.exe" -i Ethernet0 -c 5
c:\windump.exe

{'windows': {'psh': {'command': 'New-NetEventSession -Name "PCAP" -CaptureMode SaveToFile -LocalFilePath "$ENV:UserProfile\\Desktop\\pcap.etl" -MaxFileSize 0\nAdd-NetEventPacketCaptureProvider -SessionName "PCAP"\nStart-NetEventSession -Name "PCAP"\nStart-Sleep -s 60\nStop-NetEventSession -Name "PCAP"\nGet-Content "$ENV:UserProfile\\Desktop\\pcap.etl"\n', 'cleanup': 'Remove-NetEventSession -Name "Capture"\nRemove-Item $ENV:UserProfile\\Desktop\\pcap.etl\nRemove-Item $ENV:UserProfile\\Desktop\\pcap.cab\n'}}, 'darwin': {'sh': {'command': 'tcpdump -i en0 & sleep 5; kill $!\n'}}}
powershell/collection/packet_capture
powershell/collection/packet_capture
python/collection/linux/sniffer
python/collection/linux/sniffer
python/collection/osx/sniffer
python/collection/osx/sniffer
tcpdump -c 5 -nnni #{interface}
tshark -c 5 -i #{interface}
```

## Commands Dataset

```
[{'command': 'tcpdump -c 5 -nnni ens33\ntshark -c 5 -i ens33\n',
  'name': None,
  'source': 'atomics/T1040/T1040.yaml'},
 {'command': 'sudo tcpdump -c 5 -nnni en0A    \n'
             'if [ -x "$(command -v tshark)" ]; then sudo tshark -c 5 -i en0A; '
             'fi;\n',
  'name': None,
  'source': 'atomics/T1040/T1040.yaml'},
 {'command': '"c:\\Program Files\\Wireshark\\tshark.exe" -i Ethernet0 -c 5\n'
             'c:\\windump.exe\n',
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
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'tcpdump -c 5 -nnni #{interface}',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'tshark -c 5 -i #{interface}',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'}]
```

## Potential Detections

```json
[{'data_source': '/var/log/messages'},
 {'data_source': {'author': 'Timur Zinniatullin, oscd.community',
                  'date': '2019/10/21',
                  'description': 'Network sniffing refers to using the network '
                                 'interface on a system to monitor or capture '
                                 'information sent over a wired or wireless '
                                 'connection. An adversary may place a network '
                                 'interface into promiscuous mode to passively '
                                 'access data in transit over the network, or '
                                 'use span ports to capture a larger amount of '
                                 'data.',
                  'detection': {'condition': 'selection1 or selection2',
                                'selection1': {'a0': 'tcpdump',
                                               'a1': '-c',
                                               'a3|contains': '-i',
                                               'type': 'execve'},
                                'selection2': {'a0': 'tshark',
                                               'a1': '-c',
                                               'a3': '-i',
                                               'type': 'execve'}},
                  'falsepositives': ['Legitimate administrator or user uses '
                                     'network sniffing tool for legitimate '
                                     'reason'],
                  'id': 'f4d3748a-65d1-4806-bd23-e25728081d01',
                  'level': 'low',
                  'logsource': {'product': 'linux', 'service': 'auditd'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.yaml'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access',
                           'attack.discovery',
                           'attack.t1040'],
                  'title': 'Network Sniffing'}},
 {'data_source': {'author': 'Kutepov Anton, oscd.community',
                  'date': '2019/10/24',
                  'description': 'Detects capture a network trace via '
                                 'netsh.exe trace functionality',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine|contains|all': ['netsh',
                                                                           'trace',
                                                                           'start']}},
                  'falsepositives': ['Legitimate administrator or user uses '
                                     'netsh.exe trace functionality for '
                                     'legitimate reason'],
                  'id': 'd3c3861d-c504-4c77-ba55-224ba82d0118',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/'],
                  'status': 'experimental',
                  'tags': ['attack.discovery', 'attack.t1040'],
                  'title': 'Capture a Network Trace with netsh.exe'}},
 {'data_source': {'author': 'Timur Zinniatullin, oscd.community',
                  'date': '2019/10/21',
                  'description': 'Network sniffing refers to using the network '
                                 'interface on a system to monitor or capture '
                                 'information sent over a wired or wireless '
                                 'connection. An adversary may place a network '
                                 'interface into promiscuous mode to passively '
                                 'access data in transit over the network, or '
                                 'use span ports to capture a larger amount of '
                                 'data.',
                  'detection': {'condition': 'selection',
                                'selection': [{'CommandLine|contains': '-i',
                                               'Image|endswith': '\\tshark.exe'},
                                              {'Image|endswith': '\\windump.exe'}]},
                  'falsepositives': ['Admin activity'],
                  'fields': ['Image',
                             'CommandLine',
                             'User',
                             'LogonGuid',
                             'Hashes',
                             'ParentProcessGuid',
                             'ParentCommandLine'],
                  'id': 'ba1f7802-adc7-48b4-9ecb-81e227fddfd5',
                  'level': 'low',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.yaml'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access',
                           'attack.discovery',
                           'attack.t1040'],
                  'title': 'Network Sniffing'}},
 {'data_source': ['Network device logs']},
 {'data_source': ['Host network interface']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['Network device logs']},
 {'data_source': ['Host network interface']},
 {'data_source': ['Netflow/Enclave netflow']}]
```

## Potential Queries

```json
[{'name': 'Network Sniffing',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains '
           '"tshark.exe"or process_path contains "windump.exe"or process_path '
           'contains "logman.exe"or process_path contains "tcpdump.exe"or '
           'process_path contains "wprui.exe"or process_path contains '
           '"wpr.exe")'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=syslog entered promiscuous mode | table '
           'host,message'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=syslog left promiscuous mode | table '
           'host,message'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Network Sniffing': {'atomic_tests': [{'auto_generated_guid': '7fe741f7-b265-4951-a7c7-320889083b3e',
                                                                'dependencies': [{'description': 'Check '
                                                                                                 'if '
                                                                                                 'at '
                                                                                                 'least '
                                                                                                 'one '
                                                                                                 'of '
                                                                                                 'the '
                                                                                                 'tools '
                                                                                                 'are '
                                                                                                 'installed '
                                                                                                 'on '
                                                                                                 'the '
                                                                                                 'machine.\n',
                                                                                  'get_prereq_command': 'echo '
                                                                                                        '"Install '
                                                                                                        'tcpdump '
                                                                                                        'and/or '
                                                                                                        'tshark '
                                                                                                        'for '
                                                                                                        'the '
                                                                                                        'test '
                                                                                                        'to '
                                                                                                        'run."; '
                                                                                                        'exit '
                                                                                                        '1;\n',
                                                                                  'prereq_command': 'if '
                                                                                                    '[ '
                                                                                                    '! '
                                                                                                    '-x '
                                                                                                    '"$(command '
                                                                                                    '-v '
                                                                                                    'tcpdump)" '
                                                                                                    '] '
                                                                                                    '&& '
                                                                                                    '[ '
                                                                                                    '! '
                                                                                                    '-x '
                                                                                                    '"$(command '
                                                                                                    '-v '
                                                                                                    'tshark)" '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'exit '
                                                                                                    '1; '
                                                                                                    'else '
                                                                                                    'exit '
                                                                                                    '0; '
                                                                                                    'fi;\n'}],
                                                                'dependency_executor_name': 'bash',
                                                                'description': 'Perform '
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
                                                                               'ens33.\n',
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
                                                               {'auto_generated_guid': '9d04efee-eff5-4240-b8d2-07792b873608',
                                                                'dependencies': [{'description': 'Check '
                                                                                                 'if '
                                                                                                 'at '
                                                                                                 'least '
                                                                                                 'one '
                                                                                                 'of '
                                                                                                 'the '
                                                                                                 'tools '
                                                                                                 'are '
                                                                                                 'installed '
                                                                                                 'on '
                                                                                                 'the '
                                                                                                 'machine.\n',
                                                                                  'get_prereq_command': 'echo '
                                                                                                        '"Install '
                                                                                                        'tcpdump '
                                                                                                        'and/or '
                                                                                                        'tshark '
                                                                                                        'for '
                                                                                                        'the '
                                                                                                        'test '
                                                                                                        'to '
                                                                                                        'run."; '
                                                                                                        'exit '
                                                                                                        '1;\n',
                                                                                  'prereq_command': 'if '
                                                                                                    '[ '
                                                                                                    '! '
                                                                                                    '-x '
                                                                                                    '"$(command '
                                                                                                    '-v '
                                                                                                    'tcpdump)" '
                                                                                                    '] '
                                                                                                    '&& '
                                                                                                    '[ '
                                                                                                    '! '
                                                                                                    '-x '
                                                                                                    '"$(command '
                                                                                                    '-v '
                                                                                                    'tshark)" '
                                                                                                    ']; '
                                                                                                    'then '
                                                                                                    'exit '
                                                                                                    '1; '
                                                                                                    'else '
                                                                                                    'exit '
                                                                                                    '0; '
                                                                                                    'fi;\n'}],
                                                                'dependency_executor_name': 'bash',
                                                                'description': 'Perform '
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
                                                                'executor': {'command': 'sudo '
                                                                                        'tcpdump '
                                                                                        '-c '
                                                                                        '5 '
                                                                                        '-nnni '
                                                                                        '#{interface}    \n'
                                                                                        'if '
                                                                                        '[ '
                                                                                        '-x '
                                                                                        '"$(command '
                                                                                        '-v '
                                                                                        'tshark)" '
                                                                                        ']; '
                                                                                        'then '
                                                                                        'sudo '
                                                                                        'tshark '
                                                                                        '-c '
                                                                                        '5 '
                                                                                        '-i '
                                                                                        '#{interface}; '
                                                                                        'fi;\n',
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
                                                               {'auto_generated_guid': 'a5b2f6a0-24b4-493e-9590-c699f75723ca',
                                                                'description': 'Perform '
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


* [Network Sniffing Mitigation](../mitigations/Network-Sniffing-Mitigation.md)

* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)
    
* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)
    

# Actors


* [APT28](../actors/APT28.md)

* [Stolen Pencil](../actors/Stolen-Pencil.md)
    
* [APT33](../actors/APT33.md)
    
* [DarkVishnya](../actors/DarkVishnya.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
