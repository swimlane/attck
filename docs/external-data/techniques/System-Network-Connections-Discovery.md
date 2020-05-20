
# System Network Connections Discovery

## Description

### MITRE Description

> Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. 

An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected. The actions performed are likely the same types of discovery techniques depending on the operating system, but the resulting information may include details about the networked cloud environment relevant to the adversary's goals. Cloud providers may have different ways in which their virtual networks operate.(Citation: Amazon AWS VPC Guide)(Citation: Microsoft Azure Virtual Network Overview)(Citation: Google VPC Overview)

### Windows

Utilities and commands that acquire this information include [netstat](https://attack.mitre.org/software/S0104), "net use," and "net session" with [Net](https://attack.mitre.org/software/S0039).

### Mac and Linux 

In Mac and Linux, <code>netstat</code> and <code>lsof</code> can be used to list current connections. <code>who -a</code> and <code>w</code> can be used to show which users are currently logged in, similar to "net session".

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1049

## Potential Commands

```
netstat -ano[b] 
shell c:\windows\sysnative\netstat.exe -ano[b]
post/windows/gather/tcpnetstat
net session | find / "\\"
shell net session | find / "\\"
post/windows/gather/enum_logged_on_users
netstat
net use
net sessions

Get-NetTCPConnection

netstat
who -a

{'windows': {'psh': {'command': 'netstat -ano;\nGet-NetTCPConnection'}}}
{'darwin': {'sh': {'command': 'netstat -ant\n'}}, 'linux': {'sh': {'command': 'netstat -ant\n'}}, 'windows': {'psh': {'command': 'Get-NetTCPConnection\n'}}}
powershell/situational_awareness/host/monitortcpconnections
powershell/situational_awareness/host/monitortcpconnections
powershell/situational_awareness/network/powerview/get_rdp_session
powershell/situational_awareness/network/powerview/get_rdp_session
Dos
C: \ Users \ Administrator> netstat

Active connections

Protocol local address external address status
Dos
C: \ Users \ Administrator> net use
It will record a new network connection.

List is empty.
Dos
C: \ Users \ Administrator> net session
List is empty.
```

## Commands Dataset

```
[{'command': 'netstat -ano[b] ',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell c:\\windows\\sysnative\\netstat.exe -ano[b]',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'post/windows/gather/tcpnetstat',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'net session | find / "\\\\"',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell net session | find / "\\\\"',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'post/windows/gather/enum_logged_on_users',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'netstat\nnet use\nnet sessions\n',
  'name': None,
  'source': 'atomics/T1049/T1049.yaml'},
 {'command': 'Get-NetTCPConnection\n',
  'name': None,
  'source': 'atomics/T1049/T1049.yaml'},
 {'command': 'netstat\nwho -a\n',
  'name': None,
  'source': 'atomics/T1049/T1049.yaml'},
 {'command': {'windows': {'psh': {'command': 'netstat -ano;\n'
                                             'Get-NetTCPConnection'}}},
  'name': 'Enumerates network connections',
  'source': 'data/abilities/discovery/613e0ffb-e6e8-4e86-b35d-10edd232679d.yml'},
 {'command': {'darwin': {'sh': {'command': 'netstat -ant\n'}},
              'linux': {'sh': {'command': 'netstat -ant\n'}},
              'windows': {'psh': {'command': 'Get-NetTCPConnection\n'}}},
  'name': 'Find System Network Connections',
  'source': 'data/abilities/discovery/638fb6bb-ba39-4285-93d1-7e4775b033a8.yml'},
 {'command': 'powershell/situational_awareness/host/monitortcpconnections',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/host/monitortcpconnections',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_rdp_session',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_rdp_session',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'Dos\n'
             'C: \\ Users \\ Administrator> netstat\n'
             '\n'
             'Active connections\n'
             '\n'
             'Protocol local address external address status',
  'name': 'Dos',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Dos\n'
             'C: \\ Users \\ Administrator> net use\n'
             'It will record a new network connection.\n'
             '\n'
             'List is empty.',
  'name': 'Dos',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Dos\nC: \\ Users \\ Administrator> net session\nList is empty.',
  'name': 'Dos',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json
[{'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']}]
```

## Potential Queries

```json
[{'name': 'System Network Connections Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains "net.exe"or '
           'process_path contains "netstat.exe")and (process_command_line '
           'contains "*net* use*"or process_command_line contains "*net* '
           'sessions*"or process_command_line contains "*net* file*"or '
           'process_command_line contains "*netstat*")or process_command_line '
           'contains "*Get-NetTCPConnection*"'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows system network link found\n'
           'description: windows server 2016\n'
           'references:\n'
           'tags: T1049\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ NETSTAT.EXE' # process information> new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ windows "
           "\\ system32 \\ cmd.exe' # Process Information> Creator Process "
           'Name\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: netstat # '
           'Process information> process command line\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4703 # a user's "
           'privileges to be adjusted.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ProcessName: 'C: \\ Windows \\ "
           "System32 \\ NETSTAT.EXE' # process information> process name\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EnabledPrivileges: '
           "'SeDebugPrivilege' permission enabled #\n"
           '\xa0\xa0\xa0\xa0selection3:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4689 # exited process\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ProcessName: 'C: \\ Windows \\ "
           "System32 \\ NETSTAT.EXE' # process information> process name\n"
           '\xa0\xa0\xa0\xa0timeframe: last 5s # can be adjusted according to '
           'actual situation\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows system network link found\n'
           'description: windows server 2016\n'
           'references:\n'
           'tags: T1049\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ net.exe' # process information> new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ windows "
           "\\ system32 \\ cmd.exe' # Process Information> Creator Process "
           'Name\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: net use # '
           'Process Information> process command line\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4689 # exited process\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ProcessName: 'C: \\ Windows \\ "
           "System32 \\ net.exe' # process information> process name\n"
           '\xa0\xa0\xa0\xa0timeframe: last 5s # can be adjusted according to '
           'actual situation\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows system network link found\n'
           'description: windows server 2016\n'
           'references:\n'
           'tags: T1049\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ net.exe' # process information> new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ windows "
           "\\ system32 \\ cmd.exe' # Process Information> Creator Process "
           'Name\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: net session # '
           'Process Information> process command line\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ net1.exe' # process information> new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ Windows "
           "\\ System32 \\ net.exe' # Process Information> Creator Process "
           'Name\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: C: \\ Windows '
           '\\ system32 \\ net1 session # Process Information> process command '
           'line\n'
           '\xa0\xa0\xa0\xa0selection3:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4689 # exited process\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ProcessName: 'C: \\ Windows \\ "
           "System32 \\ net1.exe' # process information> process name\n"
           '\xa0\xa0\xa0\xa0selection4:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4689 # exited process\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ProcessName: 'C: \\ Windows \\ "
           "System32 \\ net.exe' # process information> process name\n"
           '\xa0\xa0\xa0\xa0timeframe: last 1m # can be adjusted according to '
           'actual situation\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'netstat '
                                                                              '-ano[b] ',
                                                  'Category': 'T1049',
                                                  'Cobalt Strike': 'shell '
                                                                   'c:\\windows\\sysnative\\netstat.exe '
                                                                   '-ano[b]',
                                                  'Description': 'Display '
                                                                 'current '
                                                                 'TCP/IP '
                                                                 'network '
                                                                 'connections '
                                                                 '(b requires '
                                                                 'elevated '
                                                                 'privs so you '
                                                                 'can see the '
                                                                 'process that '
                                                                 'opened the '
                                                                 'connection)',
                                                  'Metasploit': 'post/windows/gather/tcpnetstat'}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'net '
                                                                              'session '
                                                                              '| '
                                                                              'find '
                                                                              '/ '
                                                                              '"\\\\"',
                                                  'Category': 'T1049',
                                                  'Cobalt Strike': 'shell net '
                                                                   'session | '
                                                                   'find / '
                                                                   '"\\\\"',
                                                  'Description': 'Display the '
                                                                 'list of '
                                                                 'active SMB '
                                                                 'sessions on '
                                                                 'the '
                                                                 'workstation '
                                                                 'so you can '
                                                                 'see which '
                                                                 'users have '
                                                                 'active '
                                                                 'connections.',
                                                  'Metasploit': 'post/windows/gather/enum_logged_on_users'}},
 {'Atomic Red Team Test - System Network Connections Discovery': {'atomic_tests': [{'auto_generated_guid': '0940a971-809a-48f1-9c4d-b1d785e96ee5',
                                                                                    'description': 'Get '
                                                                                                   'a '
                                                                                                   'listing '
                                                                                                   'of '
                                                                                                   'network '
                                                                                                   'connections.\n'
                                                                                                   '\n'
                                                                                                   'Upon '
                                                                                                   'successful '
                                                                                                   'execution, '
                                                                                                   'cmd.exe '
                                                                                                   'will '
                                                                                                   'execute '
                                                                                                   '`netstat`, '
                                                                                                   '`net '
                                                                                                   'use` '
                                                                                                   'and '
                                                                                                   '`net '
                                                                                                   'sessions`. '
                                                                                                   'Results '
                                                                                                   'will '
                                                                                                   'output '
                                                                                                   'via '
                                                                                                   'stdout.\n',
                                                                                    'executor': {'command': 'netstat\n'
                                                                                                            'net '
                                                                                                            'use\n'
                                                                                                            'net '
                                                                                                            'sessions\n',
                                                                                                 'elevation_required': False,
                                                                                                 'name': 'command_prompt'},
                                                                                    'name': 'System '
                                                                                            'Network '
                                                                                            'Connections '
                                                                                            'Discovery',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': 'f069f0f1-baad-4831-aa2b-eddac4baac4a',
                                                                                    'description': 'Get '
                                                                                                   'a '
                                                                                                   'listing '
                                                                                                   'of '
                                                                                                   'network '
                                                                                                   'connections.\n'
                                                                                                   '\n'
                                                                                                   'Upon '
                                                                                                   'successful '
                                                                                                   'execution, '
                                                                                                   'powershell.exe '
                                                                                                   'will '
                                                                                                   'execute '
                                                                                                   '`get-NetTCPConnection`. '
                                                                                                   'Results '
                                                                                                   'will '
                                                                                                   'output '
                                                                                                   'via '
                                                                                                   'stdout.\n',
                                                                                    'executor': {'command': 'Get-NetTCPConnection\n',
                                                                                                 'elevation_required': False,
                                                                                                 'name': 'powershell'},
                                                                                    'name': 'System '
                                                                                            'Network '
                                                                                            'Connections '
                                                                                            'Discovery '
                                                                                            'with '
                                                                                            'PowerShell',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': '9ae28d3f-190f-4fa0-b023-c7bd3e0eabf2',
                                                                                    'dependencies': [{'description': 'Check '
                                                                                                                     'if '
                                                                                                                     'netstat '
                                                                                                                     'command '
                                                                                                                     'exists '
                                                                                                                     'on '
                                                                                                                     'the '
                                                                                                                     'machine\n',
                                                                                                      'get_prereq_command': 'echo '
                                                                                                                            '"Install '
                                                                                                                            'netstat '
                                                                                                                            'on '
                                                                                                                            'the '
                                                                                                                            'machine."; '
                                                                                                                            'exit '
                                                                                                                            '1;\n',
                                                                                                      'prereq_command': 'if '
                                                                                                                        '[ '
                                                                                                                        '-x '
                                                                                                                        '"$(command '
                                                                                                                        '-v '
                                                                                                                        'netstat)" '
                                                                                                                        ']; '
                                                                                                                        'then '
                                                                                                                        'exit '
                                                                                                                        '0; '
                                                                                                                        'else '
                                                                                                                        'exit '
                                                                                                                        '1;\n'}],
                                                                                    'dependency_executor_name': 'sh',
                                                                                    'description': 'Get '
                                                                                                   'a '
                                                                                                   'listing '
                                                                                                   'of '
                                                                                                   'network '
                                                                                                   'connections.\n'
                                                                                                   '\n'
                                                                                                   'Upon '
                                                                                                   'successful '
                                                                                                   'execution, '
                                                                                                   'sh '
                                                                                                   'will '
                                                                                                   'execute '
                                                                                                   '`netstat` '
                                                                                                   'and '
                                                                                                   '`who '
                                                                                                   '-a`. '
                                                                                                   'Results '
                                                                                                   'will '
                                                                                                   'output '
                                                                                                   'via '
                                                                                                   'stdout.\n',
                                                                                    'executor': {'command': 'netstat\n'
                                                                                                            'who '
                                                                                                            '-a\n',
                                                                                                 'elevation_required': False,
                                                                                                 'name': 'sh'},
                                                                                    'name': 'System '
                                                                                            'Network '
                                                                                            'Connections '
                                                                                            'Discovery '
                                                                                            'Linux '
                                                                                            '& '
                                                                                            'MacOS',
                                                                                    'supported_platforms': ['linux',
                                                                                                            'macos']}],
                                                                  'attack_technique': 'T1049',
                                                                  'display_name': 'System '
                                                                                  'Network '
                                                                                  'Connections '
                                                                                  'Discovery'}},
 {'Mitre Stockpile - Enumerates network connections': {'description': 'Enumerates '
                                                                      'network '
                                                                      'connections',
                                                       'id': '613e0ffb-e6e8-4e86-b35d-10edd232679d',
                                                       'name': 'System Network '
                                                               'Connections '
                                                               'Discovery',
                                                       'platforms': {'windows': {'psh': {'command': 'netstat '
                                                                                                    '-ano;\n'
                                                                                                    'Get-NetTCPConnection'}}},
                                                       'tactic': 'discovery',
                                                       'technique': {'attack_id': 'T1049',
                                                                     'name': 'System '
                                                                             'Network '
                                                                             'Connections '
                                                                             'Discovery'}}},
 {'Mitre Stockpile - Find System Network Connections': {'description': 'Find '
                                                                       'System '
                                                                       'Network '
                                                                       'Connections',
                                                        'id': '638fb6bb-ba39-4285-93d1-7e4775b033a8',
                                                        'name': 'Find System '
                                                                'Network '
                                                                'Connections',
                                                        'platforms': {'darwin': {'sh': {'command': 'netstat '
                                                                                                   '-ant\n'}},
                                                                      'linux': {'sh': {'command': 'netstat '
                                                                                                  '-ant\n'}},
                                                                      'windows': {'psh': {'command': 'Get-NetTCPConnection\n'}}},
                                                        'tactic': 'discovery',
                                                        'technique': {'attack_id': 'T1049',
                                                                      'name': 'System '
                                                                              'Network '
                                                                              'Connections '
                                                                              'Discovery'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1049',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/host/monitortcpconnections":  '
                                                                                 '["T1049"],',
                                            'Empire Module': 'powershell/situational_awareness/host/monitortcpconnections',
                                            'Technique': 'System Network '
                                                         'Connections '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1049',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_rdp_session":  '
                                                                                 '["T1049"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_rdp_session',
                                            'Technique': 'System Network '
                                                         'Connections '
                                                         'Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations

None

# Actors


* [Poseidon Group](../actors/Poseidon-Group.md)

* [menuPass](../actors/menuPass.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT3](../actors/APT3.md)
    
* [APT32](../actors/APT32.md)
    
* [admin@338](../actors/admin@338.md)
    
* [APT1](../actors/APT1.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Turla](../actors/Turla.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT38](../actors/APT38.md)
    
* [APT41](../actors/APT41.md)
    
