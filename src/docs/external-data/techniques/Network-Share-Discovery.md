
# Network Share Discovery

## Description

### MITRE Description

> Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network. 

### Windows

File sharing over a Windows network occurs over the SMB protocol. (Citation: Wikipedia Shared Resource) (Citation: TechNet Shared Folder)

[Net](https://attack.mitre.org/software/S0039) can be used to query a remote system for available shared drives using the <code>net view \\remotesystem</code> command. It can also be used to query shared drives on the local system using <code>net share</code>.

Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement.

### Mac

On Mac, locally mounted shares can be viewed with the <code>df -aH</code> command.

### Cloud

Cloud virtual networks may contain remote network shares or file storage services accessible to an adversary after they have obtained access to a system. For example, AWS, GCP, and Azure support creation of Network File System (NFS) shares and Server Message Block (SMB) shares that may be mapped on endpoint or cloud-based systems.(Citation: Amazon Creating an NFS File Share)(Citation: Google File servers on Compute Engine)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['macOS', 'Windows', 'AWS', 'GCP', 'Azure']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1135

## Potential Commands

```
net share
net share
auxiliary/scanner/smb/smb_enumshares
net view \\host /all [/domain:domain]
net view \\host /domain
auxiliary/scanner/smb/smb_enumshares
df -aH
smbutil view -g //computer1
showmount computer1

net view \\localhost

net view \\localhost
get-smbshare -Name localhost

net share

{'windows': {'pwsh,psh': {'command': 'Get-SmbShare | ConvertTo-Json', 'parsers': {'plugins.stockpile.app.parsers.json': [{'source': 'domain.smb.share', 'json_key': 'Path', 'json_type': ['str']}]}}}}
{'windows': {'psh': {'command': 'net view \\\\#{remote.host.fqdn} /all', 'parsers': {'plugins.stockpile.app.parsers.net_view': [{'source': 'remote.host.fqdn', 'edge': 'has_share', 'target': 'remote.host.share'}]}}, 'cmd': {'command': 'net view \\\\#{remote.host.fqdn} /all', 'parsers': {'plugins.stockpile.app.parsers.net_view': [{'source': 'remote.host.fqdn', 'edge': 'has_share', 'target': 'remote.host.share'}]}}}}
powershell/situational_awareness/network/powerview/get_dfs_share
powershell/situational_awareness/network/powerview/get_dfs_share
powershell/situational_awareness/network/powerview/share_finder
powershell/situational_awareness/network/powerview/share_finder
python/situational_awareness/network/active_directory/get_fileservers
python/situational_awareness/network/active_directory/get_fileservers
python/situational_awareness/network/smb_mount
python/situational_awareness/network/smb_mount
Dos
C: \ Windows \ system32> net view \\ OWA2010SP3.0day.org
In the shared resource \\ OWA2010SP3.0day.org



Share name for the type of use annotations

-------------------------------------------------- -----------------------------
Address Disk "Access to address objects"
CertEnroll Disk Active Directory Certificate Services Share
ExchangeOAB Disk OAB Distribution share
GroupMetrics Disk group metrics MailTips publishing point
NETLOGON Disk Logon server share
SYSVOL Disk Logon server share
The command completed successfully.
```

## Commands Dataset

```
[{'command': 'net share',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'net share',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'auxiliary/scanner/smb/smb_enumshares',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'net view \\\\host /all [/domain:domain]',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'net view \\\\host /domain',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'auxiliary/scanner/smb/smb_enumshares',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'df -aH\nsmbutil view -g //computer1\nshowmount computer1\n',
  'name': None,
  'source': 'atomics/T1135/T1135.yaml'},
 {'command': 'net view \\\\localhost\n',
  'name': None,
  'source': 'atomics/T1135/T1135.yaml'},
 {'command': 'net view \\\\localhost\nget-smbshare -Name localhost\n',
  'name': None,
  'source': 'atomics/T1135/T1135.yaml'},
 {'command': 'net share\n', 'name': None, 'source': 'atomics/T1135/T1135.yaml'},
 {'command': {'windows': {'pwsh,psh': {'command': 'Get-SmbShare | '
                                                  'ConvertTo-Json',
                                       'parsers': {'plugins.stockpile.app.parsers.json': [{'json_key': 'Path',
                                                                                           'json_type': ['str'],
                                                                                           'source': 'domain.smb.share'}]}}}},
  'name': 'Network Share Discovery',
  'source': 'data/abilities/discovery/530e47c6-8592-42bf-91df-c59ffbd8541b.yml'},
 {'command': {'windows': {'cmd': {'command': 'net view \\\\#{remote.host.fqdn} '
                                             '/all',
                                  'parsers': {'plugins.stockpile.app.parsers.net_view': [{'edge': 'has_share',
                                                                                          'source': 'remote.host.fqdn',
                                                                                          'target': 'remote.host.share'}]}},
                          'psh': {'command': 'net view \\\\#{remote.host.fqdn} '
                                             '/all',
                                  'parsers': {'plugins.stockpile.app.parsers.net_view': [{'edge': 'has_share',
                                                                                          'source': 'remote.host.fqdn',
                                                                                          'target': 'remote.host.share'}]}}}},
  'name': 'View the shares of a remote host',
  'source': 'data/abilities/discovery/deeac480-5c2a-42b5-90bb-41675ee53c7e.yml'},
 {'command': 'powershell/situational_awareness/network/powerview/get_dfs_share',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_dfs_share',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/share_finder',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/share_finder',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_fileservers',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_fileservers',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/smb_mount',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/smb_mount',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'Dos\n'
             'C: \\ Windows \\ system32> net view \\\\ OWA2010SP3.0day.org\n'
             'In the shared resource \\\\ OWA2010SP3.0day.org\n'
             '\n'
             '\n'
             '\n'
             'Share name for the type of use annotations\n'
             '\n'
             '-------------------------------------------------- '
             '-----------------------------\n'
             'Address Disk "Access to address objects"\n'
             'CertEnroll Disk Active Directory Certificate Services Share\n'
             'ExchangeOAB Disk OAB Distribution share\n'
             'GroupMetrics Disk group metrics MailTips publishing point\n'
             'NETLOGON Disk Logon server share\n'
             'SYSVOL Disk Logon server share\n'
             'The command completed successfully.',
  'name': 'Dos',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json
[{'data_source': {'action': 'global',
                  'author': 'Markus Neis',
                  'date': '2017/11/07',
                  'description': 'Detects automated lateral movement by Turla '
                                 'group',
                  'falsepositives': ['Unknown'],
                  'id': 'c601f20d-570a-4cde-a7d6-e17f99cb8e7f',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://securelist.com/the-epic-turla-operation/65545/'],
                  'status': 'experimental',
                  'tags': ['attack.g0010',
                           'attack.execution',
                           'attack.t1059',
                           'attack.lateral_movement',
                           'attack.t1077',
                           'attack.discovery',
                           'attack.t1083',
                           'attack.t1135'],
                  'title': 'Turla Group Lateral Movement'}},
 {'data_source': {'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['net use '
                                                              '\\\\%DomainController%\\C$ '
                                                              '"P@ssw0rd" *',
                                                              'dir '
                                                              'c:\\\\*.doc* /s',
                                                              'dir '
                                                              '%TEMP%\\\\*.exe']}},
                  'level': 'critical'}},
 {'data_source': {'detection': {'condition': 'netCommand1 | near netCommand2 '
                                             'and netCommand3',
                                'netCommand1': {'CommandLine': 'net view '
                                                               '/DOMAIN'},
                                'netCommand2': {'CommandLine': 'net session'},
                                'netCommand3': {'CommandLine': 'net share'},
                                'timeframe': '1m'},
                  'level': 'medium'}}]
```

## Potential Queries

```json
[{'name': 'Network Share Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where process_path contains "net.exe"and '
           '(process_command_line contains "view"or process_command_line '
           'contains "share")'},
 {'name': 'Network Share Discovery Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains "net.exe"and '
           '(process_command_line contains "net view"or process_command_line '
           'contains "net share"))or process_command_line contains '
           '"get-smbshare -Name"'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows network share discovery (windows server 2016) '
           'Detection\n'
           'description: windows server 2016, windows server 2012, domain '
           'environment\n'
           'tags: T1135\n'
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
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: net view \\\\ '
           '* # Process Information> process command line\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4703 # adjusted user '
           'rights. Note This event enabled more than 2016 windows server '
           'system\n'
           '\xa0\xa0\xa0\xa0selection3:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 5158 #Windows screening '
           'platform has been allowed to bind the local port. Note that the '
           'source port, protocol\n'
           '\xa0\xa0\xa0\xa0selection4:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 5156 #Windows screening '
           'platform has been allowed to connect.\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Direction: Outbound network '
           'information #> Direction: Outbound\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Sourceaddress: * # IP address of '
           'the host to initiate inquiry\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Sourceport: * # 5158 and the same '
           'event source port\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Targetaddress: * # destination IP '
           'address\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Targetport: 445 # destination '
           'port\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Agreement: * # protocol, the same '
           'protocol and 5158\n'
           '\xa0\xa0\xa0\xa0selection5:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4689 # exited process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processname: 'C: \\ Windows \\ "
           "System32 \\ net.exe' # process information> process name\n"
           '\xa0\xa0\xa0\xa0timeframe: last 5s # can be adjusted according to '
           'actual situation\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows network share discovery (windows server 2012) '
           'Detection\n'
           'description: windows server 2016, windows server 2012, domain '
           'environment\n'
           'tags: T1135\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 5156 #Windows screening '
           'platform has been allowed to connect.\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Direction: Inbound network '
           'information #> Direction: Inbound\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Sourceaddress: * # queried host IP '
           'address\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Sourceport: 445\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Targetaddress: * # Destination '
           'Address IP address of the host to initiate queries\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Targetport: * # target host port '
           'IP port to initiate queries\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Agreement: * # protocol, the 5156 '
           'and 2016 events, 5158 incident involving a consensual agreement\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4702 # assigned special '
           'permissions for the new login.\n'
           '\xa0\xa0\xa0\xa0selection3:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4624 # account was '
           'successfully logged.\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0logontype: 3 # 3 type landing\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Sourcenetworkaddress: * # Network '
           'Information> source network address above 5156 target address\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Sourceport: * # Network '
           'Information> source network port above 5156 target port\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Loginprocess: Kerberos # detailed '
           'authentication information> login process\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Authenticationpackage: Kerberos # '
           'Detailed Authentication Information> Authentication Package\n'
           '\xa0\xa0\xa0\xa0selection4:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 5140 # visited network '
           'shared objects.\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Objecttype: file # Network '
           'Information> Object Type\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Sourceaddress: * # Network '
           'Information> source address above 5156 target address\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Sourceport: * # Network '
           'Information> source port destination port above 5156\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Sharename: \\\\ * \\ IPC $ # Share '
           'Information> Share name\n'
           '\xa0\xa0\xa0\xa0selection5:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 5140 # visited network '
           'shared objects.\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Objecttype: file # Network '
           'Information> Object Type\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Sourceaddress: * # Network '
           'Information> source address above 5156 target address\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Sourceport: * # Network '
           'Information> source port destination port above 5156\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Sharename: \\\\ * \\ IPC $ # Share '
           'Information> Share name\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Relativetargetname: srvsvc # Share '
           'Information> relative to the target name\n'
           '\xa0\xa0\xa0\xa0timeframe: last 10s # can be adjusted according to '
           'actual situation\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'net '
                                                                              'share',
                                                  'Category': 'T1135',
                                                  'Cobalt Strike': 'net share',
                                                  'Description': 'Used to view '
                                                                 'network '
                                                                 'shared '
                                                                 'resource '
                                                                 'information, '
                                                                 'share a new '
                                                                 'network '
                                                                 'resource, '
                                                                 'and remove '
                                                                 'an old '
                                                                 'shared '
                                                                 'network '
                                                                 'resource '
                                                                 'from the '
                                                                 'workstation. '
                                                                 'Not for '
                                                                 'remote '
                                                                 'queries',
                                                  'Metasploit': 'auxiliary/scanner/smb/smb_enumshares'}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'net '
                                                                              'view '
                                                                              '\\\\host '
                                                                              '/all '
                                                                              '[/domain:domain]',
                                                  'Category': 'T1135',
                                                  'Cobalt Strike': 'net view '
                                                                   '\\\\host '
                                                                   '/domain',
                                                  'Description': 'Display the '
                                                                 'list of '
                                                                 'workstations '
                                                                 'and network '
                                                                 'devices on '
                                                                 'the '
                                                                 'network. ',
                                                  'Metasploit': 'auxiliary/scanner/smb/smb_enumshares'}},
 {'Atomic Red Team Test - Network Share Discovery': {'atomic_tests': [{'description': 'Network '
                                                                                      'Share '
                                                                                      'Discovery\n',
                                                                       'executor': {'command': 'df '
                                                                                               '-aH\n'
                                                                                               'smbutil '
                                                                                               'view '
                                                                                               '-g '
                                                                                               '//#{computer_name}\n'
                                                                                               'showmount '
                                                                                               '#{computer_name}\n',
                                                                                    'name': 'sh'},
                                                                       'input_arguments': {'computer_name': {'default': 'computer1',
                                                                                                             'description': 'Computer '
                                                                                                                            'name '
                                                                                                                            'to '
                                                                                                                            'find '
                                                                                                                            'a '
                                                                                                                            'mount '
                                                                                                                            'on.',
                                                                                                             'type': 'string'}},
                                                                       'name': 'Network '
                                                                               'Share '
                                                                               'Discovery',
                                                                       'supported_platforms': ['macos',
                                                                                               'linux']},
                                                                      {'description': 'Network '
                                                                                      'Share '
                                                                                      'Discovery '
                                                                                      'utilizing '
                                                                                      'the '
                                                                                      'command '
                                                                                      'prompt. '
                                                                                      'The '
                                                                                      'computer '
                                                                                      'name '
                                                                                      'variable '
                                                                                      'may '
                                                                                      'need '
                                                                                      'to '
                                                                                      'be '
                                                                                      'modified '
                                                                                      'to '
                                                                                      'point '
                                                                                      'to '
                                                                                      'a '
                                                                                      'different '
                                                                                      'host\n'
                                                                                      'Upon '
                                                                                      'execution '
                                                                                      'avalaible '
                                                                                      'network '
                                                                                      'shares '
                                                                                      'will '
                                                                                      'be '
                                                                                      'displayed '
                                                                                      'in '
                                                                                      'the '
                                                                                      'powershell '
                                                                                      'session\n',
                                                                       'executor': {'command': 'net '
                                                                                               'view '
                                                                                               '\\\\#{computer_name}\n',
                                                                                    'elevation_required': False,
                                                                                    'name': 'command_prompt'},
                                                                       'input_arguments': {'computer_name': {'default': 'localhost',
                                                                                                             'description': 'Computer '
                                                                                                                            'name '
                                                                                                                            'to '
                                                                                                                            'find '
                                                                                                                            'a '
                                                                                                                            'mount '
                                                                                                                            'on.',
                                                                                                             'type': 'string'}},
                                                                       'name': 'Network '
                                                                               'Share '
                                                                               'Discovery '
                                                                               'command '
                                                                               'prompt',
                                                                       'supported_platforms': ['windows']},
                                                                      {'description': 'Network '
                                                                                      'Share '
                                                                                      'Discovery '
                                                                                      'utilizing '
                                                                                      'PowerShell. '
                                                                                      'The '
                                                                                      'computer '
                                                                                      'name '
                                                                                      'variable '
                                                                                      'may '
                                                                                      'need '
                                                                                      'to '
                                                                                      'be '
                                                                                      'modified '
                                                                                      'to '
                                                                                      'point '
                                                                                      'to '
                                                                                      'a '
                                                                                      'different '
                                                                                      'host\n'
                                                                                      'Upon '
                                                                                      'execution, '
                                                                                      'avalaible '
                                                                                      'network '
                                                                                      'shares '
                                                                                      'will '
                                                                                      'be '
                                                                                      'displayed '
                                                                                      'in '
                                                                                      'the '
                                                                                      'powershell '
                                                                                      'session\n',
                                                                       'executor': {'command': 'net '
                                                                                               'view '
                                                                                               '\\\\#{computer_name}\n'
                                                                                               'get-smbshare '
                                                                                               '-Name '
                                                                                               '#{computer_name}\n',
                                                                                    'elevation_required': False,
                                                                                    'name': 'powershell'},
                                                                       'input_arguments': {'computer_name': {'default': 'localhost',
                                                                                                             'description': 'Computer '
                                                                                                                            'name '
                                                                                                                            'to '
                                                                                                                            'find '
                                                                                                                            'a '
                                                                                                                            'mount '
                                                                                                                            'on.',
                                                                                                             'type': 'string'}},
                                                                       'name': 'Network '
                                                                               'Share '
                                                                               'Discovery '
                                                                               'PowerShell',
                                                                       'supported_platforms': ['windows']},
                                                                      {'description': 'View '
                                                                                      'information '
                                                                                      'about '
                                                                                      'all '
                                                                                      'of '
                                                                                      'the '
                                                                                      'resources '
                                                                                      'that '
                                                                                      'are '
                                                                                      'shared '
                                                                                      'on '
                                                                                      'the '
                                                                                      'local '
                                                                                      'computer '
                                                                                      'Upon '
                                                                                      'execution, '
                                                                                      'avalaible '
                                                                                      'share '
                                                                                      'drives '
                                                                                      'will '
                                                                                      'be '
                                                                                      'displayed '
                                                                                      'in '
                                                                                      'the '
                                                                                      'powershell '
                                                                                      'session',
                                                                       'executor': {'command': 'net '
                                                                                               'share\n',
                                                                                    'elevation_required': False,
                                                                                    'name': 'command_prompt'},
                                                                       'name': 'View '
                                                                               'available '
                                                                               'share '
                                                                               'drives',
                                                                       'supported_platforms': ['windows']}],
                                                     'attack_technique': 'T1135',
                                                     'display_name': 'Network '
                                                                     'Share '
                                                                     'Discovery'}},
 {'Mitre Stockpile - Network Share Discovery': {'description': 'Network Share '
                                                               'Discovery',
                                                'id': '530e47c6-8592-42bf-91df-c59ffbd8541b',
                                                'name': 'View admin shares',
                                                'platforms': {'windows': {'pwsh,psh': {'command': 'Get-SmbShare '
                                                                                                  '| '
                                                                                                  'ConvertTo-Json',
                                                                                       'parsers': {'plugins.stockpile.app.parsers.json': [{'json_key': 'Path',
                                                                                                                                           'json_type': ['str'],
                                                                                                                                           'source': 'domain.smb.share'}]}}}},
                                                'tactic': 'discovery',
                                                'technique': {'attack_id': 'T1135',
                                                              'name': 'Network '
                                                                      'Share '
                                                                      'Discovery'}}},
 {'Mitre Stockpile - View the shares of a remote host': {'description': 'View '
                                                                        'the '
                                                                        'shares '
                                                                        'of a '
                                                                        'remote '
                                                                        'host',
                                                         'id': 'deeac480-5c2a-42b5-90bb-41675ee53c7e',
                                                         'name': 'View remote '
                                                                 'shares',
                                                         'platforms': {'windows': {'cmd': {'command': 'net '
                                                                                                      'view '
                                                                                                      '\\\\#{remote.host.fqdn} '
                                                                                                      '/all',
                                                                                           'parsers': {'plugins.stockpile.app.parsers.net_view': [{'edge': 'has_share',
                                                                                                                                                   'source': 'remote.host.fqdn',
                                                                                                                                                   'target': 'remote.host.share'}]}},
                                                                                   'psh': {'command': 'net '
                                                                                                      'view '
                                                                                                      '\\\\#{remote.host.fqdn} '
                                                                                                      '/all',
                                                                                           'parsers': {'plugins.stockpile.app.parsers.net_view': [{'edge': 'has_share',
                                                                                                                                                   'source': 'remote.host.fqdn',
                                                                                                                                                   'target': 'remote.host.share'}]}}}},
                                                         'tactic': 'discovery',
                                                         'technique': {'attack_id': 'T1135',
                                                                       'name': 'Network '
                                                                               'Share '
                                                                               'Discovery'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1135',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_dfs_share":  '
                                                                                 '["T1135"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_dfs_share',
                                            'Technique': 'Network Share '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1135',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/share_finder":  '
                                                                                 '["T1135"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/share_finder',
                                            'Technique': 'Network Share '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1135',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/active_directory/get_fileservers":  '
                                                                                 '["T1135"],',
                                            'Empire Module': 'python/situational_awareness/network/active_directory/get_fileservers',
                                            'Technique': 'Network Share '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1135',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/smb_mount":  '
                                                                                 '["T1135"],',
                                            'Empire Module': 'python/situational_awareness/network/smb_mount',
                                            'Technique': 'Network Share '
                                                         'Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations

None

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [Sowbug](../actors/Sowbug.md)
    
* [APT1](../actors/APT1.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [APT41](../actors/APT41.md)
    
