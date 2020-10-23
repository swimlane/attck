
# Credentials In Files

## Description

### MITRE Description

> Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.

It is possible to extract passwords from backups or saved virtual machines through [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). (Citation: CG 2014) Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller. (Citation: SRD GPP)

In cloud environments, authenticated user credentials are often stored in local configuration and credential files. In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files. (Citation: Specter Ops - Cloud Credential Storage)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM', 'User']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1552/001

## Potential Commands

```
shell laZagne.exe browsers [-f]
grep -riP password /
grep -riP password #{file_path}
```

## Commands Dataset

```
[{'command': 'shell laZagne.exe browsers [-f]',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'grep -riP password #{file_path}',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'grep -riP password /',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'}]
```

## Potential Detections

```json
[{'data_source': 'auditlogs (audit.rules)'},
 {'data_source': 'bash_history logs'},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']}]
```

## Potential Queries

```json
[{'name': 'Credentials In Files',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_command_line contains '
           '"*findstr* /si pass*"or process_command_line contains '
           '"*select-string -Pattern pass*"or process_command_line contains '
           '"*list vdir*/text:password*")'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=linux_audit type=execve a0=grep password'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype="bash_history" grep password | table '
           'host,user_name,bash_command'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': '',
                                                  'Category': 'T1081',
                                                  'Cobalt Strike': '',
                                                  'Description': 'https://github.com/hassaanaliw/chromepass\n'
                                                                 'This program '
                                                                 'attempts to '
                                                                 'collect '
                                                                 'passwords '
                                                                 'that Chrome '
                                                                 'stores.',
                                                  'Metasploit': ''}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': '',
                                                  'Category': 'T1081',
                                                  'Cobalt Strike': 'shell '
                                                                   'laZagne.exe '
                                                                   'browsers '
                                                                   '[-f]',
                                                  'Description': 'https://github.com/AlessandroZ/LaZagne '
                                                                 '(now part of '
                                                                 'pupy as a '
                                                                 'post-exploit '
                                                                 'module)\n'
                                                                 'This program '
                                                                 'attempts to '
                                                                 'collect '
                                                                 'passwords '
                                                                 'from many '
                                                                 'different '
                                                                 'data sources '
                                                                 'related to '
                                                                 'browsers - '
                                                                 "it'll get "
                                                                 'passwords '
                                                                 'from '
                                                                 'Firefox, '
                                                                 'Chrome, '
                                                                 'Opera, IE.\n'
                                                                 'the -f '
                                                                 'command on '
                                                                 'the browsers '
                                                                 'command call '
                                                                 'is '
                                                                 'specifically '
                                                                 'targeting '
                                                                 'Firefox',
                                                  'Metasploit': ''}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Password Policies](../mitigations/Password-Policies.md)

* [Audit](../mitigations/Audit.md)
    
* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    
* [User Training](../mitigations/User-Training.md)
    
* [Credentials in Files Mitigation](../mitigations/Credentials-in-Files-Mitigation.md)
    

# Actors


* [MuddyWater](../actors/MuddyWater.md)

* [APT3](../actors/APT3.md)
    
* [Stolen Pencil](../actors/Stolen-Pencil.md)
    
* [TA505](../actors/TA505.md)
    
* [OilRig](../actors/OilRig.md)
    
* [APT33](../actors/APT33.md)
    
* [Leafminer](../actors/Leafminer.md)
    
