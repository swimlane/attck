
# Credentials in Files

## Description

### MITRE Description

> Adversaries may search local file systems and remote file shares for files containing passwords. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.

It is possible to extract passwords from backups or saved virtual machines through [Credential Dumping](https://attack.mitre.org/techniques/T1003). (Citation: CG 2014) Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller. (Citation: SRD GPP)

In cloud environments, authenticated user credentials are often stored in local configuration and credential files. In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files. (Citation: Specter Ops - Cloud Credential Storage)



## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1081

## Potential Commands

```
shell laZagne.exe browsers [-f]
python2 laZagne.py all

grep -ri password /

findstr /si pass *.xml *.doc *.txt *.xls
ls -R | select-string -Pattern password

type C:\Windows\Panther\unattend.xml
type C:\Windows\Panther\Unattend\unattend.xml

grep -riP password #{file_path}
grep -riP password /
```

## Commands Dataset

```
[{'command': 'shell laZagne.exe browsers [-f]',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'python2 laZagne.py all\n',
  'name': None,
  'source': 'atomics/T1081/T1081.yaml'},
 {'command': 'grep -ri password /\n',
  'name': None,
  'source': 'atomics/T1081/T1081.yaml'},
 {'command': 'findstr /si pass *.xml *.doc *.txt *.xls\n'
             'ls -R | select-string -Pattern password\n',
  'name': None,
  'source': 'atomics/T1081/T1081.yaml'},
 {'command': 'type C:\\Windows\\Panther\\unattend.xml\n'
             'type C:\\Windows\\Panther\\Unattend\\unattend.xml\n',
  'name': None,
  'source': 'atomics/T1081/T1081.yaml'},
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
 {'data_source': 'bash_history logs'}]
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
                                                  'Metasploit': ''}},
 {'Atomic Red Team Test - Credentials in Files': {'atomic_tests': [{'description': '[LaZagne '
                                                                                   'Source](https://github.com/AlessandroZ/LaZagne)\n',
                                                                    'executor': {'command': 'python2 '
                                                                                            'laZagne.py '
                                                                                            'all\n',
                                                                                 'name': 'sh'},
                                                                    'name': 'Extract '
                                                                            'Browser '
                                                                            'and '
                                                                            'System '
                                                                            'credentials '
                                                                            'with '
                                                                            'LaZagne',
                                                                    'supported_platforms': ['macos']},
                                                                   {'description': 'Extracting '
                                                                                   'credentials '
                                                                                   'from '
                                                                                   'files\n',
                                                                    'executor': {'command': 'grep '
                                                                                            '-ri '
                                                                                            'password '
                                                                                            '#{file_path}\n',
                                                                                 'name': 'sh'},
                                                                    'input_arguments': {'file_path': {'default': '/',
                                                                                                      'description': 'Path '
                                                                                                                     'to '
                                                                                                                     'search',
                                                                                                      'type': 'String'}},
                                                                    'name': 'Extract '
                                                                            'passwords '
                                                                            'with '
                                                                            'grep',
                                                                    'supported_platforms': ['macos',
                                                                                            'linux']},
                                                                   {'description': 'Extracting '
                                                                                   'Credentials '
                                                                                   'from '
                                                                                   'Files. '
                                                                                   'Upon '
                                                                                   'execution, '
                                                                                   'the '
                                                                                   'contents '
                                                                                   'of '
                                                                                   'files '
                                                                                   'that '
                                                                                   'contain '
                                                                                   'the '
                                                                                   'word '
                                                                                   '"password" '
                                                                                   'will '
                                                                                   'be '
                                                                                   'displayed.\n',
                                                                    'executor': {'command': 'findstr '
                                                                                            '/si '
                                                                                            'pass '
                                                                                            '*.xml '
                                                                                            '*.doc '
                                                                                            '*.txt '
                                                                                            '*.xls\n'
                                                                                            'ls '
                                                                                            '-R '
                                                                                            '| '
                                                                                            'select-string '
                                                                                            '-Pattern '
                                                                                            'password\n',
                                                                                 'elevation_required': False,
                                                                                 'name': 'powershell'},
                                                                    'name': 'Extracting '
                                                                            'passwords '
                                                                            'with '
                                                                            'findstr',
                                                                    'supported_platforms': ['windows']},
                                                                   {'description': 'Attempts '
                                                                                   'to '
                                                                                   'access '
                                                                                   'unattend.xml, '
                                                                                   'where '
                                                                                   'credentials '
                                                                                   'are '
                                                                                   'commonly '
                                                                                   'stored, '
                                                                                   'within '
                                                                                   'the '
                                                                                   'Panther '
                                                                                   'directory '
                                                                                   'where '
                                                                                   'installation '
                                                                                   'logs '
                                                                                   'are '
                                                                                   'stored.\n'
                                                                                   'If '
                                                                                   'these '
                                                                                   'files '
                                                                                   'exist, '
                                                                                   'their '
                                                                                   'contents '
                                                                                   'will '
                                                                                   'be '
                                                                                   'displayed. '
                                                                                   'They '
                                                                                   'are '
                                                                                   'used '
                                                                                   'to '
                                                                                   'store '
                                                                                   'credentials/answers '
                                                                                   'during '
                                                                                   'the '
                                                                                   'unattended '
                                                                                   'windows '
                                                                                   'install '
                                                                                   'process.\n',
                                                                    'executor': {'command': 'type '
                                                                                            'C:\\Windows\\Panther\\unattend.xml\n'
                                                                                            'type '
                                                                                            'C:\\Windows\\Panther\\Unattend\\unattend.xml\n',
                                                                                 'elevation_required': True,
                                                                                 'name': 'command_prompt'},
                                                                    'name': 'Access '
                                                                            'unattend.xml',
                                                                    'supported_platforms': ['windows']}],
                                                  'attack_technique': 'T1081',
                                                  'display_name': 'Credentials '
                                                                  'in Files'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations

None

# Actors


* [MuddyWater](../actors/MuddyWater.md)

* [APT3](../actors/APT3.md)
    
* [Stolen Pencil](../actors/Stolen-Pencil.md)
    
* [TA505](../actors/TA505.md)
    
* [Turla](../actors/Turla.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [OilRig](../actors/OilRig.md)
    
