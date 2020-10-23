
# Domain Account

## Description

### MITRE Description

> Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior.

Commands such as <code>net user /domain</code> and <code>net group /domain</code> of the [Net](https://attack.mitre.org/software/S0039) utility, <code>dscacheutil -q group</code>on macOS, and <code>ldapsearch</code> on Linux can list domain users and groups.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1087/002

## Potential Commands

```
net user /domain
net group /domain
net user /domain
get-localgroupmember -group Users
get-aduser -filter *
query user /SERVER:$env:COMPUTERNAME
Invoke-Expression $env:TEMP\ADRecon.ps1
PathToAtomicsFolder\T1087.002\src\AdFind -default -s base lockoutduration lockoutthreshold lockoutobservationwindow maxpwdage minpwdage minpwdlength pwdhistorylength pwdproperties
```

## Commands Dataset

```
[{'command': 'net user /domain\nnet group /domain\n',
  'name': None,
  'source': 'atomics/T1087.002/T1087.002.yaml'},
 {'command': 'net user /domain\n'
             'get-localgroupmember -group Users\n'
             'get-aduser -filter *\n',
  'name': None,
  'source': 'atomics/T1087.002/T1087.002.yaml'},
 {'command': 'query user /SERVER:$env:COMPUTERNAME\n',
  'name': None,
  'source': 'atomics/T1087.002/T1087.002.yaml'},
 {'command': 'Invoke-Expression $env:TEMP\\ADRecon.ps1\n',
  'name': None,
  'source': 'atomics/T1087.002/T1087.002.yaml'},
 {'command': 'PathToAtomicsFolder\\T1087.002\\src\\AdFind -default -s base '
             'lockoutduration lockoutthreshold lockoutobservationwindow '
             'maxpwdage minpwdage minpwdlength pwdhistorylength '
             'pwdproperties\n',
  'name': None,
  'source': 'atomics/T1087.002/T1087.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Account Discovery: Domain Account': {'atomic_tests': [{'auto_generated_guid': '6fbc9e68-5ad7-444a-bd11-8bf3136c477e',
                                                                                 'description': 'Enumerate '
                                                                                                'all '
                                                                                                'accounts\n'
                                                                                                'Upon '
                                                                                                'exection, '
                                                                                                'multiple '
                                                                                                'enumeration '
                                                                                                'commands '
                                                                                                'will '
                                                                                                'be '
                                                                                                'run '
                                                                                                'and '
                                                                                                'their '
                                                                                                'output '
                                                                                                'displayed '
                                                                                                'in '
                                                                                                'the '
                                                                                                'PowerShell '
                                                                                                'session\n',
                                                                                 'executor': {'command': 'net '
                                                                                                         'user '
                                                                                                         '/domain\n'
                                                                                                         'net '
                                                                                                         'group '
                                                                                                         '/domain\n',
                                                                                              'name': 'command_prompt'},
                                                                                 'name': 'Enumerate '
                                                                                         'all '
                                                                                         'accounts '
                                                                                         '(Domain)',
                                                                                 'supported_platforms': ['windows']},
                                                                                {'auto_generated_guid': '8b8a6449-be98-4f42-afd2-dedddc7453b2',
                                                                                 'description': 'Enumerate '
                                                                                                'all '
                                                                                                'accounts '
                                                                                                'via '
                                                                                                'PowerShell. '
                                                                                                'Upon '
                                                                                                'execution, '
                                                                                                'lots '
                                                                                                'of '
                                                                                                'user '
                                                                                                'account '
                                                                                                'and '
                                                                                                'group '
                                                                                                'information '
                                                                                                'will '
                                                                                                'be '
                                                                                                'displayed.\n',
                                                                                 'executor': {'command': 'net '
                                                                                                         'user '
                                                                                                         '/domain\n'
                                                                                                         'get-localgroupmember '
                                                                                                         '-group '
                                                                                                         'Users\n'
                                                                                                         'get-aduser '
                                                                                                         '-filter '
                                                                                                         '*\n',
                                                                                              'name': 'powershell'},
                                                                                 'name': 'Enumerate '
                                                                                         'all '
                                                                                         'accounts '
                                                                                         'via '
                                                                                         'PowerShell '
                                                                                         '(Domain)',
                                                                                 'supported_platforms': ['windows']},
                                                                                {'auto_generated_guid': '161dcd85-d014-4f5e-900c-d3eaae82a0f7',
                                                                                 'description': 'Enumerate '
                                                                                                'logged '
                                                                                                'on '
                                                                                                'users. '
                                                                                                'Upon '
                                                                                                'exeuction, '
                                                                                                'logged '
                                                                                                'on '
                                                                                                'users '
                                                                                                'will '
                                                                                                'be '
                                                                                                'displayed.\n',
                                                                                 'executor': {'command': 'query '
                                                                                                         'user '
                                                                                                         '/SERVER:#{computer_name}\n',
                                                                                              'name': 'command_prompt'},
                                                                                 'input_arguments': {'computer_name': {'default': '$env:COMPUTERNAME',
                                                                                                                       'description': 'Name '
                                                                                                                                      'of '
                                                                                                                                      'remote '
                                                                                                                                      'system '
                                                                                                                                      'to '
                                                                                                                                      'query',
                                                                                                                       'type': 'String'}},
                                                                                 'name': 'Enumerate '
                                                                                         'logged '
                                                                                         'on '
                                                                                         'users '
                                                                                         'via '
                                                                                         'CMD '
                                                                                         '(Domain)',
                                                                                 'supported_platforms': ['windows']},
                                                                                {'auto_generated_guid': '95018438-454a-468c-a0fa-59c800149b59',
                                                                                 'dependencies': [{'description': 'ADRecon '
                                                                                                                  'must '
                                                                                                                  'exist '
                                                                                                                  'on '
                                                                                                                  'disk '
                                                                                                                  'at '
                                                                                                                  'specified '
                                                                                                                  'location '
                                                                                                                  '(#{adrecon_path})\n',
                                                                                                   'get_prereq_command': 'Invoke-WebRequest '
                                                                                                                         '-Uri '
                                                                                                                         '"https://raw.githubusercontent.com/sense-of-security/ADRecon/38e4abae3e26d0fa87281c1d0c65cabd4d3c6ebd/ADRecon.ps1" '
                                                                                                                         '-OutFile '
                                                                                                                         '#{adrecon_path}\n',
                                                                                                   'prereq_command': 'if '
                                                                                                                     '(Test-Path '
                                                                                                                     '#{adrecon_path}) '
                                                                                                                     '{exit '
                                                                                                                     '0} '
                                                                                                                     'else '
                                                                                                                     '{exit '
                                                                                                                     '1}\n'}],
                                                                                 'dependency_executor_name': 'powershell',
                                                                                 'description': 'ADRecon '
                                                                                                'extracts '
                                                                                                'and '
                                                                                                'combines '
                                                                                                'information '
                                                                                                'about '
                                                                                                'an '
                                                                                                'AD '
                                                                                                'environement '
                                                                                                'into '
                                                                                                'a '
                                                                                                'report. '
                                                                                                'Upon '
                                                                                                'execution, '
                                                                                                'an '
                                                                                                'Excel '
                                                                                                'file '
                                                                                                'with '
                                                                                                'all '
                                                                                                'of '
                                                                                                'the '
                                                                                                'data '
                                                                                                'will '
                                                                                                'be '
                                                                                                'generated '
                                                                                                'and '
                                                                                                'its\n'
                                                                                                'path '
                                                                                                'will '
                                                                                                'be '
                                                                                                'displayed.\n',
                                                                                 'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                 '#{adrecon_path} '
                                                                                                                 '-Force '
                                                                                                                 '-ErrorAction '
                                                                                                                 'Ignore '
                                                                                                                 '| '
                                                                                                                 'Out-Null\n'
                                                                                                                 'Get-ChildItem '
                                                                                                                 '$env:TEMP '
                                                                                                                 '-Recurse '
                                                                                                                 '-Force '
                                                                                                                 '| '
                                                                                                                 'Where{$_.Name '
                                                                                                                 '-Match '
                                                                                                                 '"^ADRecon-Report-"} '
                                                                                                                 '| '
                                                                                                                 'Remove-Item '
                                                                                                                 '-Force '
                                                                                                                 '-Recurse\n',
                                                                                              'command': 'Invoke-Expression '
                                                                                                         '#{adrecon_path}\n',
                                                                                              'name': 'powershell'},
                                                                                 'input_arguments': {'adrecon_path': {'default': '$env:TEMP\\ADRecon.ps1',
                                                                                                                      'description': 'Path '
                                                                                                                                     'of '
                                                                                                                                     'ADRecon.ps1 '
                                                                                                                                     'file',
                                                                                                                      'type': 'Path'}},
                                                                                 'name': 'Automated '
                                                                                         'AD '
                                                                                         'Recon '
                                                                                         '(ADRecon)',
                                                                                 'supported_platforms': ['windows']},
                                                                                {'auto_generated_guid': '736b4f53-f400-4c22-855d-1a6b5a551600',
                                                                                 'description': 'Adfind '
                                                                                                'tool '
                                                                                                'can '
                                                                                                'be '
                                                                                                'used '
                                                                                                'for '
                                                                                                'reconnaissance '
                                                                                                'in '
                                                                                                'an '
                                                                                                'Active '
                                                                                                'directory '
                                                                                                'environment. '
                                                                                                'The '
                                                                                                'example '
                                                                                                'chosen '
                                                                                                'illustrates '
                                                                                                'adfind '
                                                                                                'used '
                                                                                                'to '
                                                                                                'query '
                                                                                                'the '
                                                                                                'local '
                                                                                                'password '
                                                                                                'policy.\n'
                                                                                                'reference- '
                                                                                                'http://www.joeware.net/freetools/tools/adfind/, '
                                                                                                'https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx\n',
                                                                                 'executor': {'command': 'PathToAtomicsFolder\\T1087.002\\src\\AdFind '
                                                                                                         '-default '
                                                                                                         '-s '
                                                                                                         'base '
                                                                                                         'lockoutduration '
                                                                                                         'lockoutthreshold '
                                                                                                         'lockoutobservationwindow '
                                                                                                         'maxpwdage '
                                                                                                         'minpwdage '
                                                                                                         'minpwdlength '
                                                                                                         'pwdhistorylength '
                                                                                                         'pwdproperties\n',
                                                                                              'name': 'powershell'},
                                                                                 'name': 'Adfind '
                                                                                         '-Listing '
                                                                                         'password '
                                                                                         'policy',
                                                                                 'supported_platforms': ['windows']}],
                                                               'attack_technique': 'T1087.002',
                                                               'display_name': 'Account '
                                                                               'Discovery: '
                                                                               'Domain '
                                                                               'Account'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)


# Actors


* [FIN6](../actors/FIN6.md)

* [Ke3chang](../actors/Ke3chang.md)
    
* [menuPass](../actors/menuPass.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Poseidon Group](../actors/Poseidon-Group.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
* [Turla](../actors/Turla.md)
    
