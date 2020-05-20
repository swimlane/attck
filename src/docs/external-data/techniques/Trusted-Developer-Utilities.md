
# Trusted Developer Utilities

## Description

### MITRE Description

> There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering. These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application whitelisting defensive solutions.

### MSBuild

MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It takes XML formatted project files that define requirements for building various platforms and configurations. (Citation: MSDN MSBuild) 

Adversaries can use MSBuild to proxy execution of code through a trusted Windows utility. The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# code to be inserted into the XML project file. (Citation: MSDN MSBuild) Inline Tasks MSBuild will compile and execute the inline task. MSBuild.exe is a signed Microsoft binary, so when it is used this way it can execute arbitrary code and bypass application whitelisting defenses that are configured to allow MSBuild.exe execution. (Citation: LOLBAS Msbuild)

### DNX

The .NET Execution Environment (DNX), dnx.exe, is a software development kit packaged with Visual Studio Enterprise. It was retired in favor of .NET Core CLI in 2016. (Citation: Microsoft Migrating from DNX) DNX is not present on standard builds of Windows and may only be present on developer workstations using older versions of .NET Core and ASP.NET Core 1.0. The dnx.exe executable is signed by Microsoft. 

An adversary can use dnx.exe to proxy execution of arbitrary code to bypass application whitelist policies that do not account for DNX. (Citation: engima0x3 DNX Bypass)

### RCSI

The rcsi.exe utility is a non-interactive command-line interface for C# that is similar to csi.exe. It was provided within an early version of the Roslyn .NET Compiler Platform but has since been deprecated for an integrated solution. (Citation: Microsoft Roslyn CPT RCSI) The rcsi.exe binary is signed by Microsoft. (Citation: engima0x3 RCSI Bypass)

C# .csx script files can be written and executed with rcsi.exe at the command-line. An adversary can use rcsi.exe to proxy execution of arbitrary code to bypass application whitelisting policies that do not account for execution of rcsi.exe. (Citation: engima0x3 RCSI Bypass)

### WinDbg/CDB

WinDbg is a Microsoft Windows kernel and user-mode debugging utility. The Microsoft Console Debugger (CDB) cdb.exe is also user-mode debugger. Both utilities are included in Windows software development kits and can be used as standalone tools. (Citation: Microsoft Debugging Tools for Windows) They are commonly used in software development and reverse engineering and may not be found on typical Windows systems. Both WinDbg.exe and cdb.exe binaries are signed by Microsoft.

An adversary can use WinDbg.exe and cdb.exe to proxy execution of arbitrary code to bypass application whitelist policies that do not account for execution of those utilities. (Citation: Exploit Monday WinDbg)

It is likely possible to use other debuggers for similar purposes, such as the kernel-mode debugger kd.exe, which is also signed by Microsoft.

### Tracker

The file tracker utility, tracker.exe, is included with the .NET framework as part of MSBuild. It is used for logging calls to the Windows file system. (Citation: Microsoft Docs File Tracking)

An adversary can use tracker.exe to proxy execution of an arbitrary DLL into another process. Since tracker.exe is also signed it can be used to bypass application whitelisting solutions. (Citation: LOLBAS Tracker)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application whitelisting']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1127

## Potential Commands

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe PathToAtomicsFolder\T1127\src\T1127.csproj

powershell/lateral_movement/invoke_executemsbuild
powershell/lateral_movement/invoke_executemsbuild
powershell/code_execution/invoke_ntsd
powershell/code_execution/invoke_ntsd
Log
Event ID: 4688
Process information:
New Process ID: 0xa9c
New Process Name: C: \ Windows \ Microsoft.NET \ Framework64 \ v4.0.30319 \ csc.exe
Token Type lift: TokenElevationTypeDefault (1)
Creator Process ID: 0xaa0
Process the command line: C: \ Windows \ Microsoft.NET \ Framework64 \ v4.0.30319 \ csc.exe /r:System.EnterpriseServices.dll /r:System.IO.Compression.dll / target: library /out:1.exe / platform: x64 / unsafe C: \ Users \ Administrator \ Desktop \ a \ 1.cs

Event ID: 4688
Process information:
New Process ID: 0x984
New Process Name: C: \ Windows \ Microsoft.NET \ Framework64 \ v4.0.30319 \ InstallUtil.exe
Token Type lift: TokenElevationTypeDefault (1)
Creator Process ID: 0xaa0
Process the command line: C: \ Windows \ Microsoft.NET \ Framework64 \ v4.0.30319 \ InstallUtil.exe / logfile = / LogToConsole = false / U C: \ Users \ Administrator \ Desktop \ a \ 1.exe
```

## Commands Dataset

```
[{'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe '
             'PathToAtomicsFolder\\T1127\\src\\T1127.csproj\n',
  'name': None,
  'source': 'atomics/T1127/T1127.yaml'},
 {'command': 'powershell/lateral_movement/invoke_executemsbuild',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/lateral_movement/invoke_executemsbuild',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/code_execution/invoke_ntsd',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/code_execution/invoke_ntsd',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'Log\n'
             'Event ID: 4688\n'
             'Process information:\n'
             'New Process ID: 0xa9c\n'
             'New Process Name: C: \\ Windows \\ Microsoft.NET \\ Framework64 '
             '\\ v4.0.30319 \\ csc.exe\n'
             'Token Type lift: TokenElevationTypeDefault (1)\n'
             'Creator Process ID: 0xaa0\n'
             'Process the command line: C: \\ Windows \\ Microsoft.NET \\ '
             'Framework64 \\ v4.0.30319 \\ csc.exe '
             '/r:System.EnterpriseServices.dll /r:System.IO.Compression.dll / '
             'target: library /out:1.exe / platform: x64 / unsafe C: \\ Users '
             '\\ Administrator \\ Desktop \\ a \\ 1.cs\n'
             '\n'
             'Event ID: 4688\n'
             'Process information:\n'
             'New Process ID: 0x984\n'
             'New Process Name: C: \\ Windows \\ Microsoft.NET \\ Framework64 '
             '\\ v4.0.30319 \\ InstallUtil.exe\n'
             'Token Type lift: TokenElevationTypeDefault (1)\n'
             'Creator Process ID: 0xaa0\n'
             'Process the command line: C: \\ Windows \\ Microsoft.NET \\ '
             'Framework64 \\ v4.0.30319 \\ InstallUtil.exe / logfile = / '
             'LogToConsole = false / U C: \\ Users \\ Administrator \\ Desktop '
             '\\ a \\ 1.exe',
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Nik Seetharaman',
                  'description': 'Detects invocation of Microsoft Workflow '
                                 'Compiler, which may permit the execution of '
                                 'arbitrary unsigned code.',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': '*\\Microsoft.Workflow.Compiler.exe'}},
                  'falsepositives': ['Legitimate MWC use (unlikely in modern '
                                     'enterprise environments)'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '419dbf2b-8a9b-4bea-bf99-7544b050ec8d',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1127'],
                  'title': 'Microsoft Workflow Compiler'}},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']}]
```

## Potential Queries

```json
[{'name': 'Trusted Developer Utilities',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_path contains '
           '"MSBuild.exe"or process_path contains "msxsl.exe")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Trusted Developer Utilities': {'atomic_tests': [{'auto_generated_guid': '58742c0f-cb01-44cd-a60b-fb26e8871c93',
                                                                           'dependencies': [{'description': 'Project '
                                                                                                            'file '
                                                                                                            'must '
                                                                                                            'exist '
                                                                                                            'on '
                                                                                                            'disk '
                                                                                                            'at '
                                                                                                            'specified '
                                                                                                            'location '
                                                                                                            '(#{filename})\n',
                                                                                             'get_prereq_command': 'New-Item '
                                                                                                                   '-Type '
                                                                                                                   'Directory '
                                                                                                                   '(split-path '
                                                                                                                   '#{filename}) '
                                                                                                                   '-ErrorAction '
                                                                                                                   'ignore '
                                                                                                                   '| '
                                                                                                                   'Out-Null\n'
                                                                                                                   'Invoke-WebRequest '
                                                                                                                   '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1127/src/T1127.csproj" '
                                                                                                                   '-OutFile '
                                                                                                                   '"#{filename}"\n',
                                                                                             'prereq_command': 'if '
                                                                                                               '(Test-Path '
                                                                                                               '#{filename}) '
                                                                                                               '{exit '
                                                                                                               '0} '
                                                                                                               'else '
                                                                                                               '{exit '
                                                                                                               '1}\n'}],
                                                                           'dependency_executor_name': 'powershell',
                                                                           'description': 'Executes '
                                                                                          'the '
                                                                                          'code '
                                                                                          'in '
                                                                                          'a '
                                                                                          'project '
                                                                                          'file '
                                                                                          'using. '
                                                                                          'C# '
                                                                                          'Example\n',
                                                                           'executor': {'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe '
                                                                                                   '#{filename}\n',
                                                                                        'elevation_required': False,
                                                                                        'name': 'command_prompt'},
                                                                           'input_arguments': {'filename': {'default': 'PathToAtomicsFolder\\T1127\\src\\T1127.csproj',
                                                                                                            'description': 'Location '
                                                                                                                           'of '
                                                                                                                           'the '
                                                                                                                           'project '
                                                                                                                           'file',
                                                                                                            'type': 'Path'}},
                                                                           'name': 'MSBuild '
                                                                                   'Bypass '
                                                                                   'Using '
                                                                                   'Inline '
                                                                                   'Tasks',
                                                                           'supported_platforms': ['windows']}],
                                                         'attack_technique': 'T1127',
                                                         'display_name': 'Trusted '
                                                                         'Developer '
                                                                         'Utilities'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1127',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/lateral_movement/invoke_executemsbuild":  '
                                                                                 '["T1127"],',
                                            'Empire Module': 'powershell/lateral_movement/invoke_executemsbuild',
                                            'Technique': 'Trusted Developer '
                                                         'Utilities'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1127',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/code_execution/invoke_ntsd":  '
                                                                                 '["T1127"],',
                                            'Empire Module': 'powershell/code_execution/invoke_ntsd',
                                            'Technique': 'Trusted Developer '
                                                         'Utilities'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Execution](../tactics/Execution.md)
    

# Mitigations

None

# Actors

None
