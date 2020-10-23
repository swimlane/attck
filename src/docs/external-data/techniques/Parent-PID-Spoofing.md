
# Parent PID Spoofing

## Description

### MITRE Description

> Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges. New processes are typically spawned directly from their parent, or calling, process unless explicitly specified. One way of explicitly assigning the PPID of a new process is via the <code>CreateProcess</code> API call, which supports a parameter that defines the PPID to use.(Citation: DidierStevens SelectMyParent Nov 2009) This functionality is used by Windows features such as User Account Control (UAC) to correctly set the PPID after a requested elevated process is spawned by SYSTEM (typically via <code>svchost.exe</code> or <code>consent.exe</code>) rather than the current user context.(Citation: Microsoft UAC Nov 2018)

Adversaries may abuse these mechanisms to evade defenses, such as those blocking processes spawning directly from Office documents, and analysis targeting unusual/potentially malicious parent-child process relationships, such as spoofing the PPID of [PowerShell](https://attack.mitre.org/techniques/T1086)/[Rundll32](https://attack.mitre.org/techniques/T1085) to be <code>explorer.exe</code> rather than an Office document delivered as part of [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001).(Citation: CounterCept PPID Spoofing Dec 2018) This spoofing could be executed via [Visual Basic](https://attack.mitre.org/techniques/T1059/005) within a malicious Office document or any code that can perform [Native API](https://attack.mitre.org/techniques/T1106).(Citation: CTD PPID Spoofing Macro Mar 2019)(Citation: CounterCept PPID Spoofing Dec 2018)

Explicitly assigning the PPID may also enable elevated privileges given appropriate access rights to the parent process. For example, an adversary in a privileged user context (i.e. administrator) may spawn a new process and assign the parent as a process running as SYSTEM (such as <code>lsass.exe</code>), causing the new process to be elevated via the inherited access token.(Citation: XPNSec PPID Nov 2017)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Heuristic Detection', 'Host forensic analysis']
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1134/004

## Potential Commands

```
Start-ATHProcessUnderSpecificParent -FilePath #{file_path} -CommandLine '#{command_line}' -ParentId $PID
. $PathToAtomicsFolder\T1134.004\src\PPID-Spoof.ps1
$ppid=Get-Process explorer | select -expand id
PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" -dllpath "#{dll_path}"
. $PathToAtomicsFolder\T1134.004\src\PPID-Spoof.ps1
$ppid=Get-Process #{parent_process_name} | select -expand id
PPID-Spoof -ppid $ppid -spawnto "C:\Program Files\Internet Explorer\iexplore.exe" -dllpath "#{dll_path}"
Get-CimInstance -ClassName Win32_Process -Property Name, CommandLine, ProcessId -Filter "Name = 'svchost.exe' AND CommandLine LIKE '%'" | Select-Object -First 1 | Start-ATHProcessUnderSpecificParent -FilePath #{file_path} -CommandLine '-Command Start-Sleep 10'
Start-Process -FilePath #{parent_name} -PassThru | Start-ATHProcessUnderSpecificParent -FilePath $Env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -CommandLine '#{command_line}'
. $PathToAtomicsFolder\T1134.004\src\PPID-Spoof.ps1
$ppid=Get-Process #{parent_process_name} | select -expand id
PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" -dllpath "PathToAtomicsFolder\T1134.004\bin\calc.dll"
Start-ATHProcessUnderSpecificParent -FilePath #{file_path} -CommandLine '-Command Start-Sleep 10' -ParentId #{parent_pid}
Start-ATHProcessUnderSpecificParent -FilePath $Env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -CommandLine '#{command_line}' -ParentId #{parent_pid}
Start-ATHProcessUnderSpecificParent  -ParentId #{parent_pid} -TestGuid 12345678-1234-1234-1234-123456789123
. $PathToAtomicsFolder\T1134.004\src\PPID-Spoof.ps1
$ppid=Get-Process #{parent_process_name} | select -expand id
PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" -dllpath "#{dll_path}"
Start-ATHProcessUnderSpecificParent  -ParentId $PID -TestGuid #{test_guid}
Get-CimInstance -ClassName Win32_Process -Property Name, CommandLine, ProcessId -Filter "Name = 'svchost.exe' AND CommandLine LIKE '%'" | Select-Object -First 1 | Start-ATHProcessUnderSpecificParent -FilePath $Env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -CommandLine '#{command_line}'
Start-Process -FilePath #{parent_name} -PassThru | Start-ATHProcessUnderSpecificParent -FilePath #{file_path} -CommandLine '-Command Start-Sleep 10'
Start-Process -FilePath $Env:windir\System32\notepad.exe -PassThru | Start-ATHProcessUnderSpecificParent -FilePath #{file_path} -CommandLine '#{command_line}'
```

## Commands Dataset

```
[{'command': '. $PathToAtomicsFolder\\T1134.004\\src\\PPID-Spoof.ps1\n'
             '$ppid=Get-Process explorer | select -expand id\n'
             'PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" '
             '-dllpath "#{dll_path}"\n',
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1134.004\\src\\PPID-Spoof.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'PPID-Spoof -ppid $ppid -spawnto "C:\\Program Files\\Internet '
             'Explorer\\iexplore.exe" -dllpath "#{dll_path}"\n',
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1134.004\\src\\PPID-Spoof.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" '
             '-dllpath "#{dll_path}"\n',
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1134.004\\src\\PPID-Spoof.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" '
             '-dllpath "PathToAtomicsFolder\\T1134.004\\bin\\calc.dll"\n',
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1134.004\\src\\PPID-Spoof.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" '
             '-dllpath "#{dll_path}"\n',
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': 'Start-ATHProcessUnderSpecificParent -FilePath '
             '$Env:windir\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
             "-CommandLine '#{command_line}' -ParentId #{parent_pid}",
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': 'Start-ATHProcessUnderSpecificParent -FilePath #{file_path} '
             "-CommandLine '#{command_line}' -ParentId $PID",
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': 'Start-ATHProcessUnderSpecificParent -FilePath #{file_path} '
             "-CommandLine '-Command Start-Sleep 10' -ParentId #{parent_pid}",
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': 'Start-ATHProcessUnderSpecificParent  -ParentId $PID -TestGuid '
             '#{test_guid}',
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': 'Start-ATHProcessUnderSpecificParent  -ParentId #{parent_pid} '
             '-TestGuid 12345678-1234-1234-1234-123456789123',
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': 'Get-CimInstance -ClassName Win32_Process -Property Name, '
             'CommandLine, ProcessId -Filter "Name = \'svchost.exe\' AND '
             'CommandLine LIKE \'%\'" | Select-Object -First 1 | '
             'Start-ATHProcessUnderSpecificParent -FilePath #{file_path} '
             "-CommandLine '-Command Start-Sleep 10'",
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': 'Get-CimInstance -ClassName Win32_Process -Property Name, '
             'CommandLine, ProcessId -Filter "Name = \'svchost.exe\' AND '
             'CommandLine LIKE \'%\'" | Select-Object -First 1 | '
             'Start-ATHProcessUnderSpecificParent -FilePath '
             '$Env:windir\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
             "-CommandLine '#{command_line}'",
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': 'Start-Process -FilePath #{parent_name} -PassThru | '
             'Start-ATHProcessUnderSpecificParent -FilePath #{file_path} '
             "-CommandLine '-Command Start-Sleep 10'",
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': 'Start-Process -FilePath #{parent_name} -PassThru | '
             'Start-ATHProcessUnderSpecificParent -FilePath '
             '$Env:windir\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
             "-CommandLine '#{command_line}'",
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'},
 {'command': 'Start-Process -FilePath $Env:windir\\System32\\notepad.exe '
             '-PassThru | Start-ATHProcessUnderSpecificParent -FilePath '
             "#{file_path} -CommandLine '#{command_line}'",
  'name': None,
  'source': 'atomics/T1134.004/T1134.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Access Token Manipulation: Parent PID Spoofing': {'atomic_tests': [{'auto_generated_guid': '069258f4-2162-46e9-9a25-c9c6c56150d2',
                                                                                              'dependencies': [{'description': 'DLL '
                                                                                                                               'to '
                                                                                                                               'inject '
                                                                                                                               'must '
                                                                                                                               'exist '
                                                                                                                               'on '
                                                                                                                               'disk '
                                                                                                                               'at '
                                                                                                                               'specified '
                                                                                                                               'location '
                                                                                                                               '(#{dll_path})\n',
                                                                                                                'get_prereq_command': 'New-Item '
                                                                                                                                      '-Type '
                                                                                                                                      'Directory '
                                                                                                                                      '(split-path '
                                                                                                                                      '#{dll_path}) '
                                                                                                                                      '-ErrorAction '
                                                                                                                                      'ignore '
                                                                                                                                      '| '
                                                                                                                                      'Out-Null\n'
                                                                                                                                      'Invoke-WebRequest '
                                                                                                                                      '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1134.004/bin/calc.dll" '
                                                                                                                                      '-OutFile '
                                                                                                                                      '"#{dll_path}"\n',
                                                                                                                'prereq_command': 'if '
                                                                                                                                  '(Test-Path '
                                                                                                                                  '#{dll_path}) '
                                                                                                                                  '{exit '
                                                                                                                                  '0} '
                                                                                                                                  'else '
                                                                                                                                  '{exit '
                                                                                                                                  '1}\n'}],
                                                                                              'dependency_executor_name': 'powershell',
                                                                                              'description': 'This '
                                                                                                             'test '
                                                                                                             'uses '
                                                                                                             'PowerShell '
                                                                                                             'to '
                                                                                                             'replicates '
                                                                                                             'how '
                                                                                                             'Cobalt '
                                                                                                             'Strike '
                                                                                                             'does '
                                                                                                             'ppid '
                                                                                                             'spoofing '
                                                                                                             'and '
                                                                                                             'masquerade '
                                                                                                             'a '
                                                                                                             'spawned '
                                                                                                             'process.\n'
                                                                                                             'Upon '
                                                                                                             'execution, '
                                                                                                             '"Process '
                                                                                                             'C:\\Program '
                                                                                                             'Files\\Internet '
                                                                                                             'Explorer\\iexplore.exe '
                                                                                                             'is '
                                                                                                             'spawned '
                                                                                                             'with '
                                                                                                             'pid '
                                                                                                             '####" '
                                                                                                             'will '
                                                                                                             'be '
                                                                                                             'displayed '
                                                                                                             'and\n'
                                                                                                             'calc.exe '
                                                                                                             'will '
                                                                                                             'be '
                                                                                                             'launched.\n'
                                                                                                             '\n'
                                                                                                             'Credit '
                                                                                                             'to '
                                                                                                             'In '
                                                                                                             'Ming '
                                                                                                             'Loh '
                                                                                                             '(https://github.com/countercept/ppid-spoofing/blob/master/PPID-Spoof.ps1)\n',
                                                                                              'executor': {'cleanup_command': 'Stop-Process '
                                                                                                                              '-Name '
                                                                                                                              '"#{dll_process_name}" '
                                                                                                                              '-ErrorAction '
                                                                                                                              'Ignore\n'
                                                                                                                              'Stop-Process '
                                                                                                                              '-Name '
                                                                                                                              '"#{spawnto_process_name}" '
                                                                                                                              '-ErrorAction '
                                                                                                                              'Ignore\n',
                                                                                                           'command': '. '
                                                                                                                      '$PathToAtomicsFolder\\T1134.004\\src\\PPID-Spoof.ps1\n'
                                                                                                                      '$ppid=Get-Process '
                                                                                                                      '#{parent_process_name} '
                                                                                                                      '| '
                                                                                                                      'select '
                                                                                                                      '-expand '
                                                                                                                      'id\n'
                                                                                                                      'PPID-Spoof '
                                                                                                                      '-ppid '
                                                                                                                      '$ppid '
                                                                                                                      '-spawnto '
                                                                                                                      '"#{spawnto_process_path}" '
                                                                                                                      '-dllpath '
                                                                                                                      '"#{dll_path}"\n',
                                                                                                           'name': 'powershell'},
                                                                                              'input_arguments': {'dll_path': {'default': 'PathToAtomicsFolder\\T1134.004\\bin\\calc.dll',
                                                                                                                               'description': 'Path '
                                                                                                                                              'of '
                                                                                                                                              'the '
                                                                                                                                              'dll '
                                                                                                                                              'to '
                                                                                                                                              'inject',
                                                                                                                               'type': 'path'},
                                                                                                                  'dll_process_name': {'default': 'calculator',
                                                                                                                                       'description': 'Name '
                                                                                                                                                      'of '
                                                                                                                                                      'the '
                                                                                                                                                      'created '
                                                                                                                                                      'process '
                                                                                                                                                      'from '
                                                                                                                                                      'the '
                                                                                                                                                      'injected '
                                                                                                                                                      'dll',
                                                                                                                                       'type': 'string'},
                                                                                                                  'parent_process_name': {'default': 'explorer',
                                                                                                                                          'description': 'Name '
                                                                                                                                                         'of '
                                                                                                                                                         'the '
                                                                                                                                                         'parent '
                                                                                                                                                         'process',
                                                                                                                                          'type': 'string'},
                                                                                                                  'spawnto_process_name': {'default': 'iexplore',
                                                                                                                                           'description': 'Name '
                                                                                                                                                          'of '
                                                                                                                                                          'the '
                                                                                                                                                          'process '
                                                                                                                                                          'to '
                                                                                                                                                          'spawn',
                                                                                                                                           'type': 'string'},
                                                                                                                  'spawnto_process_path': {'default': 'C:\\Program '
                                                                                                                                                      'Files\\Internet '
                                                                                                                                                      'Explorer\\iexplore.exe',
                                                                                                                                           'description': 'Path '
                                                                                                                                                          'of '
                                                                                                                                                          'the '
                                                                                                                                                          'process '
                                                                                                                                                          'to '
                                                                                                                                                          'spawn',
                                                                                                                                           'type': 'path'}},
                                                                                              'name': 'Parent '
                                                                                                      'PID '
                                                                                                      'Spoofing '
                                                                                                      'using '
                                                                                                      'PowerShell',
                                                                                              'supported_platforms': ['windows']},
                                                                                             {'auto_generated_guid': '14920ebd-1d61-491a-85e0-fe98efe37f25',
                                                                                              'dependencies': [{'description': 'The '
                                                                                                                               'AtomicTestHarnesses '
                                                                                                                               'module '
                                                                                                                               'must '
                                                                                                                               'be '
                                                                                                                               'installed '
                                                                                                                               'and '
                                                                                                                               'Start-ATHProcessUnderSpecificParent '
                                                                                                                               'must '
                                                                                                                               'be '
                                                                                                                               'exported '
                                                                                                                               'in '
                                                                                                                               'the '
                                                                                                                               'module.',
                                                                                                                'get_prereq_command': 'Install-Module '
                                                                                                                                      '-Name '
                                                                                                                                      'AtomicTestHarnesses '
                                                                                                                                      '-Scope '
                                                                                                                                      'CurrentUser '
                                                                                                                                      '-Force\n',
                                                                                                                'prereq_command': '$RequiredModule '
                                                                                                                                  '= '
                                                                                                                                  'Get-Module '
                                                                                                                                  '-Name '
                                                                                                                                  'AtomicTestHarnesses '
                                                                                                                                  '-ListAvailable\n'
                                                                                                                                  'if '
                                                                                                                                  '(-not '
                                                                                                                                  '$RequiredModule) '
                                                                                                                                  '{exit '
                                                                                                                                  '1}\n'
                                                                                                                                  'if '
                                                                                                                                  '(-not '
                                                                                                                                  "$RequiredModule.ExportedCommands['Start-ATHProcessUnderSpecificParent']) "
                                                                                                                                  '{exit '
                                                                                                                                  '1} '
                                                                                                                                  'else '
                                                                                                                                  '{exit '
                                                                                                                                  '0}'}],
                                                                                              'description': 'Spawns '
                                                                                                             'a '
                                                                                                             'powershell.exe '
                                                                                                             'process '
                                                                                                             'as '
                                                                                                             'a '
                                                                                                             'child '
                                                                                                             'of '
                                                                                                             'the '
                                                                                                             'current '
                                                                                                             'process.',
                                                                                              'executor': {'command': 'Start-ATHProcessUnderSpecificParent '
                                                                                                                      '-FilePath '
                                                                                                                      '#{file_path} '
                                                                                                                      '-CommandLine '
                                                                                                                      "'#{command_line}' "
                                                                                                                      '-ParentId '
                                                                                                                      '#{parent_pid}',
                                                                                                           'name': 'powershell'},
                                                                                              'input_arguments': {'command_line': {'default': '-Command '
                                                                                                                                              'Start-Sleep '
                                                                                                                                              '10',
                                                                                                                                   'description': 'Specified '
                                                                                                                                                  'command '
                                                                                                                                                  'line '
                                                                                                                                                  'to '
                                                                                                                                                  'use',
                                                                                                                                   'type': 'string'},
                                                                                                                  'file_path': {'default': '$Env:windir\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                                                                                                                                'description': 'File '
                                                                                                                                               'path '
                                                                                                                                               'or '
                                                                                                                                               'name '
                                                                                                                                               'of '
                                                                                                                                               'process '
                                                                                                                                               'to '
                                                                                                                                               'spawn',
                                                                                                                                'type': 'path'},
                                                                                                                  'parent_pid': {'default': '$PID',
                                                                                                                                 'description': 'PID '
                                                                                                                                                'of '
                                                                                                                                                'process '
                                                                                                                                                'to '
                                                                                                                                                'spawn '
                                                                                                                                                'from',
                                                                                                                                 'type': 'string'}},
                                                                                              'name': 'Parent '
                                                                                                      'PID '
                                                                                                      'Spoofing '
                                                                                                      '- '
                                                                                                      'Spawn '
                                                                                                      'from '
                                                                                                      'Current '
                                                                                                      'Process',
                                                                                              'supported_platforms': ['windows']},
                                                                                             {'auto_generated_guid': 'cbbff285-9051-444a-9d17-c07cd2d230eb',
                                                                                              'dependencies': [{'description': 'The '
                                                                                                                               'AtomicTestHarnesses '
                                                                                                                               'module '
                                                                                                                               'must '
                                                                                                                               'be '
                                                                                                                               'installed '
                                                                                                                               'and '
                                                                                                                               'Start-ATHProcessUnderSpecificParent '
                                                                                                                               'must '
                                                                                                                               'be '
                                                                                                                               'exported '
                                                                                                                               'in '
                                                                                                                               'the '
                                                                                                                               'module.',
                                                                                                                'get_prereq_command': 'Install-Module '
                                                                                                                                      '-Name '
                                                                                                                                      'AtomicTestHarnesses '
                                                                                                                                      '-Scope '
                                                                                                                                      'CurrentUser '
                                                                                                                                      '-Force\n',
                                                                                                                'prereq_command': '$RequiredModule '
                                                                                                                                  '= '
                                                                                                                                  'Get-Module '
                                                                                                                                  '-Name '
                                                                                                                                  'AtomicTestHarnesses '
                                                                                                                                  '-ListAvailable\n'
                                                                                                                                  'if '
                                                                                                                                  '(-not '
                                                                                                                                  '$RequiredModule) '
                                                                                                                                  '{exit '
                                                                                                                                  '1}\n'
                                                                                                                                  'if '
                                                                                                                                  '(-not '
                                                                                                                                  "$RequiredModule.ExportedCommands['Start-ATHProcessUnderSpecificParent']) "
                                                                                                                                  '{exit '
                                                                                                                                  '1} '
                                                                                                                                  'else '
                                                                                                                                  '{exit '
                                                                                                                                  '0}'}],
                                                                                              'description': 'Spawns '
                                                                                                             'a '
                                                                                                             'notepad.exe '
                                                                                                             'process '
                                                                                                             'as '
                                                                                                             'a '
                                                                                                             'child '
                                                                                                             'of '
                                                                                                             'the '
                                                                                                             'current '
                                                                                                             'process.',
                                                                                              'executor': {'command': 'Start-ATHProcessUnderSpecificParent  '
                                                                                                                      '-ParentId '
                                                                                                                      '#{parent_pid} '
                                                                                                                      '-TestGuid '
                                                                                                                      '#{test_guid}',
                                                                                                           'name': 'powershell'},
                                                                                              'input_arguments': {'parent_pid': {'default': '$PID',
                                                                                                                                 'description': 'PID '
                                                                                                                                                'of '
                                                                                                                                                'process '
                                                                                                                                                'to '
                                                                                                                                                'spawn '
                                                                                                                                                'from',
                                                                                                                                 'type': 'string'},
                                                                                                                  'test_guid': {'default': '12345678-1234-1234-1234-123456789123',
                                                                                                                                'description': 'Defined '
                                                                                                                                               'test '
                                                                                                                                               'GUID',
                                                                                                                                'type': 'string'}},
                                                                                              'name': 'Parent '
                                                                                                      'PID '
                                                                                                      'Spoofing '
                                                                                                      '- '
                                                                                                      'Spawn '
                                                                                                      'from '
                                                                                                      'Specified '
                                                                                                      'Process',
                                                                                              'supported_platforms': ['windows']},
                                                                                             {'auto_generated_guid': 'e9f2b777-3123-430b-805d-5cedc66ab591',
                                                                                              'dependencies': [{'description': 'The '
                                                                                                                               'AtomicTestHarnesses '
                                                                                                                               'module '
                                                                                                                               'must '
                                                                                                                               'be '
                                                                                                                               'installed '
                                                                                                                               'and '
                                                                                                                               'Start-ATHProcessUnderSpecificParent '
                                                                                                                               'must '
                                                                                                                               'be '
                                                                                                                               'exported '
                                                                                                                               'in '
                                                                                                                               'the '
                                                                                                                               'module.',
                                                                                                                'get_prereq_command': 'Install-Module '
                                                                                                                                      '-Name '
                                                                                                                                      'AtomicTestHarnesses '
                                                                                                                                      '-Scope '
                                                                                                                                      'CurrentUser '
                                                                                                                                      '-Force\n',
                                                                                                                'prereq_command': '$RequiredModule '
                                                                                                                                  '= '
                                                                                                                                  'Get-Module '
                                                                                                                                  '-Name '
                                                                                                                                  'AtomicTestHarnesses '
                                                                                                                                  '-ListAvailable\n'
                                                                                                                                  'if '
                                                                                                                                  '(-not '
                                                                                                                                  '$RequiredModule) '
                                                                                                                                  '{exit '
                                                                                                                                  '1}\n'
                                                                                                                                  'if '
                                                                                                                                  '(-not '
                                                                                                                                  "$RequiredModule.ExportedCommands['Start-ATHProcessUnderSpecificParent']) "
                                                                                                                                  '{exit '
                                                                                                                                  '1} '
                                                                                                                                  'else '
                                                                                                                                  '{exit '
                                                                                                                                  '0}'}],
                                                                                              'description': 'Spawnd '
                                                                                                             'a '
                                                                                                             'process '
                                                                                                             'as '
                                                                                                             'a '
                                                                                                             'child '
                                                                                                             'of '
                                                                                                             'the '
                                                                                                             'first '
                                                                                                             'accessible '
                                                                                                             'svchost.exe '
                                                                                                             'process.',
                                                                                              'executor': {'command': 'Get-CimInstance '
                                                                                                                      '-ClassName '
                                                                                                                      'Win32_Process '
                                                                                                                      '-Property '
                                                                                                                      'Name, '
                                                                                                                      'CommandLine, '
                                                                                                                      'ProcessId '
                                                                                                                      '-Filter '
                                                                                                                      '"Name '
                                                                                                                      '= '
                                                                                                                      "'svchost.exe' "
                                                                                                                      'AND '
                                                                                                                      'CommandLine '
                                                                                                                      'LIKE '
                                                                                                                      '\'%\'" '
                                                                                                                      '| '
                                                                                                                      'Select-Object '
                                                                                                                      '-First '
                                                                                                                      '1 '
                                                                                                                      '| '
                                                                                                                      'Start-ATHProcessUnderSpecificParent '
                                                                                                                      '-FilePath '
                                                                                                                      '#{file_path} '
                                                                                                                      '-CommandLine '
                                                                                                                      "'#{command_line}'",
                                                                                                           'name': 'powershell'},
                                                                                              'input_arguments': {'command_line': {'default': '-Command '
                                                                                                                                              'Start-Sleep '
                                                                                                                                              '10',
                                                                                                                                   'description': 'Specified '
                                                                                                                                                  'command '
                                                                                                                                                  'line '
                                                                                                                                                  'to '
                                                                                                                                                  'use',
                                                                                                                                   'type': 'string'},
                                                                                                                  'file_path': {'default': '$Env:windir\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                                                                                                                                'description': 'File '
                                                                                                                                               'path '
                                                                                                                                               'or '
                                                                                                                                               'name '
                                                                                                                                               'of '
                                                                                                                                               'process '
                                                                                                                                               'to '
                                                                                                                                               'spawn',
                                                                                                                                'type': 'path'}},
                                                                                              'name': 'Parent '
                                                                                                      'PID '
                                                                                                      'Spoofing '
                                                                                                      '- '
                                                                                                      'Spawn '
                                                                                                      'from '
                                                                                                      'svchost.exe',
                                                                                              'supported_platforms': ['windows']},
                                                                                             {'auto_generated_guid': '2988133e-561c-4e42-a15f-6281e6a9b2db',
                                                                                              'dependencies': [{'description': 'The '
                                                                                                                               'AtomicTestHarnesses '
                                                                                                                               'module '
                                                                                                                               'must '
                                                                                                                               'be '
                                                                                                                               'installed '
                                                                                                                               'and '
                                                                                                                               'Start-ATHProcessUnderSpecificParent '
                                                                                                                               'must '
                                                                                                                               'be '
                                                                                                                               'exported '
                                                                                                                               'in '
                                                                                                                               'the '
                                                                                                                               'module.',
                                                                                                                'get_prereq_command': 'Install-Module '
                                                                                                                                      '-Name '
                                                                                                                                      'AtomicTestHarnesses '
                                                                                                                                      '-Scope '
                                                                                                                                      'CurrentUser '
                                                                                                                                      '-Force\n',
                                                                                                                'prereq_command': '$RequiredModule '
                                                                                                                                  '= '
                                                                                                                                  'Get-Module '
                                                                                                                                  '-Name '
                                                                                                                                  'AtomicTestHarnesses '
                                                                                                                                  '-ListAvailable\n'
                                                                                                                                  'if '
                                                                                                                                  '(-not '
                                                                                                                                  '$RequiredModule) '
                                                                                                                                  '{exit '
                                                                                                                                  '1}\n'
                                                                                                                                  'if '
                                                                                                                                  '(-not '
                                                                                                                                  "$RequiredModule.ExportedCommands['Start-ATHProcessUnderSpecificParent']) "
                                                                                                                                  '{exit '
                                                                                                                                  '1} '
                                                                                                                                  'else '
                                                                                                                                  '{exit '
                                                                                                                                  '0}'}],
                                                                                              'description': 'Creates '
                                                                                                             'a '
                                                                                                             'notepad.exe '
                                                                                                             'process '
                                                                                                             'and '
                                                                                                             'then '
                                                                                                             'spawns '
                                                                                                             'a '
                                                                                                             'powershell.exe '
                                                                                                             'process '
                                                                                                             'as '
                                                                                                             'a '
                                                                                                             'child '
                                                                                                             'of '
                                                                                                             'it.',
                                                                                              'executor': {'command': 'Start-Process '
                                                                                                                      '-FilePath '
                                                                                                                      '#{parent_name} '
                                                                                                                      '-PassThru '
                                                                                                                      '| '
                                                                                                                      'Start-ATHProcessUnderSpecificParent '
                                                                                                                      '-FilePath '
                                                                                                                      '#{file_path} '
                                                                                                                      '-CommandLine '
                                                                                                                      "'#{command_line}'",
                                                                                                           'name': 'powershell'},
                                                                                              'input_arguments': {'command_line': {'default': '-Command '
                                                                                                                                              'Start-Sleep '
                                                                                                                                              '10',
                                                                                                                                   'description': 'Specified '
                                                                                                                                                  'command '
                                                                                                                                                  'line '
                                                                                                                                                  'to '
                                                                                                                                                  'use',
                                                                                                                                   'type': 'string'},
                                                                                                                  'file_path': {'default': '$Env:windir\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                                                                                                                                'description': 'File '
                                                                                                                                               'path '
                                                                                                                                               'or '
                                                                                                                                               'name '
                                                                                                                                               'of '
                                                                                                                                               'process '
                                                                                                                                               'to '
                                                                                                                                               'spawn',
                                                                                                                                'type': 'path'},
                                                                                                                  'parent_name': {'default': '$Env:windir\\System32\\notepad.exe',
                                                                                                                                  'description': 'Parent '
                                                                                                                                                 'process '
                                                                                                                                                 'to '
                                                                                                                                                 'spoof '
                                                                                                                                                 'from',
                                                                                                                                  'type': 'path'}},
                                                                                              'name': 'Parent '
                                                                                                      'PID '
                                                                                                      'Spoofing '
                                                                                                      '- '
                                                                                                      'Spawn '
                                                                                                      'from '
                                                                                                      'New '
                                                                                                      'Process',
                                                                                              'supported_platforms': ['windows']}],
                                                                            'attack_technique': 'T1134.004',
                                                                            'display_name': 'Access '
                                                                                            'Token '
                                                                                            'Manipulation: '
                                                                                            'Parent '
                                                                                            'PID '
                                                                                            'Spoofing'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors

None
