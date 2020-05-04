
# Parent PID Spoofing

## Description

### MITRE Description

> Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges. New processes are typically spawned directly from their parent, or calling, process unless explicitly specified. One way of explicitly assigning the PPID of a new process is via the <code>CreateProcess</code> API call, which supports a parameter that defines the PPID to use.(Citation: DidierStevens SelectMyParent Nov 2009) This functionality is used by Windows features such as User Account Control (UAC) to correctly set the PPID after a requested elevated process is spawned by SYSTEM (typically via <code>svchost.exe</code> or <code>consent.exe</code>) rather than the current user context.(Citation: Microsoft UAC Nov 2018)

Adversaries may abuse these mechanisms to evade defenses, such as those blocking processes spawning directly from Office documents, and analysis targeting unusual/potentially malicious parent-child process relationships, such as spoofing the PPID of [PowerShell](https://attack.mitre.org/techniques/T1086)/[Rundll32](https://attack.mitre.org/techniques/T1085) to be <code>explorer.exe</code> rather than an Office document delivered as part of [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193).(Citation: CounterCept PPID Spoofing Dec 2018) This spoofing could be executed via VBA [Scripting](https://attack.mitre.org/techniques/T1064) within a malicious Office document or any code that can perform [Execution through API](https://attack.mitre.org/techniques/T1106).(Citation: CTD PPID Spoofing Macro Mar 2019)(Citation: CounterCept PPID Spoofing Dec 2018)

Explicitly assigning the PPID may also enable [Privilege Escalation](https://attack.mitre.org/tactics/TA0004) (given appropriate access rights to the parent process). For example, an adversary in a privileged user context (i.e. administrator) may spawn a new process and assign the parent as a process running as SYSTEM (such as <code>lsass.exe</code>), causing the new process to be elevated via the inherited access token.(Citation: XPNSec PPID Nov 2017)

## Additional Attributes

* Bypass: ['Host forensic analysis', 'Heuristic Detection']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1502

## Potential Commands

```
. $PathToAtomicsFolder\T1502\src\PPID-Spoof.ps1
$ppid=Get-Process explorer | select -expand id
PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" -dllpath "#{dll_path}"

. $PathToAtomicsFolder\T1502\src\PPID-Spoof.ps1
$ppid=Get-Process #{parent_process_name} | select -expand id
PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" -dllpath "PathToAtomicsFolder\T1502\bin\calc.dll"

. $PathToAtomicsFolder\T1502\src\PPID-Spoof.ps1
$ppid=Get-Process #{parent_process_name} | select -expand id
PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" -dllpath "#{dll_path}"

. $PathToAtomicsFolder\T1502\src\PPID-Spoof.ps1
$ppid=Get-Process #{parent_process_name} | select -expand id
PPID-Spoof -ppid $ppid -spawnto "C:\Program Files\Internet Explorer\iexplore.exe" -dllpath "#{dll_path}"

. $PathToAtomicsFolder\T1502\src\PPID-Spoof.ps1
$ppid=Get-Process #{parent_process_name} | select -expand id
PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" -dllpath "#{dll_path}"

```

## Commands Dataset

```
[{'command': '. $PathToAtomicsFolder\\T1502\\src\\PPID-Spoof.ps1\n'
             '$ppid=Get-Process explorer | select -expand id\n'
             'PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" '
             '-dllpath "#{dll_path}"\n',
  'name': None,
  'source': 'atomics/T1502/T1502.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1502\\src\\PPID-Spoof.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" '
             '-dllpath "PathToAtomicsFolder\\T1502\\bin\\calc.dll"\n',
  'name': None,
  'source': 'atomics/T1502/T1502.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1502\\src\\PPID-Spoof.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" '
             '-dllpath "#{dll_path}"\n',
  'name': None,
  'source': 'atomics/T1502/T1502.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1502\\src\\PPID-Spoof.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'PPID-Spoof -ppid $ppid -spawnto "C:\\Program Files\\Internet '
             'Explorer\\iexplore.exe" -dllpath "#{dll_path}"\n',
  'name': None,
  'source': 'atomics/T1502/T1502.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1502\\src\\PPID-Spoof.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'PPID-Spoof -ppid $ppid -spawnto "#{spawnto_process_path}" '
             '-dllpath "#{dll_path}"\n',
  'name': None,
  'source': 'atomics/T1502/T1502.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Parent PID Spoofing': {'atomic_tests': [{'dependencies': [{'description': 'DLL '
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
                                                                                                           '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1502/bin/calc.dll" '
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
                                                                                           '$PathToAtomicsFolder\\T1502\\src\\PPID-Spoof.ps1\n'
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
                                                                                'elevation_required': False,
                                                                                'name': 'powershell'},
                                                                   'input_arguments': {'dll_path': {'default': 'PathToAtomicsFolder\\T1502\\bin\\calc.dll',
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
                                                                   'supported_platforms': ['windows']}],
                                                 'attack_technique': 'T1502',
                                                 'display_name': 'Parent PID '
                                                                 'Spoofing'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors

None
