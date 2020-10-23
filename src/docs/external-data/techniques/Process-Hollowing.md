
# Process Hollowing

## Description

### MITRE Description

> Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process.  

Process hollowing is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code. A victim process can be created with native Windows API calls such as <code>CreateProcess</code>, which includes a flag to suspend the processes primary thread. At this point the process can be unmapped using APIs calls such as <code>ZwUnmapViewOfSection</code> or <code>NtUnmapViewOfSection</code>  before being written to, realigned to the injected code, and resumed via <code>VirtualAllocEx</code>, <code>WriteProcessMemory</code>, <code>SetThreadContext</code>, then <code>ResumeThread</code> respectively.(Citation: Leitch Hollowing)(Citation: Endgame Process Injection July 2017)

This is very similar to [Thread Local Storage](https://attack.mitre.org/techniques/T1055/005) but creates a new process rather than targeting an existing process. This behavior will likely not result in elevated privileges since the injected process was spawned from (and thus inherits the security context) of the injecting process. However, execution via process hollowing may also evade detection from security products since the execution is masked under a legitimate process. 

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application control', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1055/012

## Potential Commands

```
. $PathToAtomicsFolder\T1055.012\src\Start-Hollow.ps1
$ppid=Get-Process #{parent_process_name} | select -expand id
Start-Hollow -Sponsor "#{sponsor_binary_path}" -Hollow "#{hollow_binary_path}" -ParentPID $ppid -Verbose
. $PathToAtomicsFolder\T1055.012\src\Start-Hollow.ps1
$ppid=Get-Process #{parent_process_name} | select -expand id
Start-Hollow -Sponsor "C:\Windows\System32\calc.exe" -Hollow "#{hollow_binary_path}" -ParentPID $ppid -Verbose
. $PathToAtomicsFolder\T1055.012\src\Start-Hollow.ps1
$ppid=Get-Process #{parent_process_name} | select -expand id
Start-Hollow -Sponsor "#{sponsor_binary_path}" -Hollow "C:\Windows\System32\cmd.exe" -ParentPID $ppid -Verbose
. $PathToAtomicsFolder\T1055.012\src\Start-Hollow.ps1
$ppid=Get-Process explorer | select -expand id
Start-Hollow -Sponsor "#{sponsor_binary_path}" -Hollow "#{hollow_binary_path}" -ParentPID $ppid -Verbose
```

## Commands Dataset

```
[{'command': '. $PathToAtomicsFolder\\T1055.012\\src\\Start-Hollow.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'Start-Hollow -Sponsor "#{sponsor_binary_path}" -Hollow '
             '"C:\\Windows\\System32\\cmd.exe" -ParentPID $ppid -Verbose\n',
  'name': None,
  'source': 'atomics/T1055.012/T1055.012.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1055.012\\src\\Start-Hollow.ps1\n'
             '$ppid=Get-Process explorer | select -expand id\n'
             'Start-Hollow -Sponsor "#{sponsor_binary_path}" -Hollow '
             '"#{hollow_binary_path}" -ParentPID $ppid -Verbose\n',
  'name': None,
  'source': 'atomics/T1055.012/T1055.012.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1055.012\\src\\Start-Hollow.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'Start-Hollow -Sponsor "C:\\Windows\\System32\\calc.exe" -Hollow '
             '"#{hollow_binary_path}" -ParentPID $ppid -Verbose\n',
  'name': None,
  'source': 'atomics/T1055.012/T1055.012.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1055.012\\src\\Start-Hollow.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'Start-Hollow -Sponsor "#{sponsor_binary_path}" -Hollow '
             '"#{hollow_binary_path}" -ParentPID $ppid -Verbose\n',
  'name': None,
  'source': 'atomics/T1055.012/T1055.012.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Process Injection: Process Hollowing': {'atomic_tests': [{'auto_generated_guid': '562427b4-39ef-4e8c-af88-463a78e70b9c',
                                                                                    'description': 'This '
                                                                                                   'test '
                                                                                                   'uses '
                                                                                                   'PowerShell '
                                                                                                   'to '
                                                                                                   'create '
                                                                                                   'a '
                                                                                                   'Hollow '
                                                                                                   'from '
                                                                                                   'a '
                                                                                                   'PE '
                                                                                                   'on '
                                                                                                   'disk '
                                                                                                   'with '
                                                                                                   'explorer '
                                                                                                   'as '
                                                                                                   'the '
                                                                                                   'parent.\n'
                                                                                                   'Credit '
                                                                                                   'to '
                                                                                                   'FuzzySecurity '
                                                                                                   '(https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Start-Hollow.ps1)\n',
                                                                                    'executor': {'cleanup_command': 'Stop-Process '
                                                                                                                    '-Name '
                                                                                                                    '"#{spawnto_process_name}" '
                                                                                                                    '-ErrorAction '
                                                                                                                    'Ignore\n',
                                                                                                 'command': '. '
                                                                                                            '$PathToAtomicsFolder\\T1055.012\\src\\Start-Hollow.ps1\n'
                                                                                                            '$ppid=Get-Process '
                                                                                                            '#{parent_process_name} '
                                                                                                            '| '
                                                                                                            'select '
                                                                                                            '-expand '
                                                                                                            'id\n'
                                                                                                            'Start-Hollow '
                                                                                                            '-Sponsor '
                                                                                                            '"#{sponsor_binary_path}" '
                                                                                                            '-Hollow '
                                                                                                            '"#{hollow_binary_path}" '
                                                                                                            '-ParentPID '
                                                                                                            '$ppid '
                                                                                                            '-Verbose\n',
                                                                                                 'name': 'powershell'},
                                                                                    'input_arguments': {'hollow_binary_path': {'default': 'C:\\Windows\\System32\\cmd.exe',
                                                                                                                               'description': 'Path '
                                                                                                                                              'of '
                                                                                                                                              'the '
                                                                                                                                              'binary '
                                                                                                                                              'to '
                                                                                                                                              'hollow '
                                                                                                                                              '(executable '
                                                                                                                                              'that '
                                                                                                                                              'will '
                                                                                                                                              'run '
                                                                                                                                              'inside '
                                                                                                                                              'the '
                                                                                                                                              'sponsor)',
                                                                                                                               'type': 'string'},
                                                                                                        'parent_process_name': {'default': 'explorer',
                                                                                                                                'description': 'Name '
                                                                                                                                               'of '
                                                                                                                                               'the '
                                                                                                                                               'parent '
                                                                                                                                               'process',
                                                                                                                                'type': 'string'},
                                                                                                        'spawnto_process_name': {'default': 'calc',
                                                                                                                                 'description': 'Name '
                                                                                                                                                'of '
                                                                                                                                                'the '
                                                                                                                                                'process '
                                                                                                                                                'to '
                                                                                                                                                'spawn',
                                                                                                                                 'type': 'string'},
                                                                                                        'sponsor_binary_path': {'default': 'C:\\Windows\\System32\\calc.exe',
                                                                                                                                'description': 'Path '
                                                                                                                                               'of '
                                                                                                                                               'the '
                                                                                                                                               'sponsor '
                                                                                                                                               'binary '
                                                                                                                                               '(executable '
                                                                                                                                               'that '
                                                                                                                                               'will '
                                                                                                                                               'host '
                                                                                                                                               'the '
                                                                                                                                               'binary)',
                                                                                                                                'type': 'string'}},
                                                                                    'name': 'Process '
                                                                                            'Hollowing '
                                                                                            'using '
                                                                                            'PowerShell',
                                                                                    'supported_platforms': ['windows']}],
                                                                  'attack_technique': 'T1055.012',
                                                                  'display_name': 'Process '
                                                                                  'Injection: '
                                                                                  'Process '
                                                                                  'Hollowing'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Behavior Prevention on Endpoint](../mitigations/Behavior-Prevention-on-Endpoint.md)


# Actors


* [Patchwork](../actors/Patchwork.md)

* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Gorgon Group](../actors/Gorgon-Group.md)
    
