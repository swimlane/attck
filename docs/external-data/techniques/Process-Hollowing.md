
# Process Hollowing

## Description

### MITRE Description

> Process hollowing occurs when a process is created in a suspended state then its memory is unmapped and replaced with malicious code. Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), execution of the malicious code is masked under a legitimate process and may evade defenses and detection analysis. (Citation: Leitch Hollowing) (Citation: Endgame Process Injection July 2017)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Process whitelisting', 'Whitelisting by file name or path', 'Signature-based detection', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1093

## Potential Commands

```
. $PathToAtomicsFolder\T1093\src\Start-Hollow.ps1
$ppid=Get-Process explorer | select -expand id
Start-Hollow -Sponsor "#{sponsor_binary_path}" -Hollow "#{hollow_binary_path}" -ParentPID $ppid -Verbose

. $PathToAtomicsFolder\T1093\src\Start-Hollow.ps1
$ppid=Get-Process #{parent_process_name} | select -expand id
Start-Hollow -Sponsor "C:\Windows\System32\calc.exe" -Hollow "#{hollow_binary_path}" -ParentPID $ppid -Verbose

. $PathToAtomicsFolder\T1093\src\Start-Hollow.ps1
$ppid=Get-Process #{parent_process_name} | select -expand id
Start-Hollow -Sponsor "#{sponsor_binary_path}" -Hollow "C:\Windows\System32\cmd.exe" -ParentPID $ppid -Verbose

. $PathToAtomicsFolder\T1093\src\Start-Hollow.ps1
$ppid=Get-Process #{parent_process_name} | select -expand id
Start-Hollow -Sponsor "#{sponsor_binary_path}" -Hollow "#{hollow_binary_path}" -ParentPID $ppid -Verbose

```

## Commands Dataset

```
[{'command': '. $PathToAtomicsFolder\\T1093\\src\\Start-Hollow.ps1\n'
             '$ppid=Get-Process explorer | select -expand id\n'
             'Start-Hollow -Sponsor "#{sponsor_binary_path}" -Hollow '
             '"#{hollow_binary_path}" -ParentPID $ppid -Verbose\n',
  'name': None,
  'source': 'atomics/T1093/T1093.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1093\\src\\Start-Hollow.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'Start-Hollow -Sponsor "C:\\Windows\\System32\\calc.exe" -Hollow '
             '"#{hollow_binary_path}" -ParentPID $ppid -Verbose\n',
  'name': None,
  'source': 'atomics/T1093/T1093.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1093\\src\\Start-Hollow.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'Start-Hollow -Sponsor "#{sponsor_binary_path}" -Hollow '
             '"C:\\Windows\\System32\\cmd.exe" -ParentPID $ppid -Verbose\n',
  'name': None,
  'source': 'atomics/T1093/T1093.yaml'},
 {'command': '. $PathToAtomicsFolder\\T1093\\src\\Start-Hollow.ps1\n'
             '$ppid=Get-Process #{parent_process_name} | select -expand id\n'
             'Start-Hollow -Sponsor "#{sponsor_binary_path}" -Hollow '
             '"#{hollow_binary_path}" -ParentPID $ppid -Verbose\n',
  'name': None,
  'source': 'atomics/T1093/T1093.yaml'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['LMD - B9']},
 {'data_source': ['API monitoring']},
 {'data_source': ['Check with Fred']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['LOG-MD - B9', 'Binary file metadata']},
 {'data_source': ['API monitoring']},
 {'data_source': ['Check with Fred']}]
```

## Potential Queries

```json
[{'name': 'Process Holoowing',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_path contains "smss.exe"and '
           'process_parent_command_line !contains "smss.exe")or (process_path '
           'contains "csrss.exe"and (process_parent_command_line !contains '
           '"smss.exe"or process_parent_command_line !contains '
           '"svchost.exe"))or (process_path contains "wininit.exe"and '
           'process_parent_command_line !contains "smss.exe")or (process_path '
           'contains "winlogon.exe" and process_parent_command_line !contains '
           '"smss.exe")or (process_path contains "lsass.exe" and '
           'process_parent_command_line !contains "wininit.exe")or '
           '(process_path contains "LogonUI.exe"and '
           '(process_parent_command_line !contains "winlogon.exe" or '
           'process_parent_command_line !contains "wininit.exe"))or '
           '(process_path contains "services.exe" and '
           'process_parent_command_line !contains "wininit.exe")or '
           '(process_path contains "spoolsv.exe" and '
           'process_parent_command_line !contains "services.exe")or '
           '(process_path contains "taskhost.exe"and '
           '(process_parent_command_line !contains "services.exe" or '
           'process_parent_command_line !contains "svchost.exe"))or '
           '(process_path contains "taskhostw.exe"and '
           '(process_parent_command_line !contains "services.exe" or '
           'process_parent_command_line !contains "svchost.exe"))or '
           '(process_path contains "userinit.exe"and '
           '(process_parent_command_line !contains "dwm.exe" or '
           'process_parent_command_line !contains "winlogon.exe"))'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Process Hollowing': {'atomic_tests': [{'auto_generated_guid': '562427b4-39ef-4e8c-af88-463a78e70b9c',
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
                                                                                         '$PathToAtomicsFolder\\T1093\\src\\Start-Hollow.ps1\n'
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
                                                                              'elevation_required': False,
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
                                               'attack_technique': 'T1093',
                                               'display_name': 'Process '
                                                               'Hollowing'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [Patchwork](../actors/Patchwork.md)

* [menuPass](../actors/menuPass.md)
    
* [Gorgon Group](../actors/Gorgon-Group.md)
    
