
# Modify Existing Service

## Description

### MITRE Description

> Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Registry. Service configurations can be modified using utilities such as sc.exe and [Reg](https://attack.mitre.org/software/S0075).

Adversaries can modify an existing service to persist malware on a system by using system utilities or by using custom tools to interact with the Windows API. Use of existing services is a type of [Masquerading](https://attack.mitre.org/techniques/T1036) that may make detection analysis more challenging. Modifying existing services may interrupt their functionality or may enable services that are disabled or otherwise not commonly used.

Adversaries may also intentionally corrupt or kill services to execute malicious recovery programs/commands. (Citation: Twitter Service Recovery Nov 2017) (Citation: Microsoft Service Recovery Feb 2013)

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
* Wiki: https://attack.mitre.org/techniques/T1031

## Potential Commands

```
sc config Fax binPath= "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -noexit -c \"write-host 'T1031 Test'\""
sc start Fax

{'windows': {'psh': {'command': '$s = Get-Service -Name #{host.service.modifiable};\nif ($s.status -ne \'Stopped\') { Stop-Service $s };\n$exe = (Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Services\\#{host.service.modifiable}").ImagePath.split()[0];\n$path = (Resolve-Path $exe).Path;\nCopy-Item -Path $path -Destination ($path + ".saved");\nCopy-Item -Path "C:\\Windows\\System32\\snmptrap.exe" -Destination $path\n', 'cleanup': '$exe = (Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Services\\#{host.service.modifiable}").ImagePath.split()[0];\n$path = (Resolve-Path $exe).Path;\nIf (Test-Path ($path + ".saved")) {\n  Remove-Item $path;\n  Move-Item -Path ($path + ".saved") -Destination $path\n}\n'}}}
sc.exe
```

## Commands Dataset

```
[{'command': 'sc config Fax binPath= '
             '"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe '
             '-noexit -c \\"write-host \'T1031 Test\'\\""\n'
             'sc start Fax\n',
  'name': None,
  'source': 'atomics/T1031/T1031.yaml'},
 {'command': {'windows': {'psh': {'cleanup': '$exe = (Get-ItemProperty -Path '
                                             '"HKLM:\\System\\CurrentControlSet\\Services\\#{host.service.modifiable}").ImagePath.split()[0];\n'
                                             '$path = (Resolve-Path '
                                             '$exe).Path;\n'
                                             'If (Test-Path ($path + '
                                             '".saved")) {\n'
                                             '  Remove-Item $path;\n'
                                             '  Move-Item -Path ($path + '
                                             '".saved") -Destination $path\n'
                                             '}\n',
                                  'command': '$s = Get-Service -Name '
                                             '#{host.service.modifiable};\n'
                                             "if ($s.status -ne 'Stopped') { "
                                             'Stop-Service $s };\n'
                                             '$exe = (Get-ItemProperty -Path '
                                             '"HKLM:\\System\\CurrentControlSet\\Services\\#{host.service.modifiable}").ImagePath.split()[0];\n'
                                             '$path = (Resolve-Path '
                                             '$exe).Path;\n'
                                             'Copy-Item -Path $path '
                                             '-Destination ($path + '
                                             '".saved");\n'
                                             'Copy-Item -Path '
                                             '"C:\\Windows\\System32\\snmptrap.exe" '
                                             '-Destination $path\n'}}},
  'name': 'This is an example technique. snmptrap.exe should be changed in the '
          'command\n'
          'below with the new desired service binary. Depending on the value '
          'of\n'
          'host.service.modifiable this ability can damage the target '
          'system.\n',
  'source': 'data/abilities/persistence/52771610-2322-44cf-816b-a7df42b4c086.yml'},
 {'command': 'sc.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'}]
```

## Potential Detections

```json
[{'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['7040', 'Service Change']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['7040/7045', 'Service Change']}]
```

## Potential Queries

```json
[{'name': 'Modify Existing Service',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains "sc.exe"or '
           'process_path contains "powershell.exe"or process_path contains '
           '"cmd.exe")and process_command_line contains "*sc*config*binpath*"'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Modify Existing Service': {'atomic_tests': [{'auto_generated_guid': 'ed366cde-7d12-49df-a833-671904770b9f',
                                                                       'description': 'This '
                                                                                      'test '
                                                                                      'will '
                                                                                      'temporarily '
                                                                                      'modify '
                                                                                      'the '
                                                                                      'service '
                                                                                      'Fax '
                                                                                      'by '
                                                                                      'changing '
                                                                                      'the '
                                                                                      'binPath '
                                                                                      'to '
                                                                                      'PowerShell\n'
                                                                                      'and '
                                                                                      'will '
                                                                                      'then '
                                                                                      'revert '
                                                                                      'the '
                                                                                      'binPath '
                                                                                      'change, '
                                                                                      'restoring '
                                                                                      'Fax '
                                                                                      'to '
                                                                                      'its '
                                                                                      'original '
                                                                                      'state.\n'
                                                                                      '\n'
                                                                                      'Upon '
                                                                                      'successful '
                                                                                      'execution, '
                                                                                      'cmd '
                                                                                      'will '
                                                                                      'modify '
                                                                                      'the '
                                                                                      'binpath '
                                                                                      'for '
                                                                                      '`Fax` '
                                                                                      'to '
                                                                                      'spawn '
                                                                                      'powershell. '
                                                                                      'Powershell '
                                                                                      'will '
                                                                                      'then '
                                                                                      'spawn.\n',
                                                                       'executor': {'cleanup_command': 'sc '
                                                                                                       'config '
                                                                                                       'Fax '
                                                                                                       'binPath= '
                                                                                                       '"C:\\WINDOWS\\system32\\fxssvc.exe" '
                                                                                                       '>nul '
                                                                                                       '2>&1',
                                                                                    'command': 'sc '
                                                                                               'config '
                                                                                               'Fax '
                                                                                               'binPath= '
                                                                                               '"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe '
                                                                                               '-noexit '
                                                                                               '-c '
                                                                                               '\\"write-host '
                                                                                               "'T1031 "
                                                                                               'Test\'\\""\n'
                                                                                               'sc '
                                                                                               'start '
                                                                                               'Fax\n',
                                                                                    'elevation_required': True,
                                                                                    'name': 'command_prompt'},
                                                                       'name': 'Modify '
                                                                               'Fax '
                                                                               'service '
                                                                               'to '
                                                                               'run '
                                                                               'PowerShell',
                                                                       'supported_platforms': ['windows']}],
                                                     'attack_technique': 'T1031',
                                                     'display_name': 'Modify '
                                                                     'Existing '
                                                                     'Service'}},
 {'Mitre Stockpile - This is an example technique. snmptrap.exe should be changed in the command\nbelow with the new desired service binary. Depending on the value of\nhost.service.modifiable this ability can damage the target system.\n': {'description': 'This '
                                                                                                                                                                                                                                                               'is '
                                                                                                                                                                                                                                                               'an '
                                                                                                                                                                                                                                                               'example '
                                                                                                                                                                                                                                                               'technique. '
                                                                                                                                                                                                                                                               'snmptrap.exe '
                                                                                                                                                                                                                                                               'should '
                                                                                                                                                                                                                                                               'be '
                                                                                                                                                                                                                                                               'changed '
                                                                                                                                                                                                                                                               'in '
                                                                                                                                                                                                                                                               'the '
                                                                                                                                                                                                                                                               'command\n'
                                                                                                                                                                                                                                                               'below '
                                                                                                                                                                                                                                                               'with '
                                                                                                                                                                                                                                                               'the '
                                                                                                                                                                                                                                                               'new '
                                                                                                                                                                                                                                                               'desired '
                                                                                                                                                                                                                                                               'service '
                                                                                                                                                                                                                                                               'binary. '
                                                                                                                                                                                                                                                               'Depending '
                                                                                                                                                                                                                                                               'on '
                                                                                                                                                                                                                                                               'the '
                                                                                                                                                                                                                                                               'value '
                                                                                                                                                                                                                                                               'of\n'
                                                                                                                                                                                                                                                               'host.service.modifiable '
                                                                                                                                                                                                                                                               'this '
                                                                                                                                                                                                                                                               'ability '
                                                                                                                                                                                                                                                               'can '
                                                                                                                                                                                                                                                               'damage '
                                                                                                                                                                                                                                                               'the '
                                                                                                                                                                                                                                                               'target '
                                                                                                                                                                                                                                                               'system.\n',
                                                                                                                                                                                                                                                'id': '52771610-2322-44cf-816b-a7df42b4c086',
                                                                                                                                                                                                                                                'name': 'Replace '
                                                                                                                                                                                                                                                        'a '
                                                                                                                                                                                                                                                        'service '
                                                                                                                                                                                                                                                        'binary '
                                                                                                                                                                                                                                                        'with '
                                                                                                                                                                                                                                                        'alternate '
                                                                                                                                                                                                                                                        'binary',
                                                                                                                                                                                                                                                'platforms': {'windows': {'psh': {'cleanup': '$exe '
                                                                                                                                                                                                                                                                                             '= '
                                                                                                                                                                                                                                                                                             '(Get-ItemProperty '
                                                                                                                                                                                                                                                                                             '-Path '
                                                                                                                                                                                                                                                                                             '"HKLM:\\System\\CurrentControlSet\\Services\\#{host.service.modifiable}").ImagePath.split()[0];\n'
                                                                                                                                                                                                                                                                                             '$path '
                                                                                                                                                                                                                                                                                             '= '
                                                                                                                                                                                                                                                                                             '(Resolve-Path '
                                                                                                                                                                                                                                                                                             '$exe).Path;\n'
                                                                                                                                                                                                                                                                                             'If '
                                                                                                                                                                                                                                                                                             '(Test-Path '
                                                                                                                                                                                                                                                                                             '($path '
                                                                                                                                                                                                                                                                                             '+ '
                                                                                                                                                                                                                                                                                             '".saved")) '
                                                                                                                                                                                                                                                                                             '{\n'
                                                                                                                                                                                                                                                                                             '  '
                                                                                                                                                                                                                                                                                             'Remove-Item '
                                                                                                                                                                                                                                                                                             '$path;\n'
                                                                                                                                                                                                                                                                                             '  '
                                                                                                                                                                                                                                                                                             'Move-Item '
                                                                                                                                                                                                                                                                                             '-Path '
                                                                                                                                                                                                                                                                                             '($path '
                                                                                                                                                                                                                                                                                             '+ '
                                                                                                                                                                                                                                                                                             '".saved") '
                                                                                                                                                                                                                                                                                             '-Destination '
                                                                                                                                                                                                                                                                                             '$path\n'
                                                                                                                                                                                                                                                                                             '}\n',
                                                                                                                                                                                                                                                                                  'command': '$s '
                                                                                                                                                                                                                                                                                             '= '
                                                                                                                                                                                                                                                                                             'Get-Service '
                                                                                                                                                                                                                                                                                             '-Name '
                                                                                                                                                                                                                                                                                             '#{host.service.modifiable};\n'
                                                                                                                                                                                                                                                                                             'if '
                                                                                                                                                                                                                                                                                             '($s.status '
                                                                                                                                                                                                                                                                                             '-ne '
                                                                                                                                                                                                                                                                                             "'Stopped') "
                                                                                                                                                                                                                                                                                             '{ '
                                                                                                                                                                                                                                                                                             'Stop-Service '
                                                                                                                                                                                                                                                                                             '$s '
                                                                                                                                                                                                                                                                                             '};\n'
                                                                                                                                                                                                                                                                                             '$exe '
                                                                                                                                                                                                                                                                                             '= '
                                                                                                                                                                                                                                                                                             '(Get-ItemProperty '
                                                                                                                                                                                                                                                                                             '-Path '
                                                                                                                                                                                                                                                                                             '"HKLM:\\System\\CurrentControlSet\\Services\\#{host.service.modifiable}").ImagePath.split()[0];\n'
                                                                                                                                                                                                                                                                                             '$path '
                                                                                                                                                                                                                                                                                             '= '
                                                                                                                                                                                                                                                                                             '(Resolve-Path '
                                                                                                                                                                                                                                                                                             '$exe).Path;\n'
                                                                                                                                                                                                                                                                                             'Copy-Item '
                                                                                                                                                                                                                                                                                             '-Path '
                                                                                                                                                                                                                                                                                             '$path '
                                                                                                                                                                                                                                                                                             '-Destination '
                                                                                                                                                                                                                                                                                             '($path '
                                                                                                                                                                                                                                                                                             '+ '
                                                                                                                                                                                                                                                                                             '".saved");\n'
                                                                                                                                                                                                                                                                                             'Copy-Item '
                                                                                                                                                                                                                                                                                             '-Path '
                                                                                                                                                                                                                                                                                             '"C:\\Windows\\System32\\snmptrap.exe" '
                                                                                                                                                                                                                                                                                             '-Destination '
                                                                                                                                                                                                                                                                                             '$path\n'}}},
                                                                                                                                                                                                                                                'requirements': [{'plugins.stockpile.app.requirements.paw_provenance': [{'source': 'host.service.modifiable'}]}],
                                                                                                                                                                                                                                                'tactic': 'persistence',
                                                                                                                                                                                                                                                'technique': {'attack_id': 'T1031',
                                                                                                                                                                                                                                                              'name': 'Modify '
                                                                                                                                                                                                                                                                      'Existing '
                                                                                                                                                                                                                                                                      'Service'}}},
 {'Threat Hunting Tables': {'chain_id': '100073',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1031',
                            'mitre_caption': 'sc',
                            'os': 'windows',
                            'parent_process': 'sc.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors


* [APT32](../actors/APT32.md)

* [Honeybee](../actors/Honeybee.md)
    
* [APT19](../actors/APT19.md)
    
* [APT41](../actors/APT41.md)
    
