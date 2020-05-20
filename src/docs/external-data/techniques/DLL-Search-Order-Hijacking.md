
# DLL Search Order Hijacking

## Description

### MITRE Description

> Windows systems use a common method to look for required DLLs to load into a program. (Citation: Microsoft DLL Search) Adversaries may take advantage of the Windows DLL search order and programs that ambiguously specify DLLs to gain privilege escalation and persistence. 

Adversaries may perform DLL preloading, also called binary planting attacks, (Citation: OWASP Binary Planting) by placing a malicious DLL with the same name as an ambiguously specified DLL in a location that Windows searches before the legitimate DLL. Often this location is the current working directory of the program. Remote DLL preloading attacks occur when a program sets its current directory to a remote location such as a Web share before loading a DLL. (Citation: Microsoft 2269637) Adversaries may use this behavior to cause the program to load a malicious DLL. 

Adversaries may also directly modify the way a program loads DLLs by replacing an existing DLL or modifying a .manifest or .local redirection file, directory, or junction to cause the program to load a different DLL to maintain persistence or privilege escalation. (Citation: Microsoft DLL Redirection) (Citation: Microsoft Manifests) (Citation: Mandiant Search Order)

If a search order-vulnerable program is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation from user to administrator or SYSTEM or from administrator to SYSTEM, depending on the program.

Programs that fall victim to path hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Process whitelisting']
* Effective Permissions: ['User', 'Administrator', 'SYSTEM']
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1038

## Potential Commands

```
Check for common privilege escalation methods:
*upload PowerUp.ps1 to victim disk*
powershell.exe -epbypass PowerUp.ps1
Invoke-AllChecks
powershell-import /path/to/PowerUp.ps1
powershell Invoke-AllChecks
exploit/windows/local/trusted_service_path
copy %windir%\System32\windowspowershell\v1.0\powershell.exe %APPDATA%\updater.exe
copy %windir%\System32\amsi.dll %APPDATA%\amsi.dll
%APPDATA%\updater.exe -Command exit

powershell/privesc/powerup/find_dllhijack
powershell/privesc/powerup/find_dllhijack
powershell/privesc/powerup/write_dllhijacker
powershell/privesc/powerup/write_dllhijacker
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
 {'command': 'copy %windir%\\System32\\windowspowershell\\v1.0\\powershell.exe '
             '%APPDATA%\\updater.exe\n'
             'copy %windir%\\System32\\amsi.dll %APPDATA%\\amsi.dll\n'
             '%APPDATA%\\updater.exe -Command exit\n',
  'name': None,
  'source': 'atomics/T1038/T1038.yaml'},
 {'command': 'powershell/privesc/powerup/find_dllhijack',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/powerup/find_dllhijack',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/powerup/write_dllhijacker',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/powerup/write_dllhijacker',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Sysmon - ID 7', 'DLL monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Sysmon - ID 7', 'DLL monitoring']}]
```

## Potential Queries

```json

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
                                                  'Category': 'T1038',
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
 {'Atomic Red Team Test - DLL Search Order Hijacking': {'atomic_tests': [{'auto_generated_guid': '8549ad4b-b5df-4a2d-a3d7-2aee9e7052a3',
                                                                          'description': 'Adversaries '
                                                                                         'can '
                                                                                         'take '
                                                                                         'advantage '
                                                                                         'of '
                                                                                         'insecure '
                                                                                         'library '
                                                                                         'loading '
                                                                                         'by '
                                                                                         'PowerShell '
                                                                                         'to '
                                                                                         'load '
                                                                                         'a '
                                                                                         'vulnerable '
                                                                                         'version '
                                                                                         'of '
                                                                                         'amsi.dll '
                                                                                         'in '
                                                                                         'order '
                                                                                         'to '
                                                                                         'bypass '
                                                                                         'AMSI '
                                                                                         '(Anti-Malware '
                                                                                         'Scanning '
                                                                                         'Interface)\n'
                                                                                         'https://enigma0x3.net/2017/07/19/bypassing-amsi-via-com-server-hijacking/\n'
                                                                                         '\n'
                                                                                         'Upon '
                                                                                         'successful '
                                                                                         'execution, '
                                                                                         'powershell.exe '
                                                                                         'will '
                                                                                         'be '
                                                                                         'copied '
                                                                                         'and '
                                                                                         'renamed '
                                                                                         'to '
                                                                                         'updater.exe '
                                                                                         'and '
                                                                                         'load '
                                                                                         'amsi.dll '
                                                                                         'from '
                                                                                         'a '
                                                                                         'non-standard '
                                                                                         'path.\n',
                                                                          'executor': {'cleanup_command': 'del '
                                                                                                          '%APPDATA%\\updater.exe '
                                                                                                          '>nul '
                                                                                                          '2>&1\n'
                                                                                                          'del '
                                                                                                          '%APPDATA%\\amsi.dll '
                                                                                                          '>nul '
                                                                                                          '2>&1\n',
                                                                                       'command': 'copy '
                                                                                                  '%windir%\\System32\\windowspowershell\\v1.0\\powershell.exe '
                                                                                                  '%APPDATA%\\updater.exe\n'
                                                                                                  'copy '
                                                                                                  '%windir%\\System32\\amsi.dll '
                                                                                                  '%APPDATA%\\amsi.dll\n'
                                                                                                  '%APPDATA%\\updater.exe '
                                                                                                  '-Command '
                                                                                                  'exit\n',
                                                                                       'elevation_required': True,
                                                                                       'name': 'command_prompt'},
                                                                          'name': 'DLL '
                                                                                  'Search '
                                                                                  'Order '
                                                                                  'Hijacking '
                                                                                  '- '
                                                                                  'amsi.dll',
                                                                          'supported_platforms': ['windows']}],
                                                        'attack_technique': 'T1038',
                                                        'display_name': 'DLL '
                                                                        'Search '
                                                                        'Order '
                                                                        'Hijacking'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1038',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/powerup/find_dllhijack":  '
                                                                                 '["T1038"],',
                                            'Empire Module': 'powershell/privesc/powerup/find_dllhijack',
                                            'Technique': 'DLL Search Order '
                                                         'Hijacking'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1038',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/powerup/write_dllhijacker":  '
                                                                                 '["T1038"],',
                                            'Empire Module': 'powershell/privesc/powerup/write_dllhijacker',
                                            'Technique': 'DLL Search Order '
                                                         'Hijacking'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors


* [Threat Group-3390](../actors/Threat-Group-3390.md)

* [menuPass](../actors/menuPass.md)
    
