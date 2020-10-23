
# Bypass User Access Control

## Description

### MITRE Description

> Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action. (Citation: TechNet How UAC Works)

If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs can elevate privileges or execute some elevated [Component Object Model](https://attack.mitre.org/techniques/T1559/001) objects without prompting the user through the UAC notification box. (Citation: TechNet Inside UAC) (Citation: MSDN COM Elevation) An example of this is use of [Rundll32](https://attack.mitre.org/techniques/T1218/011) to load a specifically crafted DLL which loads an auto-elevated [Component Object Model](https://attack.mitre.org/techniques/T1559/001) object and performs a file operation in a protected directory which would typically require elevated access. Malicious software may also be injected into a trusted process to gain elevated privileges without prompting a user.(Citation: Davidson Windows)

Many methods have been discovered to bypass UAC. The Github readme page for UACME contains an extensive list of methods(Citation: Github UACMe) that have been discovered and implemented, but may not be a comprehensive list of bypasses. Additional bypass methods are regularly discovered and some used in the wild, such as:

* <code>eventvwr.exe</code> can auto-elevate and execute a specified binary or script.(Citation: enigma0x3 Fileless UAC Bypass)(Citation: Fortinet Fareit)

Another bypass is possible through some lateral movement techniques if credentials for an account with administrator privileges are known, since UAC is a single system security mechanism, and the privilege or integrity of a process running on one system will be unknown on remote systems and default to high integrity.(Citation: SANS UAC Bypass)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Windows User Account Control']
* Effective Permissions: ['Administrator']
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1548/002

## Potential Commands

```
uacbypass
One of the following:
exploit/windows/local/bypassuac
exploit/windows/local/bypassuac_injection
exploit/windows/local/bypassuac_vbs
HKEY_USERS\*\mscfile\shell\open\command
eventvwr.exe
eventvwr.exe
verclsid.exe
mshta.exe
verclsid.exe
winword.exe
*.exe reg query
HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths
\Software\Classes\ms-settings\shell\open\command
\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\cmmgr32.exe
Software\Classes\mscfile\shell\open\command|mscfile\shell\open\command
\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe|\Software\Classes\exefile\shell\runas\command\isolatedCommand
powershell/privesc/ask
powershell/privesc/bypassuac
powershell/privesc/bypassuac_eventvwr
powershell/privesc/bypassuac_wscript
powershell/privesc/bypassuac_env
powershell/privesc/bypassuac_fodhelper
powershell/privesc/bypassuac_sdctlbypass
powershell/privesc/bypassuac_tokenmanipulation
```

## Commands Dataset

```
[{'command': 'uacbypass',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'One of the following:\n'
             'exploit/windows/local/bypassuac\n'
             'exploit/windows/local/bypassuac_injection\n'
             'exploit/windows/local/bypassuac_vbs',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'eventvwr.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'HKEY_USERS\\*\\mscfile\\shell\\open\\command',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'eventvwr.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'mshta.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'verclsid.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'winword.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'verclsid.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe reg query',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'Software\\Classes\\mscfile\\shell\\open\\command|mscfile\\shell\\open\\command',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': 'Software\\Classes\\mscfile\\shell\\open\\command|mscfile\\shell\\open\\command',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': '\\Software\\Microsoft\\Windows\\CurrentVersion\\App '
             'Paths\\control.exe|\\Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': '\\Software\\Microsoft\\Windows\\CurrentVersion\\App '
             'Paths\\control.exe|\\Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': '\\Software\\Classes\\ms-settings\\shell\\open\\command',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': '\\Software\\Classes\\ms-settings\\shell\\open\\command',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App '
             'Paths\\cmmgr32.exe',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App '
             'Paths\\cmmgr32.exe',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': 'powershell/privesc/ask',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/ask',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_eventvwr',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_eventvwr',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_wscript',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_wscript',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_env',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_env',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_fodhelper',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_fodhelper',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_sdctlbypass',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_sdctlbypass',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_tokenmanipulation',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_tokenmanipulation',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'description': 'Detects UAC bypass method using Windows '
                                 'event viewer',
                  'detection': {'condition': 'methregistry or ( methprocess '
                                             'and not filterprocess )',
                                'filterprocess': {'Image': '*\\mmc.exe'},
                                'methprocess': {'EventID': 1,
                                                'ParentImage': '*\\eventvwr.exe'},
                                'methregistry': {'EventID': 13,
                                                 'TargetObject': 'HKEY_USERS\\\\*\\mscfile\\shell\\open\\command'}},
                  'falsepositives': ['unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '7c81fec3-1c1d-43b0-996a-46753041b1b6',
                  'level': 'critical',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/',
                                 'https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.privilege_escalation',
                           'attack.t1088',
                           'car.2019-04-001'],
                  'title': 'UAC Bypass via Event Viewer'}},
 {'data_source': {'author': 'Omer Yampel',
                  'description': 'Detects changes to '
                                 'HKCU:\\Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 13,
                                              'TargetObject': 'HKEY_USERS\\\\*\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand'}},
                  'falsepositives': ['unknown'],
                  'id': '5b872a46-3b90-45c1-8419-f675db8053aa',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.privilege_escalation',
                           'attack.t1088',
                           'car.2019-04-001'],
                  'title': 'UAC Bypass via sdclt'}},
 {'data_source': {'author': 'Ecco',
                  'date': '2019/08/30',
                  'description': 'Detects some Empire PowerShell UAC bypass '
                                 'methods',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['* -NoP -NonI -w '
                                                              'Hidden -c '
                                                              '$x=$((gp '
                                                              'HKCU:Software\\\\Microsoft\\\\Windows '
                                                              'Update).Update)*',
                                                              '* -NoP -NonI -c '
                                                              '$x=$((gp '
                                                              'HKCU:Software\\\\Microsoft\\\\Windows '
                                                              'Update).Update);*']}},
                  'falsepositives': ['unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '3268b746-88d8-4cd3-bffc-30077d02c787',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64',
                                 'https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-FodHelperBypass.ps1#L64'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.privilege_escalation',
                           'attack.t1088',
                           'car.2019-04-001'],
                  'title': 'Empire PowerShell UAC Bypass'}},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['System calls']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4624', 'Authentication logs']},
 {'data_source': ['System calls']}]
```

## Potential Queries

```json
[{'name': 'Bypass User Account Control Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_parent_command_line '
           'contains "eventvwr.exe"or process_parent_command_line contains '
           '"fodhelper.exe"or process_path contains "ShellRunas.exe")'},
 {'name': 'Bypass User Account Control Registry',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           '(registry_key_path contains '
           '"*\\\\mscfile\\\\shell\\\\open\\\\command\\\\*"or '
           'registry_key_path contains '
           '"*\\\\ms-settings\\\\shell\\\\open\\\\command\\\\*")'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': '',
                                                  'Category': 'T1088',
                                                  'Cobalt Strike': 'uacbypass',
                                                  'Description': 'If you have '
                                                                 'a medium '
                                                                 'integrity '
                                                                 'process, but '
                                                                 'are an '
                                                                 'administrator, '
                                                                 'UACBypass '
                                                                 'will get you '
                                                                 'a high '
                                                                 'integrity '
                                                                 'process '
                                                                 'without '
                                                                 'prompting '
                                                                 'the user for '
                                                                 'confirmation.',
                                                  'Metasploit': 'One of the '
                                                                'following:\n'
                                                                'exploit/windows/local/bypassuac\n'
                                                                'exploit/windows/local/bypassuac_injection\n'
                                                                'exploit/windows/local/bypassuac_vbs'}},
 {'Threat Hunting Tables': {'chain_id': '100012',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1088',
                            'mitre_caption': 'bypass_uac',
                            'os': 'windows',
                            'parent_process': 'eventvwr.exe',
                            'registry_path': 'HKEY_USERS\\*\\mscfile\\shell\\open\\command',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100024',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1088',
                            'mitre_caption': 'bypass_uac',
                            'os': 'windows',
                            'parent_process': 'eventvwr.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100047',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': 'https://www.redcanary.com/blog/verclsid-exe-threat-detection/',
                            'loaded_dll': '',
                            'mitre_attack': 'T1088',
                            'mitre_caption': 'bypass_uac',
                            'os': 'windows',
                            'parent_process': 'mshta.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'verclsid.exe',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100096',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1088',
                            'mitre_caption': 'bypass_uac',
                            'os': 'windows',
                            'parent_process': 'winword.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'verclsid.exe',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100203',
                            'commandline_string': 'reg query',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1088',
                            'mitre_caption': 'bypass_uac',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\App '
                                             'Paths',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'SysmonHunter - T1088': {'description': None,
                           'level': 'high',
                           'name': 'UAC bypass',
                           'phase': 'Privilege Escalation',
                           'query': [{'reg': {'path': {'pattern': 'Software\\Classes\\mscfile\\shell\\open\\command|mscfile\\shell\\open\\command'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'pattern': 'Software\\Classes\\mscfile\\shell\\open\\command|mscfile\\shell\\open\\command'}},
                                      'type': 'process'},
                                     {'reg': {'path': {'pattern': '\\Software\\Microsoft\\Windows\\CurrentVersion\\App '
                                                                  'Paths\\control.exe|\\Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'pattern': '\\Software\\Microsoft\\Windows\\CurrentVersion\\App '
                                                                         'Paths\\control.exe|\\Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand'}},
                                      'type': 'process'},
                                     {'reg': {'path': {'pattern': '\\Software\\Classes\\ms-settings\\shell\\open\\command'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'pattern': '\\Software\\Classes\\ms-settings\\shell\\open\\command'}},
                                      'type': 'process'},
                                     {'reg': {'path': {'pattern': '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App '
                                                                  'Paths\\cmmgr32.exe'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'pattern': '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App '
                                                                         'Paths\\cmmgr32.exe'}},
                                      'type': 'process'}]}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/ask":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/ask',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac_eventvwr":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac_eventvwr',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac_wscript":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac_wscript',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac_env":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac_env',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac_fodhelper":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac_fodhelper',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac_sdctlbypass":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac_sdctlbypass',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac_tokenmanipulation":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac_tokenmanipulation',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)

* [User Account Control](../mitigations/User-Account-Control.md)
    
* [Audit](../mitigations/Audit.md)
    
* [Update Software](../mitigations/Update-Software.md)
    

# Actors


* [Honeybee](../actors/Honeybee.md)

* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [APT29](../actors/APT29.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [APT37](../actors/APT37.md)
    
