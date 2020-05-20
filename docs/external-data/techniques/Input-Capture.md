
# Input Capture

## Description

### MITRE Description

> Adversaries can use methods of capturing user input for obtaining credentials for [Valid Accounts](https://attack.mitre.org/techniques/T1078) and information Collection that include keylogging and user input field interception.

Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes, (Citation: Adventures of a Keystroke) but other methods exist to target information for specific purposes, such as performing a UAC prompt or wrapping the Windows default credential provider. (Citation: Wrightson 2012)

Keylogging is likely to be used to acquire credentials for new access opportunities when [Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to remain passive on a system for a period of time before an opportunity arises.

Adversaries may also install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through [External Remote Services](https://attack.mitre.org/techniques/T1133) and [Valid Accounts](https://attack.mitre.org/techniques/T1078) or as part of the initial compromise by exploitation of the externally facing web service. (Citation: Volexity Virtual Private Keylogging)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1056

## Potential Commands

```
starting the keylogger:
keylogger {x86|x64} {pid}
when you're ready to view logs:
view -> keylog
when you're done keylogging:
jobs
jobkill {job id number}
starting the keylogger:
keyscan_start
when you're ready to get the logs:
keyscan_dump
when you're done keylogging:
keyscan_stop
Set-Location $PathToAtomicsFolder
.\T1056\src\Get-Keystrokes.ps1 -LogPath $env:TEMP\key.log

powershell.exe Get-Keystrokes -LogPath C:\key.log
powershell/collection/USBKeylogger
powershell/collection/USBKeylogger
powershell/collection/keylogger
powershell/collection/keylogger
python/collection/linux/keylogger
python/collection/linux/keylogger
python/collection/linux/xkeylogger
python/collection/linux/xkeylogger
python/collection/osx/keylogger
python/collection/osx/keylogger
```

## Commands Dataset

```
[{'command': 'starting the keylogger:\n'
             'keylogger {x86|x64} {pid}\n'
             "when you're ready to view logs:\n"
             'view -> keylog\n'
             "when you're done keylogging:\n"
             'jobs\n'
             'jobkill {job id number}',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'starting the keylogger:\n'
             'keyscan_start\n'
             "when you're ready to get the logs:\n"
             'keyscan_dump\n'
             "when you're done keylogging:\n"
             'keyscan_stop',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Set-Location $PathToAtomicsFolder\n'
             '.\\T1056\\src\\Get-Keystrokes.ps1 -LogPath $env:TEMP\\key.log\n',
  'name': None,
  'source': 'atomics/T1056/T1056.yaml'},
 {'command': 'powershell.exe Get-Keystrokes -LogPath C:\\key.log',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell/collection/USBKeylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/USBKeylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/keylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/keylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/keylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/keylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/xkeylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/xkeylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/keylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/keylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Kernel drivers']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Kernel drivers']},
 {'data_source': ['API monitoring']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': '',
                                                  'Category': 'T1056',
                                                  'Cobalt Strike': 'starting '
                                                                   'the '
                                                                   'keylogger:\n'
                                                                   'keylogger '
                                                                   '{x86|x64} '
                                                                   '{pid}\n'
                                                                   'when '
                                                                   "you're "
                                                                   'ready to '
                                                                   'view '
                                                                   'logs:\n'
                                                                   'view -> '
                                                                   'keylog\n'
                                                                   'when '
                                                                   "you're "
                                                                   'done '
                                                                   'keylogging:\n'
                                                                   'jobs\n'
                                                                   'jobkill '
                                                                   '{job id '
                                                                   'number}',
                                                  'Description': 'Keylogging '
                                                                 'is extremely '
                                                                 'useful to '
                                                                 'get '
                                                                 'credentials '
                                                                 'and other '
                                                                 'information '
                                                                 'from the '
                                                                 'victim, but '
                                                                 'make sure '
                                                                 'that you are '
                                                                 'keylogging '
                                                                 'in a process '
                                                                 'belonging to '
                                                                 'the user you '
                                                                 'want to spy '
                                                                 'on. '
                                                                 'Keylogging '
                                                                 'within a '
                                                                 'SYSTEM '
                                                                 'process will '
                                                                 'not get you '
                                                                 'the '
                                                                 'keystrokes '
                                                                 'of other '
                                                                 'users on the '
                                                                 'system. For '
                                                                 'Cobalt '
                                                                 'Strike, make '
                                                                 'sure you '
                                                                 'specifiy the '
                                                                 'correct '
                                                                 'architecture '
                                                                 'and PID for '
                                                                 'a process '
                                                                 'running as '
                                                                 'the target '
                                                                 'victim. For '
                                                                 'Metasploit, '
                                                                 'make sure '
                                                                 "you've "
                                                                 'migrated to '
                                                                 'a process '
                                                                 'that is '
                                                                 'running as '
                                                                 'the target '
                                                                 'victim '
                                                                 '(explore.exe '
                                                                 'is always '
                                                                 'good).',
                                                  'Metasploit': 'starting the '
                                                                'keylogger:\n'
                                                                'keyscan_start\n'
                                                                "when you're "
                                                                'ready to get '
                                                                'the logs:\n'
                                                                'keyscan_dump\n'
                                                                "when you're "
                                                                'done '
                                                                'keylogging:\n'
                                                                'keyscan_stop'}},
 {'Atomic Red Team Test - Input Capture': {'atomic_tests': [{'auto_generated_guid': 'd9b633ca-8efb-45e6-b838-70f595c6ae26',
                                                             'description': 'Utilize '
                                                                            'PowerShell '
                                                                            'and '
                                                                            'external '
                                                                            'resource '
                                                                            'to '
                                                                            'capture '
                                                                            'keystrokes\n'
                                                                            '[Payload](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056/src/Get-Keystrokes.ps1)\n'
                                                                            'Provided '
                                                                            'by '
                                                                            '[PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-Keystrokes.ps1)\n'
                                                                            '\n'
                                                                            'Upon '
                                                                            'successful '
                                                                            'execution, '
                                                                            'Powershell '
                                                                            'will '
                                                                            'execute '
                                                                            '`Get-Keystrokes.ps1` '
                                                                            'and '
                                                                            'output '
                                                                            'to '
                                                                            'key.log. \n',
                                                             'executor': {'cleanup_command': 'Remove-Item '
                                                                                             '$env:TEMP\\key.log '
                                                                                             '-ErrorAction '
                                                                                             'Ignore\n',
                                                                          'command': 'Set-Location '
                                                                                     '$PathToAtomicsFolder\n'
                                                                                     '.\\T1056\\src\\Get-Keystrokes.ps1 '
                                                                                     '-LogPath '
                                                                                     '#{filepath}\n',
                                                                          'elevation_required': True,
                                                                          'name': 'powershell'},
                                                             'input_arguments': {'filepath': {'default': '$env:TEMP\\key.log',
                                                                                              'description': 'Name '
                                                                                                             'of '
                                                                                                             'the '
                                                                                                             'local '
                                                                                                             'file, '
                                                                                                             'include '
                                                                                                             'path.',
                                                                                              'type': 'Path'}},
                                                             'name': 'Input '
                                                                     'Capture',
                                                             'supported_platforms': ['windows']}],
                                           'attack_technique': 'T1056',
                                           'display_name': 'Input Capture'}},
 {'Threat Hunting Tables': {'chain_id': '100132',
                            'commandline_string': 'Get-Keystrokes -LogPath '
                                                  'C:\\key.log',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1056',
                            'mitre_caption': 'input_capture',
                            'os': 'windows',
                            'parent_process': 'powershell.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1056',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/USBKeylogger":  '
                                                                                 '["T1056"],',
                                            'Empire Module': 'powershell/collection/USBKeylogger',
                                            'Technique': 'Input Capture'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1056',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/keylogger":  '
                                                                                 '["T1056"],',
                                            'Empire Module': 'powershell/collection/keylogger',
                                            'Technique': 'Input Capture'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1056',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/linux/keylogger":  '
                                                                                 '["T1056"],',
                                            'Empire Module': 'python/collection/linux/keylogger',
                                            'Technique': 'Input Capture'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1056',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/linux/xkeylogger":  '
                                                                                 '["T1056"],',
                                            'Empire Module': 'python/collection/linux/xkeylogger',
                                            'Technique': 'Input Capture'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1056',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/keylogger":  '
                                                                                 '["T1056"],',
                                            'Empire Module': 'python/collection/osx/keylogger',
                                            'Technique': 'Input Capture'}}]
```

# Tactics


* [Collection](../tactics/Collection.md)

* [Credential Access](../tactics/Credential-Access.md)
    

# Mitigations

None

# Actors


* [APT3](../actors/APT3.md)

* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT38](../actors/APT38.md)
    
* [Sowbug](../actors/Sowbug.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [Group5](../actors/Group5.md)
    
* [PLATINUM](../actors/PLATINUM.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [FIN4](../actors/FIN4.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [APT28](../actors/APT28.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Stolen Pencil](../actors/Stolen-Pencil.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [APT41](../actors/APT41.md)
    
