
# Keylogging

## Description

### MITRE Description

> Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured.

Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes.(Citation: Adventures of a Keystroke) Some methods include:

* Hooking API callbacks used for processing keystrokes. Unlike [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004), this focuses solely on API functions intended for processing keystroke data.
* Reading raw keystroke data from the hardware buffer.
* Windows Registry modifications.
* Custom drivers.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'root', 'SYSTEM', 'User']
* Platforms: ['Windows', 'macOS', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1056/001

## Potential Commands

```
Set-Location $PathToAtomicsFolder
.\T1056.001\src\Get-Keystrokes.ps1 -LogPath $env:TEMP\key.log
```

## Commands Dataset

```
[{'command': 'Set-Location $PathToAtomicsFolder\n'
             '.\\T1056.001\\src\\Get-Keystrokes.ps1 -LogPath '
             '$env:TEMP\\key.log\n',
  'name': None,
  'source': 'atomics/T1056.001/T1056.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Input Capture: Keylogging': {'atomic_tests': [{'auto_generated_guid': 'd9b633ca-8efb-45e6-b838-70f595c6ae26',
                                                                         'description': 'Utilize '
                                                                                        'PowerShell '
                                                                                        'and '
                                                                                        'external '
                                                                                        'resource '
                                                                                        'to '
                                                                                        'capture '
                                                                                        'keystrokes\n'
                                                                                        '[Payload](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/src/Get-Keystrokes.ps1)\n'
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
                                                                                        'key.log.\n',
                                                                         'executor': {'cleanup_command': 'Remove-Item '
                                                                                                         '$env:TEMP\\key.log '
                                                                                                         '-ErrorAction '
                                                                                                         'Ignore\n',
                                                                                      'command': 'Set-Location '
                                                                                                 '$PathToAtomicsFolder\n'
                                                                                                 '.\\T1056.001\\src\\Get-Keystrokes.ps1 '
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
                                                       'attack_technique': 'T1056.001',
                                                       'display_name': 'Input '
                                                                       'Capture: '
                                                                       'Keylogging'}}]
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
    
* [APT39](../actors/APT39.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
* [APT32](../actors/APT32.md)
    
