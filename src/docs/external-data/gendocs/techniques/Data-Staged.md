
# Data Staged

## Description

### MITRE Description

> Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.(Citation: PWC Cloud Hopper April 2017)

In cloud environments, adversaries may stage data within a particular instance or virtual machine before exfiltration. An adversary may [Create Cloud Instance](https://attack.mitre.org/techniques/T1578/002) and stage data in that instance.(Citation: Mandiant M-Trends 2020)

Adversaries may choose to stage data from a victim network in a centralized location prior to Exfiltration to minimize the number of connections made to their C2 server and better evade detection.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1074

## Potential Commands

```
{'darwin': {'sh': {'command': 'cp "#{host.file.path[filters(technique=T1005,max=3)]}" #{host.dir.staged[filters(max=1)]}\n'}}, 'linux': {'sh': {'command': 'cp "#{host.file.path[filters(technique=T1005,max=3)]}" #{host.dir.staged[filters(max=1)]}\n'}}, 'windows': {'psh': {'command': 'Copy-Item #{host.file.path[filters(technique=T1005,max=3)]} #{host.dir.staged[filters(max=1)]}\n'}, 'cmd': {'command': 'copy #{host.file.path[filters(technique=T1005,max=3)]} #{host.dir.staged[filters(max=1)]}\n'}}}
{'darwin': {'sh': {'command': 'mkdir -p staged && echo $PWD/staged\n', 'cleanup': 'rm -rf staged\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.staged'}]}}}, 'linux': {'sh': {'command': 'mkdir -p staged && echo $PWD/staged\n', 'cleanup': 'rm -rf staged\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.staged'}]}}}, 'windows': {'psh,pwsh': {'command': 'New-Item -Path "." -Name "staged" -ItemType "directory" -Force | foreach {$_.FullName} | Select-Object\n', 'cleanup': 'Remove-Item -Path "staged" -recurse\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.dir.staged'}]}}}}
```

## Commands Dataset

```
[{'command': {'darwin': {'sh': {'command': 'cp '
                                           '"#{host.file.path[filters(technique=T1005,max=3)]}" '
                                           '#{host.dir.staged[filters(max=1)]}\n'}},
              'linux': {'sh': {'command': 'cp '
                                          '"#{host.file.path[filters(technique=T1005,max=3)]}" '
                                          '#{host.dir.staged[filters(max=1)]}\n'}},
              'windows': {'cmd': {'command': 'copy '
                                             '#{host.file.path[filters(technique=T1005,max=3)]} '
                                             '#{host.dir.staged[filters(max=1)]}\n'},
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
[{'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']}]
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
[{'Mitre Stockpile - copy files to staging directory': {'description': 'copy '
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
                                                                                                     '#{host.dir.staged[filters(max=1)]}\n'},
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


* [Data Staged Mitigation](../mitigations/Data-Staged-Mitigation.md)


# Actors


* [Wizard Spider](../actors/Wizard-Spider.md)

