
# Archive Collected Data

## Description

### MITRE Description

> An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network. Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.

Both compression and encryption are done prior to exfiltration, and can be performed using a utility, 3rd party library, or custom method.

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
* Wiki: https://attack.mitre.org/techniques/T1560

## Potential Commands

```
dir #{input_file} -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\T1560-data-ps.zip
dir $env:USERPROFILE -Recurse | Compress-Archive -DestinationPath #{output_file}
```

## Commands Dataset

```
[{'command': 'dir $env:USERPROFILE -Recurse | Compress-Archive '
             '-DestinationPath #{output_file}\n',
  'name': None,
  'source': 'atomics/T1560/T1560.yaml'},
 {'command': 'dir #{input_file} -Recurse | Compress-Archive -DestinationPath '
             '$env:USERPROFILE\\T1560-data-ps.zip\n',
  'name': None,
  'source': 'atomics/T1560/T1560.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Archive Collected Data': {'atomic_tests': [{'auto_generated_guid': '41410c60-614d-4b9d-b66e-b0192dd9c597',
                                                                      'description': 'An '
                                                                                     'adversary '
                                                                                     'may '
                                                                                     'compress '
                                                                                     'data '
                                                                                     '(e.g., '
                                                                                     'sensitive '
                                                                                     'documents) '
                                                                                     'that '
                                                                                     'is '
                                                                                     'collected '
                                                                                     'prior '
                                                                                     'to '
                                                                                     'exfiltration.\n'
                                                                                     'When '
                                                                                     'the '
                                                                                     'test '
                                                                                     'completes '
                                                                                     'you '
                                                                                     'should '
                                                                                     'find '
                                                                                     'the '
                                                                                     'files '
                                                                                     'from '
                                                                                     'the '
                                                                                     '$env:USERPROFILE '
                                                                                     'directory '
                                                                                     'compressed '
                                                                                     'in '
                                                                                     'a '
                                                                                     'file '
                                                                                     'called '
                                                                                     'T1560-data-ps.zip '
                                                                                     'in '
                                                                                     'the '
                                                                                     '$env:USERPROFILE '
                                                                                     'directory \n',
                                                                      'executor': {'cleanup_command': 'Remove-Item '
                                                                                                      '-path '
                                                                                                      '#{output_file} '
                                                                                                      '-ErrorAction '
                                                                                                      'Ignore',
                                                                                   'command': 'dir '
                                                                                              '#{input_file} '
                                                                                              '-Recurse '
                                                                                              '| '
                                                                                              'Compress-Archive '
                                                                                              '-DestinationPath '
                                                                                              '#{output_file}\n',
                                                                                   'elevation_required': False,
                                                                                   'name': 'powershell'},
                                                                      'input_arguments': {'input_file': {'default': '$env:USERPROFILE',
                                                                                                         'description': 'Path '
                                                                                                                        'that '
                                                                                                                        'should '
                                                                                                                        'be '
                                                                                                                        'compressed '
                                                                                                                        'into '
                                                                                                                        'our '
                                                                                                                        'output '
                                                                                                                        'file',
                                                                                                         'type': 'Path'},
                                                                                          'output_file': {'default': '$env:USERPROFILE\\T1560-data-ps.zip',
                                                                                                          'description': 'Path '
                                                                                                                         'where '
                                                                                                                         'resulting '
                                                                                                                         'compressed '
                                                                                                                         'data '
                                                                                                                         'should '
                                                                                                                         'be '
                                                                                                                         'placed',
                                                                                                          'type': 'Path'}},
                                                                      'name': 'Compress '
                                                                              'Data '
                                                                              'for '
                                                                              'Exfiltration '
                                                                              'With '
                                                                              'PowerShell',
                                                                      'supported_platforms': ['windows']}],
                                                    'attack_technique': 'T1560',
                                                    'display_name': 'Archive '
                                                                    'Collected '
                                                                    'Data'}}]
```

# Tactics


* [Collection](../tactics/Collection.md)


# Mitigations


* [Audit](../mitigations/Audit.md)


# Actors


* [Patchwork](../actors/Patchwork.md)

* [Honeybee](../actors/Honeybee.md)
    
* [FIN6](../actors/FIN6.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT28](../actors/APT28.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [APT32](../actors/APT32.md)
    
* [menuPass](../actors/menuPass.md)
    
