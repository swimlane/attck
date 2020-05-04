
# Software Packing

## Description

### MITRE Description

> Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory.

Utilities used to perform software packing are called packers. Example packers are MPRESS and UPX. A more comprehensive list of known packers is available, (Citation: Wikipedia Exe Compression) but adversaries may create their own packing techniques that do not leave the same artifacts as well-known packers to evade defenses.

Adversaries may use virtual machine software protection as a form of software packing to protect their code. Virtual machine software protection translates an executable's original code into a special format that only a special virtual machine can run. A virtual machine is then called to run this code.(Citation: ESET FinFisher Jan 2018)

## Additional Attributes

* Bypass: ['Signature-based detection', 'Anti-virus', 'Heuristic detection']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Windows', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1045

## Potential Commands

```
cp PathToAtomicsFolder/T1045/bin/linux/test_upx /tmp/packed_bin && /tmp/packed_bin

cp PathToAtomicsFolder/T1045/bin/linux/test_upx_header_changed /tmp/packed_bin && /tmp/packed_bin

cp PathToAtomicsFolder/T1045/bin/darwin/test_upx /tmp/packed_bin && /tmp/packed_bin

cp PathToAtomicsFolder/T1045/bin/darwin/test_upx_header_changed /tmp/packed_bin && /tmp/packed_bin

```

## Commands Dataset

```
[{'command': 'cp PathToAtomicsFolder/T1045/bin/linux/test_upx /tmp/packed_bin '
             '&& /tmp/packed_bin\n',
  'name': None,
  'source': 'atomics/T1045/T1045.yaml'},
 {'command': 'cp PathToAtomicsFolder/T1045/bin/linux/test_upx_header_changed '
             '/tmp/packed_bin && /tmp/packed_bin\n',
  'name': None,
  'source': 'atomics/T1045/T1045.yaml'},
 {'command': 'cp PathToAtomicsFolder/T1045/bin/darwin/test_upx /tmp/packed_bin '
             '&& /tmp/packed_bin\n',
  'name': None,
  'source': 'atomics/T1045/T1045.yaml'},
 {'command': 'cp PathToAtomicsFolder/T1045/bin/darwin/test_upx_header_changed '
             '/tmp/packed_bin && /tmp/packed_bin\n',
  'name': None,
  'source': 'atomics/T1045/T1045.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Software Packing': {'atomic_tests': [{'description': 'Copies '
                                                                               'and '
                                                                               'then '
                                                                               'runs '
                                                                               'a '
                                                                               'simple '
                                                                               'binary '
                                                                               '(just '
                                                                               'outputting '
                                                                               '"the '
                                                                               'cake '
                                                                               'is '
                                                                               'a '
                                                                               'lie"), '
                                                                               'that '
                                                                               'was '
                                                                               'packed '
                                                                               'by '
                                                                               'UPX.\n'
                                                                               'No '
                                                                               'other '
                                                                               'protection/compression '
                                                                               'were '
                                                                               'applied.\n',
                                                                'executor': {'cleanup_command': 'rm '
                                                                                                '/tmp/packed_bin\n',
                                                                             'command': 'cp '
                                                                                        '#{bin_path} '
                                                                                        '/tmp/packed_bin '
                                                                                        '&& '
                                                                                        '/tmp/packed_bin\n',
                                                                             'elevation_required': False,
                                                                             'name': 'sh'},
                                                                'input_arguments': {'bin_path': {'default': 'PathToAtomicsFolder/T1045/bin/linux/test_upx',
                                                                                                 'description': 'Packed '
                                                                                                                'binary',
                                                                                                 'type': 'Path'}},
                                                                'name': 'Binary '
                                                                        'simply '
                                                                        'packed '
                                                                        'by '
                                                                        'UPX '
                                                                        '(linux)',
                                                                'supported_platforms': ['linux']},
                                                               {'description': 'Copies '
                                                                               'and '
                                                                               'then '
                                                                               'runs '
                                                                               'a '
                                                                               'simple '
                                                                               'binary '
                                                                               '(just '
                                                                               'outputting '
                                                                               '"the '
                                                                               'cake '
                                                                               'is '
                                                                               'a '
                                                                               'lie"), '
                                                                               'that '
                                                                               'was '
                                                                               'packed '
                                                                               'by '
                                                                               'UPX.\n'
                                                                               '\n'
                                                                               'The '
                                                                               'UPX '
                                                                               'magic '
                                                                               'number '
                                                                               '(`0x55505821`, '
                                                                               '"`UPX!`") '
                                                                               'was '
                                                                               'changed '
                                                                               'to '
                                                                               '(`0x4c4f5452`, '
                                                                               '"`LOTR`"). '
                                                                               'This '
                                                                               'prevents '
                                                                               'the '
                                                                               'binary '
                                                                               'from '
                                                                               'being '
                                                                               'detected\n'
                                                                               'by '
                                                                               'some '
                                                                               'methods, '
                                                                               'and '
                                                                               'especially '
                                                                               'UPX '
                                                                               'is '
                                                                               'not '
                                                                               'able '
                                                                               'to '
                                                                               'uncompress '
                                                                               'it '
                                                                               'any '
                                                                               'more.\n',
                                                                'executor': {'cleanup_command': 'rm '
                                                                                                '/tmp/packed_bin\n',
                                                                             'command': 'cp '
                                                                                        '#{bin_path} '
                                                                                        '/tmp/packed_bin '
                                                                                        '&& '
                                                                                        '/tmp/packed_bin\n',
                                                                             'elevation_required': False,
                                                                             'name': 'sh'},
                                                                'input_arguments': {'bin_path': {'default': 'PathToAtomicsFolder/T1045/bin/linux/test_upx_header_changed',
                                                                                                 'description': 'Packed '
                                                                                                                'binary',
                                                                                                 'type': 'Path'}},
                                                                'name': 'Binary '
                                                                        'packed '
                                                                        'by '
                                                                        'UPX, '
                                                                        'with '
                                                                        'modified '
                                                                        'headers '
                                                                        '(linux)',
                                                                'supported_platforms': ['linux']},
                                                               {'description': 'Copies '
                                                                               'and '
                                                                               'then '
                                                                               'runs '
                                                                               'a '
                                                                               'simple '
                                                                               'binary '
                                                                               '(just '
                                                                               'outputting '
                                                                               '"the '
                                                                               'cake '
                                                                               'is '
                                                                               'a '
                                                                               'lie"), '
                                                                               'that '
                                                                               'was '
                                                                               'packed '
                                                                               'by '
                                                                               'UPX.\n'
                                                                               'No '
                                                                               'other '
                                                                               'protection/compression '
                                                                               'were '
                                                                               'applied.\n',
                                                                'executor': {'cleanup_command': 'rm '
                                                                                                '/tmp/packed_bin\n',
                                                                             'command': 'cp '
                                                                                        '#{bin_path} '
                                                                                        '/tmp/packed_bin '
                                                                                        '&& '
                                                                                        '/tmp/packed_bin\n',
                                                                             'elevation_required': False,
                                                                             'name': 'sh'},
                                                                'input_arguments': {'bin_path': {'default': 'PathToAtomicsFolder/T1045/bin/darwin/test_upx',
                                                                                                 'description': 'Packed '
                                                                                                                'binary',
                                                                                                 'type': 'Path'}},
                                                                'name': 'Binary '
                                                                        'simply '
                                                                        'packed '
                                                                        'by '
                                                                        'UPX',
                                                                'supported_platforms': ['macos']},
                                                               {'description': 'Copies '
                                                                               'and '
                                                                               'then '
                                                                               'runs '
                                                                               'a '
                                                                               'simple '
                                                                               'binary '
                                                                               '(just '
                                                                               'outputting '
                                                                               '"the '
                                                                               'cake '
                                                                               'is '
                                                                               'a '
                                                                               'lie"), '
                                                                               'that '
                                                                               'was '
                                                                               'packed '
                                                                               'by '
                                                                               'UPX.\n'
                                                                               '\n'
                                                                               'The '
                                                                               'UPX '
                                                                               'magic '
                                                                               'number '
                                                                               '(`0x55505821`, '
                                                                               '"`UPX!`") '
                                                                               'was '
                                                                               'changed '
                                                                               'to '
                                                                               '(`0x4c4f5452`, '
                                                                               '"`LOTR`"). '
                                                                               'This '
                                                                               'prevents '
                                                                               'the '
                                                                               'binary '
                                                                               'from '
                                                                               'being '
                                                                               'detected\n'
                                                                               'by '
                                                                               'some '
                                                                               'methods, '
                                                                               'and '
                                                                               'especially '
                                                                               'UPX '
                                                                               'is '
                                                                               'not '
                                                                               'able '
                                                                               'to '
                                                                               'uncompress '
                                                                               'it '
                                                                               'any '
                                                                               'more.\n',
                                                                'executor': {'cleanup_command': 'rm '
                                                                                                '/tmp/packed_bin\n',
                                                                             'command': 'cp '
                                                                                        '#{bin_path} '
                                                                                        '/tmp/packed_bin '
                                                                                        '&& '
                                                                                        '/tmp/packed_bin\n',
                                                                             'elevation_required': False,
                                                                             'name': 'sh'},
                                                                'input_arguments': {'bin_path': {'default': 'PathToAtomicsFolder/T1045/bin/darwin/test_upx_header_changed',
                                                                                                 'description': 'Packed '
                                                                                                                'binary',
                                                                                                 'type': 'Path'}},
                                                                'name': 'Binary '
                                                                        'packed '
                                                                        'by '
                                                                        'UPX, '
                                                                        'with '
                                                                        'modified '
                                                                        'headers',
                                                                'supported_platforms': ['macos']}],
                                              'attack_technique': 'T1045',
                                              'display_name': 'Software '
                                                              'Packing'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [Elderwood](../actors/Elderwood.md)

* [APT29](../actors/APT29.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [APT3](../actors/APT3.md)
    
* [APT38](../actors/APT38.md)
    
* [Dark Caracal](../actors/Dark-Caracal.md)
    
* [Group5](../actors/Group5.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [APT39](../actors/APT39.md)
    
* [The White Company](../actors/The-White-Company.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
