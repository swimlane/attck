
# Software Packing

## Description

### MITRE Description

> Adversaries may perform software packing or virtual machine software protection to conceal their code. Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory. Virtual machine software protection translates an executable's original code into a special format that only a special virtual machine can run. A virtual machine is then called to run this code.(Citation: ESET FinFisher Jan 2018) 

Utilities used to perform software packing are called packers. Example packers are MPRESS and UPX. A more comprehensive list of known packers is available, (Citation: Wikipedia Exe Compression) but adversaries may create their own packing techniques that do not leave the same artifacts as well-known packers to evade defenses.  

## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti-virus', 'Heuristic detection', 'Signature-based detection']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1027/002

## Potential Commands

```
cp PathToAtomicsFolder/T1027.002/bin/darwin/test_upx_header_changed /tmp/packed_bin && /tmp/packed_bin
cp PathToAtomicsFolder/T1027.002/bin/darwin/test_upx /tmp/packed_bin && /tmp/packed_bin
cp PathToAtomicsFolder/T1027.002/bin/linux/test_upx_header_changed /tmp/packed_bin && /tmp/packed_bin
cp PathToAtomicsFolder/T1027.002/bin/linux/test_upx /tmp/packed_bin && /tmp/packed_bin
```

## Commands Dataset

```
[{'command': 'cp PathToAtomicsFolder/T1027.002/bin/linux/test_upx '
             '/tmp/packed_bin && /tmp/packed_bin\n',
  'name': None,
  'source': 'atomics/T1027.002/T1027.002.yaml'},
 {'command': 'cp '
             'PathToAtomicsFolder/T1027.002/bin/linux/test_upx_header_changed '
             '/tmp/packed_bin && /tmp/packed_bin\n',
  'name': None,
  'source': 'atomics/T1027.002/T1027.002.yaml'},
 {'command': 'cp PathToAtomicsFolder/T1027.002/bin/darwin/test_upx '
             '/tmp/packed_bin && /tmp/packed_bin\n',
  'name': None,
  'source': 'atomics/T1027.002/T1027.002.yaml'},
 {'command': 'cp '
             'PathToAtomicsFolder/T1027.002/bin/darwin/test_upx_header_changed '
             '/tmp/packed_bin && /tmp/packed_bin\n',
  'name': None,
  'source': 'atomics/T1027.002/T1027.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Obfuscated Files or Information: Software Packing': {'atomic_tests': [{'auto_generated_guid': '11c46cd8-e471-450e-acb8-52a1216ae6a4',
                                                                                                 'description': 'Copies '
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
                                                                                                              'name': 'sh'},
                                                                                                 'input_arguments': {'bin_path': {'default': 'PathToAtomicsFolder/T1027.002/bin/linux/test_upx',
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
                                                                                                {'auto_generated_guid': 'f06197f8-ff46-48c2-a0c6-afc1b50665e1',
                                                                                                 'description': 'Copies '
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
                                                                                                              'name': 'sh'},
                                                                                                 'input_arguments': {'bin_path': {'default': 'PathToAtomicsFolder/T1027.002/bin/linux/test_upx_header_changed',
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
                                                                                                {'auto_generated_guid': 'b16ef901-00bb-4dda-b4fc-a04db5067e20',
                                                                                                 'description': 'Copies '
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
                                                                                                              'name': 'sh'},
                                                                                                 'input_arguments': {'bin_path': {'default': 'PathToAtomicsFolder/T1027.002/bin/darwin/test_upx',
                                                                                                                                  'description': 'Packed '
                                                                                                                                                 'binary',
                                                                                                                                  'type': 'Path'}},
                                                                                                 'name': 'Binary '
                                                                                                         'simply '
                                                                                                         'packed '
                                                                                                         'by '
                                                                                                         'UPX',
                                                                                                 'supported_platforms': ['macos']},
                                                                                                {'auto_generated_guid': '4d46e16b-5765-4046-9f25-a600d3e65e4d',
                                                                                                 'description': 'Copies '
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
                                                                                                              'name': 'sh'},
                                                                                                 'input_arguments': {'bin_path': {'default': 'PathToAtomicsFolder/T1027.002/bin/darwin/test_upx_header_changed',
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
                                                                               'attack_technique': 'T1027.002',
                                                                               'display_name': 'Obfuscated '
                                                                                               'Files '
                                                                                               'or '
                                                                                               'Information: '
                                                                                               'Software '
                                                                                               'Packing'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Antivirus/Antimalware](../mitigations/Antivirus-Antimalware.md)


# Actors


* [Elderwood](../actors/Elderwood.md)

* [APT29](../actors/APT29.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [APT3](../actors/APT3.md)
    
* [APT38](../actors/APT38.md)
    
* [Dark Caracal](../actors/Dark-Caracal.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [APT39](../actors/APT39.md)
    
* [The White Company](../actors/The-White-Company.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [Rocke](../actors/Rocke.md)
    
* [TA505](../actors/TA505.md)
    
