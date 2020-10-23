
# Rootkit

## Description

### MITRE Description

> Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating system API calls that supply system information. (Citation: Symantec Windows Rootkits) 

Rootkits or rootkit enabling functionality may reside at the user or kernel level in the operating system or lower, to include a hypervisor, Master Boot Record, or [System Firmware](https://attack.mitre.org/techniques/T1542/001). (Citation: Wikipedia Rootkit) Rootkits have been seen for Windows, Linux, and Mac OS X systems. (Citation: CrowdStrike Linux Rootkit) (Citation: BlackHat Mac OSX Rootkit)

## Aliases

```

```

## Additional Attributes

* Bypass: ['File monitoring', 'Host intrusion prevention systems', 'Application control', 'Signature-based detection', 'System access controls', 'Application control by file name or path', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM', 'root']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1014

## Potential Commands

```
puppetstrings C:\Drivers\driver.sys
sudo insmod PathToAtomicsFolder/T1014/bin/T1014.ko
sudo modprobe T1014
sudo insmod #{rootkit_path}
sudo modprobe #{rootkit_name}
```

## Commands Dataset

```
[{'command': 'sudo insmod #{rootkit_path}\n',
  'name': None,
  'source': 'atomics/T1014/T1014.yaml'},
 {'command': 'sudo insmod PathToAtomicsFolder/T1014/bin/T1014.ko\n',
  'name': None,
  'source': 'atomics/T1014/T1014.yaml'},
 {'command': 'sudo insmod #{rootkit_path}\n',
  'name': None,
  'source': 'atomics/T1014/T1014.yaml'},
 {'command': 'sudo insmod #{rootkit_path}\n',
  'name': None,
  'source': 'atomics/T1014/T1014.yaml'},
 {'command': 'sudo modprobe #{rootkit_name}\n',
  'name': None,
  'source': 'atomics/T1014/T1014.yaml'},
 {'command': 'sudo modprobe #{rootkit_name}\n',
  'name': None,
  'source': 'atomics/T1014/T1014.yaml'},
 {'command': 'sudo modprobe T1014\n',
  'name': None,
  'source': 'atomics/T1014/T1014.yaml'},
 {'command': 'sudo modprobe #{rootkit_name}\n',
  'name': None,
  'source': 'atomics/T1014/T1014.yaml'},
 {'command': 'puppetstrings C:\\Drivers\\driver.sys\n',
  'name': None,
  'source': 'atomics/T1014/T1014.yaml'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['LOG-MD', 'AutoRuns']},
 {'data_source': ['LOG-MD', 'Windows Registry', 'Compare']},
 {'data_source': ['LOG-MD', 'File Hash', 'Compare']},
 {'data_source': ['BIOS']},
 {'data_source': ['MBR']},
 {'data_source': ['System calls']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['LOG-MD', 'AutoRuns']},
 {'data_source': ['LOG-MD', 'Windows Registry', 'Compare']},
 {'data_source': ['LOG-MD', 'File Hash', 'Compare']},
 {'data_source': ['BIOS']},
 {'data_source': ['MBR']},
 {'data_source': ['System calls']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Rootkit': {'atomic_tests': [{'auto_generated_guid': 'dfb50072-e45a-4c75-a17e-a484809c8553',
                                                       'dependencies': [{'description': 'The '
                                                                                        'kernel '
                                                                                        'module '
                                                                                        'must '
                                                                                        'exist '
                                                                                        'on '
                                                                                        'disk '
                                                                                        'at '
                                                                                        'specified '
                                                                                        'location '
                                                                                        '(#{rootkit_path})\n',
                                                                         'get_prereq_command': 'if '
                                                                                               '[ '
                                                                                               '! '
                                                                                               '-d '
                                                                                               '#{temp_folder} '
                                                                                               ']; '
                                                                                               'then '
                                                                                               'mkdir '
                                                                                               '#{temp_folder}; '
                                                                                               'touch '
                                                                                               '#{temp_folder}/safe_to_delete; '
                                                                                               'fi;\n'
                                                                                               'cp '
                                                                                               '#{rootkit_source_path}/* '
                                                                                               '#{temp_folder}/\n'
                                                                                               'cd '
                                                                                               '#{temp_folder}; '
                                                                                               'make\n'
                                                                                               'mv '
                                                                                               '#{temp_folder}/#{rootkit_name}.ko '
                                                                                               '#{rootkit_path}\n'
                                                                                               '[ '
                                                                                               '-f '
                                                                                               '#{temp_folder}/safe_to_delete '
                                                                                               '] '
                                                                                               '&& '
                                                                                               'rm '
                                                                                               '-rf '
                                                                                               '#{temp_folder}\n',
                                                                         'prereq_command': 'if '
                                                                                           '[ '
                                                                                           '-f '
                                                                                           '#{rootkit_path} '
                                                                                           ']; '
                                                                                           'then '
                                                                                           'exit '
                                                                                           '0; '
                                                                                           'else '
                                                                                           'exit '
                                                                                           '1; '
                                                                                           'fi;\n'}],
                                                       'dependency_executor_name': 'bash',
                                                       'description': 'Loadable '
                                                                      'Kernel '
                                                                      'Module '
                                                                      'based '
                                                                      'Rootkit\n',
                                                       'executor': {'cleanup_command': 'sudo '
                                                                                       'rmmod '
                                                                                       '#{rootkit_name}\n',
                                                                    'command': 'sudo '
                                                                               'insmod '
                                                                               '#{rootkit_path}\n',
                                                                    'elevation_required': True,
                                                                    'name': 'sh'},
                                                       'input_arguments': {'rootkit_name': {'default': 'T1014',
                                                                                            'description': 'Module '
                                                                                                           'name',
                                                                                            'type': 'String'},
                                                                           'rootkit_path': {'default': 'PathToAtomicsFolder/T1014/bin/T1014.ko',
                                                                                            'description': 'Path '
                                                                                                           'To '
                                                                                                           'rootkit',
                                                                                            'type': 'String'},
                                                                           'rootkit_source_path': {'default': 'PathToAtomicsFolder/T1014/src/Linux',
                                                                                                   'description': 'Path '
                                                                                                                  'to '
                                                                                                                  'the '
                                                                                                                  'rootkit '
                                                                                                                  'source. '
                                                                                                                  'Used '
                                                                                                                  'when '
                                                                                                                  'prerequistes '
                                                                                                                  'are '
                                                                                                                  'fetched.',
                                                                                                   'type': 'path'},
                                                                           'temp_folder': {'default': '/tmp/T1014',
                                                                                           'description': 'Temp '
                                                                                                          'folder '
                                                                                                          'used '
                                                                                                          'to '
                                                                                                          'compile '
                                                                                                          'the '
                                                                                                          'code. '
                                                                                                          'Used '
                                                                                                          'when '
                                                                                                          'prerequistes '
                                                                                                          'are '
                                                                                                          'fetched.',
                                                                                           'type': 'path'}},
                                                       'name': 'Loadable '
                                                               'Kernel Module '
                                                               'based Rootkit',
                                                       'supported_platforms': ['linux']},
                                                      {'auto_generated_guid': '75483ef8-f10f-444a-bf02-62eb0e48db6f',
                                                       'dependencies': [{'description': 'The '
                                                                                        'kernel '
                                                                                        'module '
                                                                                        'must '
                                                                                        'exist '
                                                                                        'on '
                                                                                        'disk '
                                                                                        'at '
                                                                                        'specified '
                                                                                        'location '
                                                                                        '(#{rootkit_path})\n',
                                                                         'get_prereq_command': 'if '
                                                                                               '[ '
                                                                                               '! '
                                                                                               '-d '
                                                                                               '#{temp_folder} '
                                                                                               ']; '
                                                                                               'then '
                                                                                               'mkdir '
                                                                                               '#{temp_folder}; '
                                                                                               'touch '
                                                                                               '#{temp_folder}/safe_to_delete; '
                                                                                               'fi;\n'
                                                                                               'cp '
                                                                                               '#{rootkit_source_path}/* '
                                                                                               '#{temp_folder}/\n'
                                                                                               'cd '
                                                                                               '#{temp_folder}; '
                                                                                               'make        \n'
                                                                                               'sudo '
                                                                                               'cp '
                                                                                               '#{temp_folder}/#{rootkit_name}.ko '
                                                                                               '/lib/modules/$(uname '
                                                                                               '-r)/\n'
                                                                                               '[ '
                                                                                               '-f '
                                                                                               '#{temp_folder}/safe_to_delete '
                                                                                               '] '
                                                                                               '&& '
                                                                                               'rm '
                                                                                               '-rf '
                                                                                               '#{temp_folder}\n'
                                                                                               'sudo '
                                                                                               'depmod '
                                                                                               '-a\n',
                                                                         'prereq_command': 'if '
                                                                                           '[ '
                                                                                           '-f '
                                                                                           '/lib/modules/$(uname '
                                                                                           '-r)/#{rootkit_name}.ko '
                                                                                           ']; '
                                                                                           'then '
                                                                                           'exit '
                                                                                           '0; '
                                                                                           'else '
                                                                                           'exit '
                                                                                           '1; '
                                                                                           'fi;\n'}],
                                                       'dependency_executor_name': 'bash',
                                                       'description': 'Loadable '
                                                                      'Kernel '
                                                                      'Module '
                                                                      'based '
                                                                      'Rootkit\n',
                                                       'executor': {'cleanup_command': 'sudo '
                                                                                       'modprobe '
                                                                                       '-r '
                                                                                       '#{rootkit_name}\n'
                                                                                       'sudo '
                                                                                       'rm '
                                                                                       '/lib/modules/$(uname '
                                                                                       '-r)/#{rootkit_name}.ko\n'
                                                                                       'sudo '
                                                                                       'depmod '
                                                                                       '-a\n',
                                                                    'command': 'sudo '
                                                                               'modprobe '
                                                                               '#{rootkit_name}\n',
                                                                    'elevation_required': True,
                                                                    'name': 'sh'},
                                                       'input_arguments': {'rootkit_name': {'default': 'T1014',
                                                                                            'description': 'Module '
                                                                                                           'name',
                                                                                            'type': 'String'},
                                                                           'rootkit_path': {'default': 'PathToAtomicsFolder/T1014/bin/T1014.ko',
                                                                                            'description': 'Path '
                                                                                                           'To '
                                                                                                           'rootkit',
                                                                                            'type': 'String'},
                                                                           'rootkit_source_path': {'default': 'PathToAtomicsFolder/T1014/src/Linux',
                                                                                                   'description': 'Path '
                                                                                                                  'to '
                                                                                                                  'the '
                                                                                                                  'rootkit '
                                                                                                                  'source. '
                                                                                                                  'Used '
                                                                                                                  'when '
                                                                                                                  'prerequistes '
                                                                                                                  'are '
                                                                                                                  'fetched.',
                                                                                                   'type': 'path'},
                                                                           'temp_folder': {'default': '/tmp/T1014',
                                                                                           'description': 'Temp '
                                                                                                          'folder '
                                                                                                          'used '
                                                                                                          'to '
                                                                                                          'compile '
                                                                                                          'the '
                                                                                                          'code. '
                                                                                                          'Used '
                                                                                                          'when '
                                                                                                          'prerequistes '
                                                                                                          'are '
                                                                                                          'fetched.',
                                                                                           'type': 'path'}},
                                                       'name': 'Loadable '
                                                               'Kernel Module '
                                                               'based Rootkit',
                                                       'supported_platforms': ['linux']},
                                                      {'auto_generated_guid': '8e4e1985-9a19-4529-b4b8-b7a49ff87fae',
                                                       'description': 'This '
                                                                      'test '
                                                                      'exploits '
                                                                      'a '
                                                                      'signed '
                                                                      'driver '
                                                                      'to '
                                                                      'execute '
                                                                      'code in '
                                                                      'Kernel.\n'
                                                                      'SHA1 '
                                                                      'C1D5CF8C43E7679B782630E93F5E6420CA1749A7\n'
                                                                      'We '
                                                                      'leverage '
                                                                      'the '
                                                                      'work '
                                                                      'done '
                                                                      'here:\n'
                                                                      'https://zerosum0x0.blogspot.com/2017/07/puppet-strings-dirty-secret-for-free.html\n'
                                                                      'The '
                                                                      'hash of '
                                                                      'our PoC '
                                                                      'Exploit '
                                                                      'is\n'
                                                                      'SHA1 '
                                                                      'DD8DA630C00953B6D5182AA66AF999B1E117F441\n'
                                                                      'This '
                                                                      'will '
                                                                      'simulate '
                                                                      'hiding '
                                                                      'a '
                                                                      'process.\n'
                                                                      'It '
                                                                      'would '
                                                                      'be wise '
                                                                      'if you '
                                                                      'only '
                                                                      'run '
                                                                      'this in '
                                                                      'a test '
                                                                      'environment\n',
                                                       'executor': {'command': 'puppetstrings '
                                                                               '#{driver_path}\n',
                                                                    'name': 'command_prompt'},
                                                       'input_arguments': {'driver_path': {'default': 'C:\\Drivers\\driver.sys',
                                                                                           'description': 'Path '
                                                                                                          'to '
                                                                                                          'the '
                                                                                                          'vulnerable '
                                                                                                          'driver',
                                                                                           'type': 'Path'}},
                                                       'name': 'Windows Signed '
                                                               'Driver Rootkit '
                                                               'Test',
                                                       'supported_platforms': ['windows']}],
                                     'attack_technique': 'T1014',
                                     'display_name': 'Rootkit'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Rootkit Mitigation](../mitigations/Rootkit-Mitigation.md)


# Actors


* [Winnti Group](../actors/Winnti-Group.md)

* [APT28](../actors/APT28.md)
    
* [APT41](../actors/APT41.md)
    
* [Rocke](../actors/Rocke.md)
    
