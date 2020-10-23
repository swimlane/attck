
# Kernel Modules and Extensions

## Description

### MITRE Description

> Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. For example, one type of module is the device driver, which allows the kernel to access hardware connected to the system. (Citation: Linux Kernel Programming) 

When used maliciously, LKMs can be a type of kernel-mode [Rootkit](https://attack.mitre.org/techniques/T1014) that run with the highest operating system privilege (Ring 0). (Citation: Linux Kernel Module Programming Guide) Common features of LKM based rootkits include: hiding itself, selective hiding of files, processes and network activity, as well as log tampering, providing authenticated backdoors and enabling root access to non-privileged users. (Citation: iDefense Rootkit Overview)

Kernel extensions, also called kext, are used for macOS to load functionality onto a system similar to LKMs for Linux. They are loaded and unloaded through <code>kextload</code> and <code>kextunload</code> commands.

Adversaries can use LKMs and kexts to covertly persist on a system and elevate privileges. Examples have been found in the wild and there are some open source projects. (Citation: Volatility Phalanx2) (Citation: CrowdStrike Linux Rootkit) (Citation: GitHub Reptile) (Citation: GitHub Diamorphine)(Citation: RSAC 2015 San Francisco Patrick Wardle) (Citation: Synack Secure Kernel Extension Broken)(Citation: Securelist Ventir) (Citation: Trend Micro Skidmap)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['root']
* Platforms: ['macOS', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1547/006

## Potential Commands

```
sudo insmod #{module_path}
sudo insmod /tmp/T1547.006/T1547006.ko
```

## Commands Dataset

```
[{'command': 'sudo insmod #{module_path}\n',
  'name': None,
  'source': 'atomics/T1547.006/T1547.006.yaml'},
 {'command': 'sudo insmod /tmp/T1547.006/T1547006.ko\n',
  'name': None,
  'source': 'atomics/T1547.006/T1547.006.yaml'},
 {'command': 'sudo insmod #{module_path}\n',
  'name': None,
  'source': 'atomics/T1547.006/T1547.006.yaml'},
 {'command': 'sudo insmod #{module_path}\n',
  'name': None,
  'source': 'atomics/T1547.006/T1547.006.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Boot or Logon Autostart Execution: Kernel Modules and Extensions': {'atomic_tests': [{'auto_generated_guid': '687dcb93-9656-4853-9c36-9977315e9d23',
                                                                                                                'dependencies': [{'description': 'The '
                                                                                                                                                 'kernel '
                                                                                                                                                 'module '
                                                                                                                                                 'must '
                                                                                                                                                 'exist '
                                                                                                                                                 'on '
                                                                                                                                                 'disk '
                                                                                                                                                 'at '
                                                                                                                                                 'specified '
                                                                                                                                                 'location\n',
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
                                                                                                                                                        '#{module_source_path}/* '
                                                                                                                                                        '#{temp_folder}/\n'
                                                                                                                                                        'cd '
                                                                                                                                                        '#{temp_folder}; '
                                                                                                                                                        'make\n'
                                                                                                                                                        'if '
                                                                                                                                                        '[ '
                                                                                                                                                        '! '
                                                                                                                                                        '-f '
                                                                                                                                                        '#{module_path} '
                                                                                                                                                        ']; '
                                                                                                                                                        'then '
                                                                                                                                                        'mv '
                                                                                                                                                        '#{temp_folder}/#{module_name}.ko '
                                                                                                                                                        '#{module_path}; '
                                                                                                                                                        'fi;\n',
                                                                                                                                  'prereq_command': 'if '
                                                                                                                                                    '[ '
                                                                                                                                                    '-f '
                                                                                                                                                    '#{module_path} '
                                                                                                                                                    ']; '
                                                                                                                                                    'then '
                                                                                                                                                    'exit '
                                                                                                                                                    '0; '
                                                                                                                                                    'else '
                                                                                                                                                    'exit '
                                                                                                                                                    '1; '
                                                                                                                                                    'fi;\n'}],
                                                                                                                'dependency_executor_name': 'bash',
                                                                                                                'description': 'This '
                                                                                                                               'test '
                                                                                                                               'uses '
                                                                                                                               'the '
                                                                                                                               'insmod '
                                                                                                                               'command '
                                                                                                                               'to '
                                                                                                                               'load '
                                                                                                                               'a '
                                                                                                                               'kernel '
                                                                                                                               'module '
                                                                                                                               'for '
                                                                                                                               'Linux.\n',
                                                                                                                'executor': {'cleanup_command': 'sudo '
                                                                                                                                                'rmmod '
                                                                                                                                                '#{module_name}\n'
                                                                                                                                                '[ '
                                                                                                                                                '-f '
                                                                                                                                                '#{temp_folder}/safe_to_delete '
                                                                                                                                                '] '
                                                                                                                                                '&& '
                                                                                                                                                'rm '
                                                                                                                                                '-rf '
                                                                                                                                                '#{temp_folder}\n',
                                                                                                                             'command': 'sudo '
                                                                                                                                        'insmod '
                                                                                                                                        '#{module_path}\n',
                                                                                                                             'elevation_required': True,
                                                                                                                             'name': 'bash'},
                                                                                                                'input_arguments': {'module_name': {'default': 'T1547006',
                                                                                                                                                    'description': 'Name '
                                                                                                                                                                   'of '
                                                                                                                                                                   'the '
                                                                                                                                                                   'kernel '
                                                                                                                                                                   'module '
                                                                                                                                                                   'name.',
                                                                                                                                                    'type': 'string'},
                                                                                                                                    'module_path': {'default': '/tmp/T1547.006/T1547006.ko',
                                                                                                                                                    'description': 'Folder '
                                                                                                                                                                   'used '
                                                                                                                                                                   'to '
                                                                                                                                                                   'store '
                                                                                                                                                                   'the '
                                                                                                                                                                   'module.',
                                                                                                                                                    'type': 'path'},
                                                                                                                                    'module_source_path': {'default': 'PathToAtomicsFolder/T1547.006/src',
                                                                                                                                                           'description': 'Path '
                                                                                                                                                                          'to '
                                                                                                                                                                          'download '
                                                                                                                                                                          'Gsecdump '
                                                                                                                                                                          'binary '
                                                                                                                                                                          'file',
                                                                                                                                                           'type': 'url'},
                                                                                                                                    'temp_folder': {'default': '/tmp/T1547.006',
                                                                                                                                                    'description': 'Temp '
                                                                                                                                                                   'folder '
                                                                                                                                                                   'used '
                                                                                                                                                                   'to '
                                                                                                                                                                   'compile '
                                                                                                                                                                   'the '
                                                                                                                                                                   'code.',
                                                                                                                                                    'type': 'path'}},
                                                                                                                'name': 'Linux '
                                                                                                                        '- '
                                                                                                                        'Load '
                                                                                                                        'Kernel '
                                                                                                                        'Module '
                                                                                                                        'via '
                                                                                                                        'insmod',
                                                                                                                'supported_platforms': ['linux']}],
                                                                                              'attack_technique': 'T1547.006',
                                                                                              'display_name': 'Boot '
                                                                                                              'or '
                                                                                                              'Logon '
                                                                                                              'Autostart '
                                                                                                              'Execution: '
                                                                                                              'Kernel '
                                                                                                              'Modules '
                                                                                                              'and '
                                                                                                              'Extensions'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)

* [Antivirus/Antimalware](../mitigations/Antivirus-Antimalware.md)
    
* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    

# Actors

None
