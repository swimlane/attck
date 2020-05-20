
# System Shutdown/Reboot

## Description

### MITRE Description

> Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine. In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer.(Citation: Microsoft Shutdown Oct 2017) Shutting down or rebooting systems may disrupt access to computer resources for legitimate users.

Adversaries may attempt to shutdown/reboot a system after impacting it in other ways, such as [Disk Structure Wipe](https://attack.mitre.org/techniques/T1487) or [Inhibit System Recovery](https://attack.mitre.org/techniques/T1490), to hasten the intended effects on system availability.(Citation: Talos Nyetya June 2017)(Citation: Talos Olympic Destroyer 2018)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'root', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1529

## Potential Commands

```
None
None
shutdown -r now

shutdown -h now

reboot

halt -p

halt --reboot

poweroff

poweroff --reboot

```

## Commands Dataset

```
[{'command': None, 'name': None, 'source': 'atomics/T1529/T1529.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1529/T1529.yaml'},
 {'command': 'shutdown -r now\n',
  'name': None,
  'source': 'atomics/T1529/T1529.yaml'},
 {'command': 'shutdown -h now\n',
  'name': None,
  'source': 'atomics/T1529/T1529.yaml'},
 {'command': 'reboot\n', 'name': None, 'source': 'atomics/T1529/T1529.yaml'},
 {'command': 'halt -p\n', 'name': None, 'source': 'atomics/T1529/T1529.yaml'},
 {'command': 'halt --reboot\n',
  'name': None,
  'source': 'atomics/T1529/T1529.yaml'},
 {'command': 'poweroff\n', 'name': None, 'source': 'atomics/T1529/T1529.yaml'},
 {'command': 'poweroff --reboot\n',
  'name': None,
  'source': 'atomics/T1529/T1529.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - System Shutdown/Reboot': {'atomic_tests': [{'auto_generated_guid': 'ad254fa8-45c0-403b-8c77-e00b3d3e7a64',
                                                                      'description': 'This '
                                                                                     'test '
                                                                                     'shuts '
                                                                                     'down '
                                                                                     'a '
                                                                                     'Windows '
                                                                                     'system.\n',
                                                                      'executor': {'command': 'shutdown '
                                                                                              '/s '
                                                                                              '/t '
                                                                                              '#{timeout}\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'command_prompt'},
                                                                      'input_arguments': {'timeout': {'default': 1,
                                                                                                      'description': 'Timeout '
                                                                                                                     'period '
                                                                                                                     'before '
                                                                                                                     'shutdown '
                                                                                                                     '(seconds)',
                                                                                                      'type': 'string'}},
                                                                      'name': 'Shutdown '
                                                                              'System '
                                                                              '- '
                                                                              'Windows',
                                                                      'supported_platforms': ['windows']},
                                                                     {'auto_generated_guid': 'f4648f0d-bf78-483c-bafc-3ec99cd1c302',
                                                                      'description': 'This '
                                                                                     'test '
                                                                                     'restarts '
                                                                                     'a '
                                                                                     'Windows '
                                                                                     'system.\n',
                                                                      'executor': {'command': 'shutdown '
                                                                                              '/r '
                                                                                              '/t '
                                                                                              '#{timeout}\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'command_prompt'},
                                                                      'input_arguments': {'timeout': {'default': 1,
                                                                                                      'description': 'Timeout '
                                                                                                                     'period '
                                                                                                                     'before '
                                                                                                                     'restart '
                                                                                                                     '(seconds)',
                                                                                                      'type': 'string'}},
                                                                      'name': 'Restart '
                                                                              'System '
                                                                              '- '
                                                                              'Windows',
                                                                      'supported_platforms': ['windows']},
                                                                     {'auto_generated_guid': '6326dbc4-444b-4c04-88f4-27e94d0327cb',
                                                                      'description': 'This '
                                                                                     'test '
                                                                                     'restarts '
                                                                                     'a '
                                                                                     'macOS/Linux '
                                                                                     'system.\n',
                                                                      'executor': {'command': 'shutdown '
                                                                                              '-r '
                                                                                              '#{timeout}\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'bash'},
                                                                      'input_arguments': {'timeout': {'default': 'now',
                                                                                                      'description': 'Time '
                                                                                                                     'to '
                                                                                                                     'restart '
                                                                                                                     '(can '
                                                                                                                     'be '
                                                                                                                     'minutes '
                                                                                                                     'or '
                                                                                                                     'specific '
                                                                                                                     'time)',
                                                                                                      'type': 'string'}},
                                                                      'name': 'Restart '
                                                                              'System '
                                                                              'via '
                                                                              '`shutdown` '
                                                                              '- '
                                                                              'macOS/Linux',
                                                                      'supported_platforms': ['macos',
                                                                                              'linux']},
                                                                     {'auto_generated_guid': '4963a81e-a3ad-4f02-adda-812343b351de',
                                                                      'description': 'This '
                                                                                     'test '
                                                                                     'shuts '
                                                                                     'down '
                                                                                     'a '
                                                                                     'macOS/Linux '
                                                                                     'system '
                                                                                     'using '
                                                                                     'a '
                                                                                     'halt.\n',
                                                                      'executor': {'command': 'shutdown '
                                                                                              '-h '
                                                                                              '#{timeout}\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'bash'},
                                                                      'input_arguments': {'timeout': {'default': 'now',
                                                                                                      'description': 'Time '
                                                                                                                     'to '
                                                                                                                     'shutdown '
                                                                                                                     '(can '
                                                                                                                     'be '
                                                                                                                     'minutes '
                                                                                                                     'or '
                                                                                                                     'specific '
                                                                                                                     'time)',
                                                                                                      'type': 'string'}},
                                                                      'name': 'Shutdown '
                                                                              'System '
                                                                              'via '
                                                                              '`shutdown` '
                                                                              '- '
                                                                              'macOS/Linux',
                                                                      'supported_platforms': ['macos',
                                                                                              'linux']},
                                                                     {'auto_generated_guid': '47d0b042-a918-40ab-8cf9-150ffe919027',
                                                                      'description': 'This '
                                                                                     'test '
                                                                                     'restarts '
                                                                                     'a '
                                                                                     'macOS/Linux '
                                                                                     'system '
                                                                                     'via '
                                                                                     '`reboot`.\n',
                                                                      'executor': {'command': 'reboot\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'bash'},
                                                                      'name': 'Restart '
                                                                              'System '
                                                                              'via '
                                                                              '`reboot` '
                                                                              '- '
                                                                              'macOS/Linux',
                                                                      'supported_platforms': ['macos',
                                                                                              'linux']},
                                                                     {'auto_generated_guid': '918f70ab-e1ef-49ff-bc57-b27021df84dd',
                                                                      'description': 'This '
                                                                                     'test '
                                                                                     'shuts '
                                                                                     'down '
                                                                                     'a '
                                                                                     'Linux '
                                                                                     'system '
                                                                                     'using '
                                                                                     '`halt`.\n',
                                                                      'executor': {'command': 'halt '
                                                                                              '-p\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'bash'},
                                                                      'name': 'Shutdown '
                                                                              'System '
                                                                              'via '
                                                                              '`halt` '
                                                                              '- '
                                                                              'Linux',
                                                                      'supported_platforms': ['linux']},
                                                                     {'auto_generated_guid': '78f92e14-f1e9-4446-b3e9-f1b921f2459e',
                                                                      'description': 'This '
                                                                                     'test '
                                                                                     'restarts '
                                                                                     'a '
                                                                                     'Linux '
                                                                                     'system '
                                                                                     'using '
                                                                                     '`halt`.\n',
                                                                      'executor': {'command': 'halt '
                                                                                              '--reboot\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'bash'},
                                                                      'name': 'Reboot '
                                                                              'System '
                                                                              'via '
                                                                              '`halt` '
                                                                              '- '
                                                                              'Linux',
                                                                      'supported_platforms': ['linux']},
                                                                     {'auto_generated_guid': '73a90cd2-48a2-4ac5-8594-2af35fa909fa',
                                                                      'description': 'This '
                                                                                     'test '
                                                                                     'shuts '
                                                                                     'down '
                                                                                     'a '
                                                                                     'Linux '
                                                                                     'system '
                                                                                     'using '
                                                                                     '`poweroff`.\n',
                                                                      'executor': {'command': 'poweroff\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'bash'},
                                                                      'name': 'Shutdown '
                                                                              'System '
                                                                              'via '
                                                                              '`poweroff` '
                                                                              '- '
                                                                              'Linux',
                                                                      'supported_platforms': ['linux']},
                                                                     {'auto_generated_guid': '61303105-ff60-427b-999e-efb90b314e41',
                                                                      'description': 'This '
                                                                                     'test '
                                                                                     'restarts '
                                                                                     'a '
                                                                                     'Linux '
                                                                                     'system '
                                                                                     'using '
                                                                                     '`poweroff`.\n',
                                                                      'executor': {'command': 'poweroff '
                                                                                              '--reboot\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'bash'},
                                                                      'name': 'Reboot '
                                                                              'System '
                                                                              'via '
                                                                              '`poweroff` '
                                                                              '- '
                                                                              'Linux',
                                                                      'supported_platforms': ['linux']}],
                                                    'attack_technique': 'T1529',
                                                    'display_name': 'System '
                                                                    'Shutdown/Reboot'}}]
```

# Tactics


* [Impact](../tactics/Impact.md)


# Mitigations

None

# Actors


* [APT37](../actors/APT37.md)

* [APT38](../actors/APT38.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
