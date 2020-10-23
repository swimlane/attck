
# Windows Command Shell

## Description

### MITRE Description

> Adversaries may abuse the Windows command shell for execution. The Windows command shell (<code>cmd.exe</code>) is the primary command prompt on Windows systems. The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands. 

Batch files (ex: .bat or .cmd) also provide the shell with a list of sequential commands to run, as well as normal scripting operations such as conditionals and loops. Common uses of batch files include long or repetitive tasks, or the need to run the same set of commands on multiple systems.

Adversaries may leverage <code>cmd.exe</code> to execute various commands and payloads. Common uses include <code>cmd.exe /c</code> to execute a single command, or abusing <code>cmd.exe</code> interactively with input and output forwarded over a command and control channel.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1059/003

## Potential Commands

```
Start-Process $env:TEMP\T1059.003_script.bat
Start-Process #{script_path}
```

## Commands Dataset

```
[{'command': 'Start-Process #{script_path}\n',
  'name': None,
  'source': 'atomics/T1059.003/T1059.003.yaml'},
 {'command': 'Start-Process $env:TEMP\\T1059.003_script.bat\n',
  'name': None,
  'source': 'atomics/T1059.003/T1059.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Command and Scripting Interpreter: Windows Command Shell': {'atomic_tests': [{'auto_generated_guid': '9e8894c0-50bd-4525-a96c-d4ac78ece388',
                                                                                                        'dependencies': [{'description': 'Batch '
                                                                                                                                         'file '
                                                                                                                                         'must '
                                                                                                                                         'exist '
                                                                                                                                         'on '
                                                                                                                                         'disk '
                                                                                                                                         'at '
                                                                                                                                         'specified '
                                                                                                                                         'location '
                                                                                                                                         '(#{script_path})\n',
                                                                                                                          'get_prereq_command': 'New-Item '
                                                                                                                                                '#{script_path} '
                                                                                                                                                '-Force '
                                                                                                                                                '| '
                                                                                                                                                'Out-Null\n'
                                                                                                                                                'Set-Content '
                                                                                                                                                '-Path '
                                                                                                                                                '#{script_path} '
                                                                                                                                                '-Value '
                                                                                                                                                '"#{command_to_execute}"\n',
                                                                                                                          'prereq_command': 'if '
                                                                                                                                            '(Test-Path '
                                                                                                                                            '#{script_path}) '
                                                                                                                                            '{exit '
                                                                                                                                            '0} '
                                                                                                                                            'else '
                                                                                                                                            '{exit '
                                                                                                                                            '1}\n'}],
                                                                                                        'dependency_executor_name': 'powershell',
                                                                                                        'description': 'Creates '
                                                                                                                       'and '
                                                                                                                       'executes '
                                                                                                                       'a '
                                                                                                                       'simple '
                                                                                                                       'batch '
                                                                                                                       'script. '
                                                                                                                       'Upon '
                                                                                                                       'execution, '
                                                                                                                       'CMD '
                                                                                                                       'will '
                                                                                                                       'briefly '
                                                                                                                       'launh '
                                                                                                                       'to '
                                                                                                                       'run '
                                                                                                                       'the '
                                                                                                                       'batch '
                                                                                                                       'script '
                                                                                                                       'then '
                                                                                                                       'close '
                                                                                                                       'again.\n',
                                                                                                        'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                                        '#{script_path} '
                                                                                                                                        '-Force '
                                                                                                                                        '-ErrorAction '
                                                                                                                                        'Ignore\n',
                                                                                                                     'command': 'Start-Process '
                                                                                                                                '#{script_path}\n',
                                                                                                                     'name': 'powershell'},
                                                                                                        'input_arguments': {'command_to_execute': {'default': 'dir',
                                                                                                                                                   'description': 'Command '
                                                                                                                                                                  'to '
                                                                                                                                                                  'execute '
                                                                                                                                                                  'within '
                                                                                                                                                                  'script.',
                                                                                                                                                   'type': 'string'},
                                                                                                                            'script_path': {'default': '$env:TEMP\\T1059.003_script.bat',
                                                                                                                                            'description': 'Script '
                                                                                                                                                           'path.',
                                                                                                                                            'type': 'path'}},
                                                                                                        'name': 'Create '
                                                                                                                'and '
                                                                                                                'Execute '
                                                                                                                'Batch '
                                                                                                                'Script',
                                                                                                        'supported_platforms': ['windows']}],
                                                                                      'attack_technique': 'T1059.003',
                                                                                      'display_name': 'Command '
                                                                                                      'and '
                                                                                                      'Scripting '
                                                                                                      'Interpreter: '
                                                                                                      'Windows '
                                                                                                      'Command '
                                                                                                      'Shell'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)


# Actors


* [Dark Caracal](../actors/Dark-Caracal.md)

* [Leviathan](../actors/Leviathan.md)
    
* [APT37](../actors/APT37.md)
    
* [APT1](../actors/APT1.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [FIN10](../actors/FIN10.md)
    
* [admin@338](../actors/admin@338.md)
    
* [APT3](../actors/APT3.md)
    
* [menuPass](../actors/menuPass.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Threat Group-1314](../actors/Threat-Group-1314.md)
    
* [Sowbug](../actors/Sowbug.md)
    
* [Rancor](../actors/Rancor.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Suckfly](../actors/Suckfly.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [APT38](../actors/APT38.md)
    
* [APT28](../actors/APT28.md)
    
* [APT18](../actors/APT18.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [APT39](../actors/APT39.md)
    
* [APT32](../actors/APT32.md)
    
* [Silence](../actors/Silence.md)
    
* [Turla](../actors/Turla.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
* [FIN7](../actors/FIN7.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
* [TA505](../actors/TA505.md)
    
