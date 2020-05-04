
# Service Stop

## Description

### MITRE Description

> Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment.(Citation: Talos Olympic Destroyer 2018)(Citation: Novetta Blockbuster) 

Adversaries may accomplish this by disabling individual services of high importance to an organization, such as <code>MSExchangeIS</code>, which will make Exchange content inaccessible (Citation: Novetta Blockbuster). In some cases, adversaries may stop or disable many or all services to render systems unusable.(Citation: Talos Olympic Destroyer 2018) Services may not allow for modification of their data stores while running. Adversaries may stop services in order to conduct [Data Destruction](https://attack.mitre.org/techniques/T1485) or [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) on the data stores of services like Exchange and SQL Server.(Citation: SecureWorks WannaCry Analysis)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator', 'SYSTEM', 'User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1489

## Potential Commands

```
sc.exe stop spooler

net.exe stop spooler

taskkill.exe /f /im spoolsv.exe

```

## Commands Dataset

```
[{'command': 'sc.exe stop spooler\n',
  'name': None,
  'source': 'atomics/T1489/T1489.yaml'},
 {'command': 'net.exe stop spooler\n',
  'name': None,
  'source': 'atomics/T1489/T1489.yaml'},
 {'command': 'taskkill.exe /f /im spoolsv.exe\n',
  'name': None,
  'source': 'atomics/T1489/T1489.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Service Stop': {'atomic_tests': [{'description': 'Stops '
                                                                           'a '
                                                                           'specified '
                                                                           'service '
                                                                           'using '
                                                                           'the '
                                                                           'sc.exe '
                                                                           'command. '
                                                                           'Upon '
                                                                           'execution, '
                                                                           'if '
                                                                           'the '
                                                                           'spooler '
                                                                           'service '
                                                                           'was '
                                                                           'running '
                                                                           'infomration '
                                                                           'will '
                                                                           'be '
                                                                           'displayed '
                                                                           'saying\n'
                                                                           'it '
                                                                           'has '
                                                                           'changed '
                                                                           'to '
                                                                           'a '
                                                                           'state '
                                                                           'of '
                                                                           'STOP_PENDING. '
                                                                           'If '
                                                                           'the '
                                                                           'spooler '
                                                                           'service '
                                                                           'was '
                                                                           'not '
                                                                           'running '
                                                                           '"The '
                                                                           'service '
                                                                           'has '
                                                                           'not '
                                                                           'been '
                                                                           'started." '
                                                                           'will '
                                                                           'be '
                                                                           'displayed '
                                                                           'and '
                                                                           'it '
                                                                           'can '
                                                                           'be\n'
                                                                           'started '
                                                                           'by '
                                                                           'running '
                                                                           'the '
                                                                           'cleanup '
                                                                           'command.\n',
                                                            'executor': {'cleanup_command': 'sc.exe '
                                                                                            'start '
                                                                                            '#{service_name} '
                                                                                            '>nul '
                                                                                            '2>&1\n',
                                                                         'command': 'sc.exe '
                                                                                    'stop '
                                                                                    '#{service_name}\n',
                                                                         'elevation_required': True,
                                                                         'name': 'command_prompt'},
                                                            'input_arguments': {'service_name': {'default': 'spooler',
                                                                                                 'description': 'Name '
                                                                                                                'of '
                                                                                                                'a '
                                                                                                                'service '
                                                                                                                'to '
                                                                                                                'stop',
                                                                                                 'type': 'String'}},
                                                            'name': 'Windows - '
                                                                    'Stop '
                                                                    'service '
                                                                    'using '
                                                                    'Service '
                                                                    'Controller',
                                                            'supported_platforms': ['windows']},
                                                           {'description': 'Stops '
                                                                           'a '
                                                                           'specified '
                                                                           'service '
                                                                           'using '
                                                                           'the '
                                                                           'net.exe '
                                                                           'command. '
                                                                           'Upon '
                                                                           'execution, '
                                                                           'if '
                                                                           'the '
                                                                           'service '
                                                                           'was '
                                                                           'running '
                                                                           '"The '
                                                                           'Print '
                                                                           'Spooler '
                                                                           'service '
                                                                           'was '
                                                                           'stopped '
                                                                           'successfully."\n'
                                                                           'will '
                                                                           'be '
                                                                           'displayed. '
                                                                           'If '
                                                                           'the '
                                                                           'service '
                                                                           'was '
                                                                           'not '
                                                                           'running, '
                                                                           '"The '
                                                                           'Print '
                                                                           'Spooler '
                                                                           'service '
                                                                           'is '
                                                                           'not '
                                                                           'started." '
                                                                           'will '
                                                                           'be '
                                                                           'displayed '
                                                                           'and '
                                                                           'it '
                                                                           'can '
                                                                           'be\n'
                                                                           'started '
                                                                           'by '
                                                                           'running '
                                                                           'the '
                                                                           'cleanup '
                                                                           'command.\n',
                                                            'executor': {'cleanup_command': 'net.exe '
                                                                                            'start '
                                                                                            '#{service_name} '
                                                                                            '>nul '
                                                                                            '2>&1\n',
                                                                         'command': 'net.exe '
                                                                                    'stop '
                                                                                    '#{service_name}\n',
                                                                         'elevation_required': True,
                                                                         'name': 'command_prompt'},
                                                            'input_arguments': {'service_name': {'default': 'spooler',
                                                                                                 'description': 'Name '
                                                                                                                'of '
                                                                                                                'a '
                                                                                                                'service '
                                                                                                                'to '
                                                                                                                'stop',
                                                                                                 'type': 'String'}},
                                                            'name': 'Windows - '
                                                                    'Stop '
                                                                    'service '
                                                                    'using '
                                                                    'net.exe',
                                                            'supported_platforms': ['windows']},
                                                           {'description': 'Stops '
                                                                           'a '
                                                                           'specified '
                                                                           'service '
                                                                           'killng '
                                                                           'the '
                                                                           "service's "
                                                                           'process.\n'
                                                                           'This '
                                                                           'technique '
                                                                           'was '
                                                                           'used '
                                                                           'by '
                                                                           'WannaCry. '
                                                                           'Upon '
                                                                           'execution, '
                                                                           'if '
                                                                           'the '
                                                                           'spoolsv '
                                                                           'service '
                                                                           'was '
                                                                           'running '
                                                                           '"SUCCESS: '
                                                                           'The '
                                                                           'process '
                                                                           '"spoolsv.exe" '
                                                                           'with '
                                                                           'PID '
                                                                           '2316 '
                                                                           'has '
                                                                           'been '
                                                                           'terminated."\n'
                                                                           'will '
                                                                           'be '
                                                                           'displayed. '
                                                                           'If '
                                                                           'the '
                                                                           'service '
                                                                           'was '
                                                                           'not '
                                                                           'running '
                                                                           '"ERROR: '
                                                                           'The '
                                                                           'process '
                                                                           '"spoolsv.exe" '
                                                                           'not '
                                                                           'found." '
                                                                           'will '
                                                                           'be '
                                                                           'displayed '
                                                                           'and '
                                                                           'it '
                                                                           'can '
                                                                           'be\n'
                                                                           'started '
                                                                           'by '
                                                                           'running '
                                                                           'the '
                                                                           'cleanup '
                                                                           'command.\n',
                                                            'executor': {'command': 'taskkill.exe '
                                                                                    '/f '
                                                                                    '/im '
                                                                                    '#{process_name}\n',
                                                                         'elevation_required': False,
                                                                         'name': 'command_prompt'},
                                                            'input_arguments': {'process_name': {'default': 'spoolsv.exe',
                                                                                                 'description': 'Name '
                                                                                                                'of '
                                                                                                                'a '
                                                                                                                'process '
                                                                                                                'to '
                                                                                                                'kill',
                                                                                                 'type': 'String'}},
                                                            'name': 'Windows - '
                                                                    'Stop '
                                                                    'service '
                                                                    'by '
                                                                    'killing '
                                                                    'process',
                                                            'supported_platforms': ['windows']}],
                                          'attack_technique': 'T1489',
                                          'display_name': 'Service Stop'}}]
```

# Tactics


* [Impact](../tactics/Impact.md)


# Mitigations

None

# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

