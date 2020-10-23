
# At (Linux)

## Description

### MITRE Description

> Adversaries may abuse the [at](https://attack.mitre.org/software/S0110) utility to perform task scheduling for initial or recurring execution of malicious code. The [at](https://attack.mitre.org/software/S0110) command within Linux operating systems enables administrators to schedule tasks.(Citation: Kifarunix - Task Scheduling in Linux)

An adversary may use [at](https://attack.mitre.org/software/S0110) in Linux environments to execute programs at system startup or on a scheduled basis for persistence. [at](https://attack.mitre.org/software/S0110) can also be abused to conduct remote Execution as part of Lateral Movement and or to run a process under the context of a specified account.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux']
* Remote: True
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1053/001

## Potential Commands

```
echo "echo Hello from Atomic Red Team" | at #{time_spec}
echo "#{at_command}" | at now + 1 minute
```

## Commands Dataset

```
[{'command': 'echo "#{at_command}" | at now + 1 minute\n',
  'name': None,
  'source': 'atomics/T1053.001/T1053.001.yaml'},
 {'command': 'echo "echo Hello from Atomic Red Team" | at #{time_spec}\n',
  'name': None,
  'source': 'atomics/T1053.001/T1053.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Scheduled Task/Job: At (Linux)': {'atomic_tests': [{'auto_generated_guid': '7266d898-ac82-4ec0-97c7-436075d0d08e',
                                                                              'dependencies': [{'description': 'The '
                                                                                                               '`at` '
                                                                                                               'and '
                                                                                                               '`atd` '
                                                                                                               'executables '
                                                                                                               'must '
                                                                                                               'exist '
                                                                                                               'in '
                                                                                                               'the '
                                                                                                               'PATH\n',
                                                                                                'get_prereq_command': 'echo '
                                                                                                                      "'Please "
                                                                                                                      'install '
                                                                                                                      '`at` '
                                                                                                                      'and '
                                                                                                                      '`atd`; '
                                                                                                                      'they '
                                                                                                                      'were '
                                                                                                                      'not '
                                                                                                                      'found '
                                                                                                                      'in '
                                                                                                                      'the '
                                                                                                                      'PATH '
                                                                                                                      '(Package '
                                                                                                                      'name: '
                                                                                                                      "`at`)'\n",
                                                                                                'prereq_command': 'which '
                                                                                                                  'at '
                                                                                                                  '&& '
                                                                                                                  'which '
                                                                                                                  'atd\n'},
                                                                                               {'description': 'The '
                                                                                                               '`atd` '
                                                                                                               'daemon '
                                                                                                               'must '
                                                                                                               'be '
                                                                                                               'running\n',
                                                                                                'get_prereq_command': 'echo '
                                                                                                                      "'Please "
                                                                                                                      'start '
                                                                                                                      'the '
                                                                                                                      '`atd` '
                                                                                                                      'daemon '
                                                                                                                      '(sysv: '
                                                                                                                      '`service '
                                                                                                                      'atd '
                                                                                                                      'start` '
                                                                                                                      '; '
                                                                                                                      'systemd: '
                                                                                                                      '`systemctl '
                                                                                                                      'start '
                                                                                                                      "atd`)'\n",
                                                                                                'prereq_command': 'systemctl '
                                                                                                                  'status '
                                                                                                                  'atd '
                                                                                                                  '|| '
                                                                                                                  'service '
                                                                                                                  'atd '
                                                                                                                  'status\n'}],
                                                                              'dependency_executor_name': 'sh',
                                                                              'description': 'This '
                                                                                             'test '
                                                                                             'submits '
                                                                                             'a '
                                                                                             'command '
                                                                                             'to '
                                                                                             'be '
                                                                                             'run '
                                                                                             'in '
                                                                                             'the '
                                                                                             'future '
                                                                                             'by '
                                                                                             'the '
                                                                                             '`at` '
                                                                                             'daemon.\n',
                                                                              'executor': {'command': 'echo '
                                                                                                      '"#{at_command}" '
                                                                                                      '| '
                                                                                                      'at '
                                                                                                      '#{time_spec}\n',
                                                                                           'elevation_required': False,
                                                                                           'name': 'sh'},
                                                                              'input_arguments': {'at_command': {'default': 'echo '
                                                                                                                            'Hello '
                                                                                                                            'from '
                                                                                                                            'Atomic '
                                                                                                                            'Red '
                                                                                                                            'Team',
                                                                                                                 'description': 'The '
                                                                                                                                'command '
                                                                                                                                'to '
                                                                                                                                'be '
                                                                                                                                'run',
                                                                                                                 'type': 'String'},
                                                                                                  'time_spec': {'default': 'now '
                                                                                                                           '+ '
                                                                                                                           '1 '
                                                                                                                           'minute',
                                                                                                                'description': 'Time '
                                                                                                                               'specification '
                                                                                                                               'of '
                                                                                                                               'when '
                                                                                                                               'the '
                                                                                                                               'command '
                                                                                                                               'should '
                                                                                                                               'run',
                                                                                                                'type': 'String'}},
                                                                              'name': 'At '
                                                                                      '- '
                                                                                      'Schedule '
                                                                                      'a '
                                                                                      'job',
                                                                              'supported_platforms': ['linux']}],
                                                            'attack_technique': 'T1053.001',
                                                            'display_name': 'Scheduled '
                                                                            'Task/Job: '
                                                                            'At '
                                                                            '(Linux)'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)

* [Audit](../mitigations/Audit.md)
    

# Actors

None
