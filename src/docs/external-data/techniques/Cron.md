
# Cron

## Description

### MITRE Description

> Adversaries may abuse the <code>cron</code> utility to perform task scheduling for initial or recurring execution of malicious code. The <code>cron</code> utility is a time-based job scheduler for Unix-like operating systems.  The <code> crontab</code> file contains the schedule of cron entries to be run and the specified times for execution. Any <code>crontab</code> files are stored in operating system-specific file paths.

An adversary may use <code>cron</code> in Linux or Unix environments to execute programs at system startup or on a scheduled basis for persistence. <code>cron</code> can also be abused to conduct remote Execution as part of Lateral Movement and or to run a process under the context of a specified account.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1053/003

## Potential Commands

```
crontab -l > /tmp/notevil
echo "* * * * * /tmp/evil.sh" > #{tmp_cron} && crontab #{tmp_cron}
crontab -l > /tmp/notevil
echo "* * * * * #{command}" > /tmp/persistevil && crontab /tmp/persistevil
echo "echo 'Hello from Atomic Red Team' > /tmp/atomic.log" > /etc/cron.daily/#{cron_script_name}
echo "#{command}" > /etc/cron.daily/persistevil
```

## Commands Dataset

```
[{'command': 'crontab -l > /tmp/notevil\n'
             'echo "* * * * * /tmp/evil.sh" > #{tmp_cron} && crontab '
             '#{tmp_cron}\n',
  'name': None,
  'source': 'atomics/T1053.003/T1053.003.yaml'},
 {'command': 'crontab -l > /tmp/notevil\n'
             'echo "* * * * * #{command}" > /tmp/persistevil && crontab '
             '/tmp/persistevil\n',
  'name': None,
  'source': 'atomics/T1053.003/T1053.003.yaml'},
 {'command': 'echo "echo \'Hello from Atomic Red Team\' > /tmp/atomic.log" > '
             '/etc/cron.daily/#{cron_script_name}\n',
  'name': None,
  'source': 'atomics/T1053.003/T1053.003.yaml'},
 {'command': 'echo "#{command}" > /etc/cron.daily/persistevil\n',
  'name': None,
  'source': 'atomics/T1053.003/T1053.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Scheduled Task/Job: Cron': {'atomic_tests': [{'auto_generated_guid': '435057fb-74b1-410e-9403-d81baf194f75',
                                                                        'description': 'This '
                                                                                       'test '
                                                                                       'replaces '
                                                                                       'the '
                                                                                       'current '
                                                                                       "user's "
                                                                                       'crontab '
                                                                                       'file '
                                                                                       'with '
                                                                                       'the '
                                                                                       'contents '
                                                                                       'of '
                                                                                       'the '
                                                                                       'referenced '
                                                                                       'file. '
                                                                                       'This '
                                                                                       'technique '
                                                                                       'was '
                                                                                       'used '
                                                                                       'by '
                                                                                       'numerous '
                                                                                       'IoT '
                                                                                       'automated '
                                                                                       'exploitation '
                                                                                       'attacks.\n',
                                                                        'executor': {'cleanup_command': 'crontab '
                                                                                                        '/tmp/notevil\n',
                                                                                     'command': 'crontab '
                                                                                                '-l '
                                                                                                '> '
                                                                                                '/tmp/notevil\n'
                                                                                                'echo '
                                                                                                '"* '
                                                                                                '* '
                                                                                                '* '
                                                                                                '* '
                                                                                                '* '
                                                                                                '#{command}" '
                                                                                                '> '
                                                                                                '#{tmp_cron} '
                                                                                                '&& '
                                                                                                'crontab '
                                                                                                '#{tmp_cron}\n',
                                                                                     'name': 'bash'},
                                                                        'input_arguments': {'command': {'default': '/tmp/evil.sh',
                                                                                                        'description': 'Command '
                                                                                                                       'to '
                                                                                                                       'execute',
                                                                                                        'type': 'string'},
                                                                                            'tmp_cron': {'default': '/tmp/persistevil',
                                                                                                         'description': 'Temporary '
                                                                                                                        'reference '
                                                                                                                        'file '
                                                                                                                        'to '
                                                                                                                        'hold '
                                                                                                                        'evil '
                                                                                                                        'cron '
                                                                                                                        'schedule',
                                                                                                         'type': 'path'}},
                                                                        'name': 'Cron '
                                                                                '- '
                                                                                'Replace '
                                                                                'crontab '
                                                                                'with '
                                                                                'referenced '
                                                                                'file',
                                                                        'supported_platforms': ['macos',
                                                                                                'linux']},
                                                                       {'auto_generated_guid': 'b7d42afa-9086-4c8a-b7b0-8ea3faa6ebb0',
                                                                        'description': 'This '
                                                                                       'test '
                                                                                       'adds '
                                                                                       'a '
                                                                                       'script '
                                                                                       'to '
                                                                                       'a '
                                                                                       'cron '
                                                                                       'folder '
                                                                                       'configured '
                                                                                       'to '
                                                                                       'execute '
                                                                                       'on '
                                                                                       'a '
                                                                                       'schedule. '
                                                                                       'This '
                                                                                       'technique '
                                                                                       'was '
                                                                                       'used '
                                                                                       'by '
                                                                                       'the '
                                                                                       'threat '
                                                                                       'actor '
                                                                                       'Rocke '
                                                                                       'during '
                                                                                       'the '
                                                                                       'exploitation '
                                                                                       'of '
                                                                                       'Linux '
                                                                                       'web '
                                                                                       'servers.\n',
                                                                        'executor': {'cleanup_command': 'rm '
                                                                                                        '/etc/cron.daily/#{cron_script_name}\n',
                                                                                     'command': 'echo '
                                                                                                '"#{command}" '
                                                                                                '> '
                                                                                                '/etc/cron.daily/#{cron_script_name}\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'bash'},
                                                                        'input_arguments': {'command': {'default': 'echo '
                                                                                                                   "'Hello "
                                                                                                                   'from '
                                                                                                                   'Atomic '
                                                                                                                   'Red '
                                                                                                                   "Team' "
                                                                                                                   '> '
                                                                                                                   '/tmp/atomic.log',
                                                                                                        'description': 'Command '
                                                                                                                       'to '
                                                                                                                       'execute',
                                                                                                        'type': 'string'},
                                                                                            'cron_script_name': {'default': 'persistevil',
                                                                                                                 'description': 'Name '
                                                                                                                                'of '
                                                                                                                                'file '
                                                                                                                                'to '
                                                                                                                                'store '
                                                                                                                                'in '
                                                                                                                                'cron '
                                                                                                                                'folder',
                                                                                                                 'type': 'string'}},
                                                                        'name': 'Cron '
                                                                                '- '
                                                                                'Add '
                                                                                'script '
                                                                                'to '
                                                                                'cron '
                                                                                'folder',
                                                                        'supported_platforms': ['macos',
                                                                                                'linux']}],
                                                      'attack_technique': 'T1053.003',
                                                      'display_name': 'Scheduled '
                                                                      'Task/Job: '
                                                                      'Cron'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Audit](../mitigations/Audit.md)

* [User Account Management](../mitigations/User-Account-Management.md)
    

# Actors


* [Rocke](../actors/Rocke.md)

