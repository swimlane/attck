
# Local Job Scheduling

## Description

### MITRE Description

> On Linux and macOS systems, multiple methods are supported for creating pre-scheduled and periodic background jobs: cron, (Citation: Die.net Linux crontab Man Page) at, (Citation: Die.net Linux at Man Page) and launchd. (Citation: AppleDocs Scheduling Timed Jobs) Unlike [Scheduled Task](https://attack.mitre.org/techniques/T1053) on Windows systems, job scheduling on Linux-based systems cannot be done remotely unless used in conjunction within an established remote session, like secure shell (SSH).

### cron

System-wide cron jobs are installed by modifying <code>/etc/crontab</code> file, <code>/etc/cron.d/</code> directory or other locations supported by the Cron daemon, while per-user cron jobs are installed using crontab with specifically formatted crontab files. (Citation: AppleDocs Scheduling Timed Jobs) This works on macOS and Linux systems.

Those methods allow for commands or scripts to be executed at specific, periodic intervals in the background without user interaction. An adversary may use job scheduling to execute programs at system startup or on a scheduled basis for Persistence, (Citation: Janicab) (Citation: Methods of Mac Malware Persistence) (Citation: Malware Persistence on OS X) (Citation: Avast Linux Trojan Cron Persistence) to conduct Execution as part of Lateral Movement, to gain root privileges, or to run a process under the context of a specific account.

### at

The at program is another means on POSIX-based systems, including macOS and Linux, to schedule a program or script job for execution at a later date and/or time, which could also be used for the same purposes.

### launchd

Each launchd job is described by a different configuration property list (plist) file similar to [Launch Daemon](https://attack.mitre.org/techniques/T1160) or [Launch Agent](https://attack.mitre.org/techniques/T1159), except there is an additional key called <code>StartCalendarInterval</code> with a dictionary of time values. (Citation: AppleDocs Scheduling Timed Jobs) This only works on macOS and OS X.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'User', 'root']
* Platforms: ['Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1168

## Potential Commands

```
echo "* * * * * /tmp/evil.sh" > #{tmp_cron} && crontab #{tmp_cron}

echo "* * * * * #{command}" > /tmp/persistevil && crontab /tmp/persistevil

echo "echo 'Hello from Atomic Red Team' > /tmp/atomic.log" > /etc/cron.daily/#{cron_script_name}

echo "#{command}" > /etc/cron.daily/persistevil

bash crontab
shell crontab
python/persistence/multi/crontab
python/persistence/multi/crontab
echo "* * * * * #{command}" > #{tmp_cron} && crontab #{tmp_cron}
echo "#{command}" > /etc/cron.daily/#{cron_script_name}
at now + 1 minute -f script.sh
echo "shutdown -h now" | at -m 23:5
at now + 1 minute | ping -c 4 google.com > /home/ec2-user/google6.txt
```

## Commands Dataset

```
[{'command': 'echo "* * * * * /tmp/evil.sh" > #{tmp_cron} && crontab '
             '#{tmp_cron}\n',
  'name': None,
  'source': 'atomics/T1168/T1168.yaml'},
 {'command': 'echo "* * * * * #{command}" > /tmp/persistevil && crontab '
             '/tmp/persistevil\n',
  'name': None,
  'source': 'atomics/T1168/T1168.yaml'},
 {'command': 'echo "echo \'Hello from Atomic Red Team\' > /tmp/atomic.log" > '
             '/etc/cron.daily/#{cron_script_name}\n',
  'name': None,
  'source': 'atomics/T1168/T1168.yaml'},
 {'command': 'echo "#{command}" > /etc/cron.daily/persistevil\n',
  'name': None,
  'source': 'atomics/T1168/T1168.yaml'},
 {'command': 'bash crontab', 'name': None, 'source': 'Threat Hunting Tables'},
 {'command': 'shell crontab', 'name': None, 'source': 'Threat Hunting Tables'},
 {'command': 'python/persistence/multi/crontab',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/persistence/multi/crontab',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'echo "* * * * * #{command}" > #{tmp_cron} && crontab #{tmp_cron}',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'echo "#{command}" > /etc/cron.daily/#{cron_script_name}',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'at now + 1 minute -f script.sh',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'echo "shutdown -h now" | at -m 23:5',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'at now + 1 minute | ping -c 4 google.com > '
             '/home/ec2-user/google6.txt',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'}]
```

## Potential Detections

```json
[{'data_source': '/var/log/cron'}, {'data_source': 'bash_history'}]
```

## Potential Queries

```json
[{'name': None,
  'product': 'Splunk',
  'query': '1. bash_history : track the command "crontab" - you may need to '
           'look for the commands crontab <file>'},
 {'name': None, 'product': 'Splunk', 'query': ''},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=bash_history bash_command="crontab *" | '
           'table host, user_name, bash_command'},
 {'name': None,
  'product': 'Splunk',
  'query': '2. /var/log/cron :  look for "crontab" & "REPLACE" in the cron '
           'logs'},
 {'name': None, 'product': 'Splunk', 'query': 'index=linux crontab replace'},
 {'name': None,
  'product': 'Splunk',
  'query': '3. /var.log/cron - track CMD command'},
 {'name': None,
  'product': 'Splunk',
  'query': 'cat /var/log/cron | grep CMD | cut -d " " -f 9 |sort | uniq -c  | '
           'sort -rn will give you all the jobs which run in the environment '
           'with its number starting from high to low. You can look for a '
           'suspecious job/s which are not a part of a whitelisted jobs.'},
 {'name': None,
  'product': 'Splunk',
  'query': '4. index=linux sourcetype=bash_history at'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Local Job Scheduling': {'atomic_tests': [{'auto_generated_guid': '435057fb-74b1-410e-9403-d81baf194f75',
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
                                                                    'executor': {'command': 'echo '
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
                                                                    'executor': {'command': 'echo '
                                                                                            '"#{command}" '
                                                                                            '> '
                                                                                            '/etc/cron.daily/#{cron_script_name}\n',
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
                                                                                            'linux']},
                                                                   {'auto_generated_guid': '11979f23-9b9d-482a-9935-6fc9cd022c3e',
                                                                    'description': 'This '
                                                                                   'test '
                                                                                   'adds '
                                                                                   'persistence '
                                                                                   'via '
                                                                                   'a '
                                                                                   'plist '
                                                                                   'to '
                                                                                   'execute '
                                                                                   'via '
                                                                                   'the '
                                                                                   'macOS '
                                                                                   'Event '
                                                                                   'Monitor '
                                                                                   'Daemon. \n',
                                                                    'executor': {'name': 'manual',
                                                                                 'steps': '1. '
                                                                                          'Place '
                                                                                          'this '
                                                                                          'file '
                                                                                          'in '
                                                                                          '/etc/emond.d/rules/atomicredteam.plist\n'
                                                                                          '<?xml '
                                                                                          'version="1.0" '
                                                                                          'encoding="UTF-8"?>\n'
                                                                                          '<!DOCTYPE '
                                                                                          'plist '
                                                                                          'PUBLIC '
                                                                                          '"-//Apple//DTD '
                                                                                          'PLIST '
                                                                                          '1.0//EN" '
                                                                                          '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                                                                                          '<plist '
                                                                                          'version="1.0">\n'
                                                                                          '<array>\n'
                                                                                          '    '
                                                                                          '<dict>\n'
                                                                                          '        '
                                                                                          '<key>name</key>\n'
                                                                                          '        '
                                                                                          '<string>atomicredteam</string>\n'
                                                                                          '        '
                                                                                          '<key>enabled</key>\n'
                                                                                          '        '
                                                                                          '<true/>\n'
                                                                                          '        '
                                                                                          '<key>eventTypes</key>\n'
                                                                                          '        '
                                                                                          '<array>\n'
                                                                                          '            '
                                                                                          '<string>startup</string>\n'
                                                                                          '        '
                                                                                          '</array>\n'
                                                                                          '        '
                                                                                          '<key>actions</key>\n'
                                                                                          '        '
                                                                                          '<array>\n'
                                                                                          '            '
                                                                                          '<dict>\n'
                                                                                          '                '
                                                                                          '<key>command</key>\n'
                                                                                          '                '
                                                                                          '<string>/usr/bin/say</string>\n'
                                                                                          '                '
                                                                                          '<key>user</key>\n'
                                                                                          '                '
                                                                                          '<string>root</string>\n'
                                                                                          '                '
                                                                                          '<key>arguments</key>\n'
                                                                                          '                    '
                                                                                          '<array>\n'
                                                                                          '                        '
                                                                                          '<string>-v '
                                                                                          'Tessa</string>\n'
                                                                                          '                        '
                                                                                          '<string>I '
                                                                                          'am '
                                                                                          'a '
                                                                                          'persistent '
                                                                                          'startup '
                                                                                          'item.</string>\n'
                                                                                          '                    '
                                                                                          '</array>\n'
                                                                                          '                '
                                                                                          '<key>type</key>\n'
                                                                                          '                '
                                                                                          '<string>RunCommand</string>\n'
                                                                                          '            '
                                                                                          '</dict>\n'
                                                                                          '        '
                                                                                          '</array>\n'
                                                                                          '    '
                                                                                          '</dict>\n'
                                                                                          '</array>\n'
                                                                                          '</plist>\n'
                                                                                          '\n'
                                                                                          '2. '
                                                                                          'Place '
                                                                                          'an '
                                                                                          'empty '
                                                                                          'file '
                                                                                          'in '
                                                                                          '/private/var/db/emondClients/\n'
                                                                                          '\n'
                                                                                          '3. '
                                                                                          'sudo '
                                                                                          'touch '
                                                                                          '/private/var/db/emondClients/randomflag\n'},
                                                                    'name': 'Event '
                                                                            'Monitor '
                                                                            'Daemon '
                                                                            'Persistence',
                                                                    'supported_platforms': ['macos',
                                                                                            'linux']}],
                                                  'attack_technique': 'T1168',
                                                  'display_name': 'Local Job '
                                                                  'Scheduling'}},
 {'Threat Hunting Tables': {'chain_id': '100200',
                            'commandline_string': 'crontab',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1168',
                            'mitre_caption': 'cron_job',
                            'os': 'mac',
                            'parent_process': 'bash',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100202',
                            'commandline_string': 'crontab',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1168',
                            'mitre_caption': 'cron_job',
                            'os': 'linux',
                            'parent_process': 'shell',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1168',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/persistence/multi/crontab":  '
                                                                                 '["T1168"],',
                                            'Empire Module': 'python/persistence/multi/crontab',
                                            'Technique': 'Local Job '
                                                         'Scheduling'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)

* [Persistence](../tactics/Persistence.md)
    

# Mitigations

None

# Actors

None
