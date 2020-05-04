
# System Time Discovery

## Description

### MITRE Description

> The system time is set and stored by the Windows Time Service within a domain to maintain time synchronization between systems and services in an enterprise network. (Citation: MSDN System Time) (Citation: Technet Windows Time Service)

An adversary may gather the system time and/or time zone from a local or remote system. This information may be gathered in a number of ways, such as with [Net](https://attack.mitre.org/software/S0039) on Windows by performing <code>net time \\hostname</code> to gather the system time on a remote system. The victim's time zone may also be inferred from the current system time or gathered by using <code>w32tm /tz</code>. (Citation: Technet Windows Time Service) The information could be useful for performing other techniques, such as executing a file with a [Scheduled Task](https://attack.mitre.org/techniques/T1053) (Citation: RSA EU12 They're Inside), or to discover locality information based on time zone to assist in victim targeting.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1124

## Potential Commands

```
net time \\localhost
w32tm /tz

Get-Date

{'darwin': {'sh': {'command': 'date -u +"%Y-%m-%dT%H:%M:%SZ"\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}}, 'linux': {'sh': {'command': 'date -u +"%Y-%m-%dT%H:%M:%SZ"\n', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}}, 'windows': {'psh': {'command': "Get-Date -UFormat '+%Y-%m-%dT%H:%M:%SZ'\n", 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}}}
Dos
C: \ Windows \ system32> net time \\ ICBC
Current time \\ ICBC is 2019/11/10 20:09:50

The command completed successfully.
Dos
Microsoft Windows [Version 10.0.14393]
(C) 2016 Microsoft Corporation. all rights reserved.

C: \ Users \ Administrator> w32tm / tz
Time zone: Current: TIME_ZONE_ID_UNKNOWN deviating: -480 minutes (UTC = local time + Bias)
[Standard name: "China Standard Time" partial amount: 0 Date :( unspecified)]
[Daylight Saving Time Name: "China Daylight Saving Time" partial amount: -60 points :( date not specified)]
```

## Commands Dataset

```
[{'command': 'net time \\\\localhost\nw32tm /tz\n',
  'name': None,
  'source': 'atomics/T1124/T1124.yaml'},
 {'command': 'Get-Date\n', 'name': None, 'source': 'atomics/T1124/T1124.yaml'},
 {'command': {'darwin': {'sh': {'command': 'date -u +"%Y-%m-%dT%H:%M:%SZ"\n',
                                'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}},
              'linux': {'sh': {'command': 'date -u +"%Y-%m-%dT%H:%M:%SZ"\n',
                               'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}},
              'windows': {'psh': {'command': 'Get-Date -UFormat '
                                             "'+%Y-%m-%dT%H:%M:%SZ'\n",
                                  'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}}},
  'name': 'get current system time (ISO 8601)',
  'source': 'data/abilities/discovery/fa6e8607-e0b1-425d-8924-9b894da5a002.yml'},
 {'command': 'Dos\n'
             'C: \\ Windows \\ system32> net time \\\\ ICBC\n'
             'Current time \\\\ ICBC is 2019/11/10 20:09:50\n'
             '\n'
             'The command completed successfully.',
  'name': 'Dos',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Dos\n'
             'Microsoft Windows [Version 10.0.14393]\n'
             '(C) 2016 Microsoft Corporation. all rights reserved.\n'
             '\n'
             'C: \\ Users \\ Administrator> w32tm / tz\n'
             'Time zone: Current: TIME_ZONE_ID_UNKNOWN deviating: -480 minutes '
             '(UTC = local time + Bias)\n'
             '[Standard name: "China Standard Time" partial amount: 0 Date :( '
             'unspecified)]\n'
             '[Daylight Saving Time Name: "China Daylight Saving Time" partial '
             'amount: -60 points :( date not specified)]',
  'name': 'Dos',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'System Time Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_path contains '
           '"*\\\\net.exe"and process_command_line contains "*net* time*")or '
           'process_path contains "w32tm.exe"or process_command_line contains '
           '"*Get-Date*"'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows system service discovery\n'
           'description: windows server 2016\n'
           'references:\n'
           'tags: T1124\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ net.exe' # process information> new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ windows "
           "\\ system32 \\ cmd.exe' # Process Information> Creator Process "
           'Name\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: net time * # '
           'Process Information> process command line\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ net1.exe' # process information> new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ Windows "
           "\\ System32 \\ net.exe' # Process Information> Creator Process "
           'Name\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: C: \\ Windows '
           '\\ system32 \\ net1 time * # Process Information> process command '
           'line\n'
           '\xa0\xa0\xa0\xa0selection3:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4689 # exited process\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ProcessName: 'C: \\ Windows \\ "
           "System32 \\ net1.exe' # process information> process name\n"
           '\xa0\xa0\xa0\xa0selection4:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4689 # exited process\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ProcessName: 'C: \\ Windows \\ "
           "System32 \\ net.exe' # process information> process name\n"
           '\xa0\xa0\xa0\xa0timeframe: last 1m # can be adjusted according to '
           'actual situation\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows system service discovery\n'
           'description: windows server 2016\n'
           'references:\n'
           'tags: T1124\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection1:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688 # have created a new '
           'process.\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Newprocessname: 'C: \\ Windows \\ "
           "System32 \\ w32tm.exe' # process information> new process name\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Creatorprocessname: 'C: \\ windows "
           "\\ system32 \\ cmd.exe' # Process Information> Creator Process "
           'Name\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Processcommandline: w32tm / tz # '
           'Process Information> process command line\n'
           '\xa0\xa0\xa0\xa0selection2:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4689 # exited process\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ProcessName: 'C: \\ Windows \\ "
           "System32 \\ w32tm.exe' # process information> process name\n"
           '\xa0\xa0\xa0\xa0timeframe: last 5s # can be adjusted according to '
           'actual situation\n'
           '\xa0\xa0\xa0\xa0condition: all of them\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - System Time Discovery': {'atomic_tests': [{'description': 'Identify '
                                                                                    'the '
                                                                                    'system '
                                                                                    'time. '
                                                                                    'Upon '
                                                                                    'execution, '
                                                                                    'the '
                                                                                    'local '
                                                                                    'computer '
                                                                                    'system '
                                                                                    'time '
                                                                                    'and '
                                                                                    'timezone '
                                                                                    'will '
                                                                                    'be '
                                                                                    'displayed.\n',
                                                                     'executor': {'command': 'net '
                                                                                             'time '
                                                                                             '\\\\#{computer_name}\n'
                                                                                             'w32tm '
                                                                                             '/tz\n',
                                                                                  'elevation_required': False,
                                                                                  'name': 'command_prompt'},
                                                                     'input_arguments': {'computer_name': {'default': 'localhost',
                                                                                                           'description': 'computer '
                                                                                                                          'name '
                                                                                                                          'to '
                                                                                                                          'query',
                                                                                                           'type': 'string'}},
                                                                     'name': 'System '
                                                                             'Time '
                                                                             'Discovery',
                                                                     'supported_platforms': ['windows']},
                                                                    {'description': 'Identify '
                                                                                    'the '
                                                                                    'system '
                                                                                    'time '
                                                                                    'via '
                                                                                    'PowerShell. '
                                                                                    'Upon '
                                                                                    'execution, '
                                                                                    'the '
                                                                                    'system '
                                                                                    'time '
                                                                                    'will '
                                                                                    'be '
                                                                                    'displayed.\n',
                                                                     'executor': {'command': 'Get-Date\n',
                                                                                  'elevation_required': False,
                                                                                  'name': 'powershell'},
                                                                     'name': 'System '
                                                                             'Time '
                                                                             'Discovery '
                                                                             '- '
                                                                             'PowerShell',
                                                                     'supported_platforms': ['windows']}],
                                                   'attack_technique': 'T1124',
                                                   'display_name': 'System '
                                                                   'Time '
                                                                   'Discovery'}},
 {'Mitre Stockpile - get current system time (ISO 8601)': {'description': 'get '
                                                                          'current '
                                                                          'system '
                                                                          'time '
                                                                          '(ISO '
                                                                          '8601)',
                                                           'id': 'fa6e8607-e0b1-425d-8924-9b894da5a002',
                                                           'name': 'Get System '
                                                                   'Time',
                                                           'platforms': {'darwin': {'sh': {'command': 'date '
                                                                                                      '-u '
                                                                                                      '+"%Y-%m-%dT%H:%M:%SZ"\n',
                                                                                           'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}},
                                                                         'linux': {'sh': {'command': 'date '
                                                                                                     '-u '
                                                                                                     '+"%Y-%m-%dT%H:%M:%SZ"\n',
                                                                                          'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}},
                                                                         'windows': {'psh': {'command': 'Get-Date '
                                                                                                        '-UFormat '
                                                                                                        "'+%Y-%m-%dT%H:%M:%SZ'\n",
                                                                                             'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.current.time'}]}}}},
                                                           'tactic': 'discovery',
                                                           'technique': {'attack_id': 'T1124',
                                                                         'name': 'System '
                                                                                 'Time '
                                                                                 'Discovery'}}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations

None

# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Turla](../actors/Turla.md)
    
* [The White Company](../actors/The-White-Company.md)
    
