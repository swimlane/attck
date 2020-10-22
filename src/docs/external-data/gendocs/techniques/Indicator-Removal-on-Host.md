
# Indicator Removal on Host

## Description

### MITRE Description

> Adversaries may delete or alter generated artifacts on a host system, including logs or captured files such as quarantined malware. Locations and format of logs are platform or product-specific, however standard operating system logs are captured as Windows events or Linux/macOS files such as [Bash History](https://attack.mitre.org/techniques/T1139) and /var/log/*.

These actions may interfere with event collection, reporting, or other notifications used to detect intrusion activity. This that may compromise the integrity of security solutions by causing notable events to go unreported. This activity may also impede forensic analysis and incident response, due to lack of sufficient data to determine what occurred.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Log analysis', 'Host intrusion prevention systems', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1070

## Potential Commands

```
{'windows': {'psh,pwsh': {'command': 'Clear-Eventlog Security;\nClear-Eventlog System;\n'}}}
fsutil.exe usn deletejournal /D
vssadmin.exe delete shadows /all /quiet
wbadmin.exe delete catalog -quiet
wevtutil.exe /cl
wmic.exe /NODE:*shadowcopy delete *
wevtutilcl
wevtutil|cl
fsutil|usn|deletejournal
fsutilusn|deletejournal
powershell/credentials/mimikatz/purge
powershell/credentials/mimikatz/purge
powershell/management/lock
powershell/management/lock
powershell/management/logoff
powershell/management/logoff
powershell/management/restart
powershell/management/restart
python/persistence/osx/RemoveDaemon
python/persistence/osx/RemoveDaemon
```
rm -rf /var/log/*
```
```

## Commands Dataset

```
[{'command': {'windows': {'psh,pwsh': {'command': 'Clear-Eventlog Security;\n'
                                                  'Clear-Eventlog System;\n'}}},
  'name': 'Clear Sysmon logs [intended to trigger CAR-2016-04-002]',
  'source': 'data/abilities/defense-evasion/fcf71ee3-d1a9-4136-b919-9e5f6da43608.yml'},
 {'command': 'fsutil.exe usn deletejournal /D',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'vssadmin.exe delete shadows /all /quiet',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wbadmin.exe delete catalog -quiet',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wevtutil.exe /cl',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wmic.exe /NODE:*shadowcopy delete *',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'wevtutilcl',
  'name': None,
  'source': 'SysmonHunter - Indicator Removal on Host'},
 {'command': 'wevtutil|cl',
  'name': None,
  'source': 'SysmonHunter - Indicator Removal on Host'},
 {'command': 'fsutil|usn|deletejournal',
  'name': None,
  'source': 'SysmonHunter - Indicator Removal on Host'},
 {'command': 'fsutilusn|deletejournal',
  'name': None,
  'source': 'SysmonHunter - Indicator Removal on Host'},
 {'command': 'powershell/credentials/mimikatz/purge',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/purge',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/lock',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/lock',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/logoff',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/logoff',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/restart',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/restart',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/persistence/osx/RemoveDaemon',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/persistence/osx/RemoveDaemon',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'rm -rf /var/log/*',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'}]
```

## Potential Detections

```json
[{'data_source': 'auditlogs (audit.rules)'},
 {'data_source': 'bash_history logs'},
 {'data_source': {'author': '@neu5ron, Florian Roth',
                  'date': '2019/03/22',
                  'description': 'Detects a command that clears or disables '
                                 'any ETW trace log which could indicate a '
                                 'logging evasion.',
                  'detection': {'condition': 'selection_clear_1 or '
                                             'selection_clear_2 or '
                                             'selection_disable_1 or '
                                             'selection_disable_2',
                                'selection_clear_1': {'CommandLine': '* cl '
                                                                     '*/Trace*'},
                                'selection_clear_2': {'CommandLine': '* '
                                                                     'clear-log '
                                                                     '*/Trace*'},
                                'selection_disable_1': {'CommandLine': '* sl* '
                                                                       '/e:false*'},
                                'selection_disable_2': {'CommandLine': '* '
                                                                       'set-log* '
                                                                       '/e:false*'}},
                  'id': 'a238b5d0-ce2d-4414-a676-7a531b3d13d6',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil',
                                 'https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_mal_lockergoga.yml',
                                 'https://abuse.io/lockergoga.txt'],
                  'tags': ['attack.execution',
                           'attack.t1070',
                           'car.2016-04-002'],
                  'title': 'Disable of ETW Trace'}},
 {'data_source': {'author': 'Ecco',
                  'date': '2019/09/26',
                  'description': 'Detects clearing or configuration of '
                                 'eventlogs uwing wevtutil. Might be used by '
                                 'ransomwares during the attack (seen by '
                                 'NotPetya and others)',
                  'detection': {'condition': '(1 of selection_binary_*) and (1 '
                                             'of selection_clear_* or 1 of '
                                             'selection_disable_*)',
                                'selection_binary_1': {'Image': '*\\wevtutil.exe'},
                                'selection_binary_2': {'OriginalFileName': 'wevtutil.exe'},
                                'selection_clear_1': {'CommandLine': '* cl *'},
                                'selection_clear_2': {'CommandLine': '* '
                                                                     'clear-log '
                                                                     '*'},
                                'selection_disable_1': {'CommandLine': '* sl '
                                                                       '*'},
                                'selection_disable_2': {'CommandLine': '* '
                                                                       'set-log '
                                                                       '*'}},
                  'falsepositives': ['Admin activity',
                                     'Scripts and administrative tools used in '
                                     'the monitored environment'],
                  'id': 'cc36992a-4671-4f21-a91d-6c2b72a2edf5',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'tags': ['attack.execution',
                           'attack.t1070',
                           'car.2016-04-002'],
                  'title': 'Suspicious eventlog clear or configuration using '
                           'wevtutil'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'One of the Windows Eventlogs has been '
                                 'cleared. e.g. caused by "wevtutil cl" '
                                 'command execution',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 104,
                                              'Source': 'Microsoft-Windows-Eventlog'}},
                  'falsepositives': ['Unknown'],
                  'id': 'd99b79d2-0a6f-4f46-ad8b-260b6e17f982',
                  'level': 'medium',
                  'logsource': {'product': 'windows', 'service': 'system'},
                  'references': ['https://twitter.com/deviouspolack/status/832535435960209408',
                                 'https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100'],
                  'tags': ['attack.defense_evasion',
                           'attack.t1070',
                           'car.2016-04-002'],
                  'title': 'Eventlog Cleared'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Some threat groups tend to delete the local '
                                 "'Security' Eventlog using certain utitlities",
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': [517, 1102]}},
                  'falsepositives': ['Rollout of log collection agents (the '
                                     'setup routine often includes a reset of '
                                     'the local Eventlog)',
                                     'System provisioning (system reset before '
                                     'the golden image creation)'],
                  'id': 'f2f01843-e7b8-4f95-a35a-d23584476423',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'tags': ['attack.defense_evasion',
                           'attack.t1070',
                           'car.2016-04-002'],
                  'title': 'Security Eventlog Cleared'}},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']}]
```

## Potential Queries

```json
[{'name': 'Indicator Removal On Host',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where process_path contains "wevtutil"'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=linux_audit syscall=263 | table '
           'host,auid,uid,euid,exe,key'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=linux_audit type=PATH name=*.log '
           'nametype=delete'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': '-a always,exit -F arch=b64 -F PATH=/var/log -S unlinkat -F '
           'auid>=1000 -F auid!=4294967295 -F key=delete_logs'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype="bash_history" rm * .log | table host, '
           'user_name, bash_command'},
 {'name': None, 'product': 'Splunk', 'query': '```'}]
```

## Raw Dataset

```json
[{'Mitre Stockpile - Clear Sysmon logs [intended to trigger CAR-2016-04-002]': {'description': 'Clear '
                                                                                               'Sysmon '
                                                                                               'logs '
                                                                                               '[intended '
                                                                                               'to '
                                                                                               'trigger '
                                                                                               'CAR-2016-04-002]',
                                                                                'id': 'fcf71ee3-d1a9-4136-b919-9e5f6da43608',
                                                                                'name': 'Clear '
                                                                                        'Logs',
                                                                                'platforms': {'windows': {'psh,pwsh': {'command': 'Clear-Eventlog '
                                                                                                                                  'Security;\n'
                                                                                                                                  'Clear-Eventlog '
                                                                                                                                  'System;\n'}}},
                                                                                'privilege': 'Elevated',
                                                                                'tactic': 'defense-evasion',
                                                                                'technique': {'attack_id': 'T1070',
                                                                                              'name': 'Indicator '
                                                                                                      'Removal '
                                                                                                      'on '
                                                                                                      'Host'}}},
 {'Threat Hunting Tables': {'chain_id': '100034',
                            'commandline_string': 'usn deletejournal /D',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': 'https://www.joesecurity.org/reports/report-71b6a493388e7d0b40c83ce903bc6b04.html#overview',
                            'loaded_dll': '',
                            'mitre_attack': 'T1070',
                            'mitre_caption': 'indicator_removal',
                            'os': 'windows',
                            'parent_process': 'fsutil.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100083',
                            'commandline_string': 'delete shadows /all /quiet',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '51bf86b51ec3a3bf21bc9a9ea7c00f2599efafda93535c2d7e92dd1d07380332',
                            'loaded_dll': '',
                            'mitre_attack': 'T1070',
                            'mitre_caption': 'indicator_removal',
                            'os': 'windows',
                            'parent_process': 'vssadmin.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100084',
                            'commandline_string': 'delete catalog -quiet',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1070',
                            'mitre_caption': 'indicator_removal',
                            'os': 'windows',
                            'parent_process': 'wbadmin.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100085',
                            'commandline_string': '/cl',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': 'https://www.joesecurity.org/reports/report-fbbdc39af1139aebba4da004475e8839.html',
                            'loaded_dll': '',
                            'mitre_attack': 'T1070',
                            'mitre_caption': 'indicator_removal',
                            'os': 'windows',
                            'parent_process': 'wevtutil.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100101',
                            'commandline_string': '/NODE:*shadowcopy delete *',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1070',
                            'mitre_caption': 'indicator_removal',
                            'os': 'windows',
                            'parent_process': 'wmic.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'SysmonHunter - T1070': {'description': None,
                           'level': 'high',
                           'name': 'Indicator Removal on Host',
                           'phase': 'Defense Evasion',
                           'query': [{'process': {'cmdline': {'pattern': 'cl'},
                                                  'image': {'pattern': 'wevtutil'}},
                                      'type': 'process'},
                                     {'process': {'cmdline': {'op': 'and',
                                                              'pattern': 'wevtutil|cl'}},
                                      'type': 'process'},
                                     {'process': {'cmdline': {'op': 'and',
                                                              'pattern': 'fsutil|usn|deletejournal'}},
                                      'type': 'process'},
                                     {'process': {'cmdline': {'op': 'and',
                                                              'pattern': 'usn|deletejournal'},
                                                  'image': {'pattern': 'fsutil'}},
                                      'type': 'process'}]}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1070',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/purge":  '
                                                                                 '["T1070"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/purge',
                                            'Technique': 'Indicator Removal on '
                                                         'Host'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1070',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/lock":  '
                                                                                 '["T1070"],',
                                            'Empire Module': 'powershell/management/lock',
                                            'Technique': 'Indicator Removal on '
                                                         'Host'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1070',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/logoff":  '
                                                                                 '["T1070"],',
                                            'Empire Module': 'powershell/management/logoff',
                                            'Technique': 'Indicator Removal on '
                                                         'Host'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1070',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/restart":  '
                                                                                 '["T1070"],',
                                            'Empire Module': 'powershell/management/restart',
                                            'Technique': 'Indicator Removal on '
                                                         'Host'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1070',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/persistence/osx/RemoveDaemon":  '
                                                                                 '["T1070"],',
                                            'Empire Module': 'python/persistence/osx/RemoveDaemon',
                                            'Technique': 'Indicator Removal on '
                                                         'Host'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Indicator Removal on Host Mitigation](../mitigations/Indicator-Removal-on-Host-Mitigation.md)

* [Remote Data Storage](../mitigations/Remote-Data-Storage.md)
    
* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)
    
* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    

# Actors

None
