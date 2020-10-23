
# Data from Local System

## Description

### MITRE Description

> Adversaries may search local system sources, such as file systems or local databases, to find files of interest and sensitive data prior to Exfiltration.

Adversaries may do this using a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), such as [cmd](https://attack.mitre.org/software/S0106), which has functionality to interact with the file system to gather information. Some adversaries may also use [Automated Collection](https://attack.mitre.org/techniques/T1119) on the local system.


## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1005

## Potential Commands

```
pip install -q stormssh 2> /dev/null && storm list | sed 's/\x1b\[[0-9;]*m//g'
pip install stormssh && storm list
find $(echo ~#{host.user.name}) -type f -size -500k -maxdepth 5 -exec grep -EIr -o "\b[A-Za-z0-9._%+-]+@#{target.org.name}\b" 2>/dev/null {} \;
curl #{remote.host.socket}
Get-ChildItem C:\Users -Recurse -Include *.#{file.sensitive.extension} -ErrorAction 'SilentlyContinue' | foreach {$_.FullName} | Select-Object -first 5;
exit 0;
find / -name '*.#{file.sensitive.extension}' -type f -not -path '*/\.*' -size -500k 2>/dev/null | head -5
find /Users -name '*.#{file.sensitive.extension}' -type f -not -path '*/\.*' -size -500k 2>/dev/null | head -5
find $(echo ~#{host.user.name}) -type f -size -500k -maxdepth 5 -exec grep -EIr -o "(($(echo #{domain.broadcast.ip} | cut -d. -f-2))\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" 2>/dev/null {} \;
powershell/collection/get_sql_column_sample_data
powershell/collection/get_sql_query
powershell/collection/minidump
powershell/credentials/sessiongopher
python/collection/osx/browser_dump
python/collection/osx/imessage_dump
python/situational_awareness/host/osx/situational_awareness
```

## Commands Dataset

```
[{'command': 'pip install stormssh && storm list\n',
  'name': 'Search for valid SSH commands in the config file',
  'source': 'data/abilities/collection/02de522f-7e0a-4544-8afc-0c195f400f5f.yml'},
 {'command': 'pip install -q stormssh 2> /dev/null && storm list | sed '
             "'s/\\x1b\\[[0-9;]*m//g'\n",
  'name': 'Search for valid SSH commands in the config file',
  'source': 'data/abilities/collection/02de522f-7e0a-4544-8afc-0c195f400f5f.yml'},
 {'command': 'find $(echo ~#{host.user.name}) -type f -size -500k -maxdepth 5 '
             '-exec grep -EIr -o "\\b[A-Za-z0-9._%+-]+@#{target.org.name}\\b" '
             '2>/dev/null {} \\;\n',
  'name': 'Grep for all emails for the given target company',
  'source': 'data/abilities/collection/1f7ff232-ebf8-42bf-a3c4-657855794cfe.yml'},
 {'command': 'curl #{remote.host.socket}\n',
  'name': 'See the raw content of a socket',
  'source': 'data/abilities/collection/89955f55-529d-4d58-bed4-fed9e42515ec.yml'},
 {'command': 'curl #{remote.host.socket}\n',
  'name': 'See the raw content of a socket',
  'source': 'data/abilities/collection/89955f55-529d-4d58-bed4-fed9e42515ec.yml'},
 {'command': "find /Users -name '*.#{file.sensitive.extension}' -type f -not "
             "-path '*/\\.*' -size -500k 2>/dev/null | head -5\n",
  'name': 'Locate files deemed sensitive',
  'source': 'data/abilities/collection/90c2efaa-8205-480d-8bb6-61d90dbaf81b.yml'},
 {'command': 'Get-ChildItem C:\\Users -Recurse -Include '
             "*.#{file.sensitive.extension} -ErrorAction 'SilentlyContinue' | "
             'foreach {$_.FullName} | Select-Object -first 5;\n'
             'exit 0;\n',
  'name': 'Locate files deemed sensitive',
  'source': 'data/abilities/collection/90c2efaa-8205-480d-8bb6-61d90dbaf81b.yml'},
 {'command': "find / -name '*.#{file.sensitive.extension}' -type f -not -path "
             "'*/\\.*' -size -500k 2>/dev/null | head -5\n",
  'name': 'Locate files deemed sensitive',
  'source': 'data/abilities/collection/90c2efaa-8205-480d-8bb6-61d90dbaf81b.yml'},
 {'command': 'find $(echo ~#{host.user.name}) -type f -size -500k -maxdepth 5 '
             '-exec grep -EIr -o "(($(echo #{domain.broadcast.ip} | cut -d. '
             '-f-2))\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" '
             '2>/dev/null {} \\;\n',
  'name': 'Grep for IP addresses in file system per user',
  'source': 'data/abilities/collection/d69e8660-62c9-431e-87eb-8cf6bd4e35cf.yml'},
 {'command': 'powershell/collection/get_sql_column_sample_data',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/get_sql_column_sample_data',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/get_sql_query',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/get_sql_query',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/minidump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/minidump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/sessiongopher',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/sessiongopher',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/browser_dump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/browser_dump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/imessage_dump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/imessage_dump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/host/osx/situational_awareness',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/host/osx/situational_awareness',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['200-500', ' 4100-4104', 'PowerShell logs']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['5861', 'WMI']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['200-500', ' 4100-4104', 'PowerShell logs']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['5861', 'WMI']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - Search for valid SSH commands in the config file': {'description': 'Search '
                                                                                        'for '
                                                                                        'valid '
                                                                                        'SSH '
                                                                                        'commands '
                                                                                        'in '
                                                                                        'the '
                                                                                        'config '
                                                                                        'file',
                                                                         'id': '02de522f-7e0a-4544-8afc-0c195f400f5f',
                                                                         'name': 'Parse '
                                                                                 'SSH '
                                                                                 'config',
                                                                         'platforms': {'darwin': {'sh': {'command': 'pip '
                                                                                                                    'install '
                                                                                                                    'stormssh '
                                                                                                                    '&& '
                                                                                                                    'storm '
                                                                                                                    'list\n',
                                                                                                         'parsers': {'plugins.stockpile.app.parsers.ssh': [{'source': 'remote.ssh.cmd'}]}}},
                                                                                       'linux': {'sh': {'command': 'pip '
                                                                                                                   'install '
                                                                                                                   '-q '
                                                                                                                   'stormssh '
                                                                                                                   '2> '
                                                                                                                   '/dev/null '
                                                                                                                   '&& '
                                                                                                                   'storm '
                                                                                                                   'list '
                                                                                                                   '| '
                                                                                                                   'sed '
                                                                                                                   "'s/\\x1b\\[[0-9;]*m//g'\n",
                                                                                                        'parsers': {'plugins.stockpile.app.parsers.ssh': [{'source': 'remote.ssh.cmd'}]}}}},
                                                                         'tactic': 'collection',
                                                                         'technique': {'attack_id': 'T1005',
                                                                                       'name': 'Data '
                                                                                               'from '
                                                                                               'Local '
                                                                                               'System'}}},
 {'Mitre Stockpile - Grep for all emails for the given target company': {'description': 'Grep '
                                                                                        'for '
                                                                                        'all '
                                                                                        'emails '
                                                                                        'for '
                                                                                        'the '
                                                                                        'given '
                                                                                        'target '
                                                                                        'company',
                                                                         'id': '1f7ff232-ebf8-42bf-a3c4-657855794cfe',
                                                                         'name': 'Find '
                                                                                 'company '
                                                                                 'emails',
                                                                         'platforms': {'darwin': {'sh': {'command': 'find '
                                                                                                                    '$(echo '
                                                                                                                    '~#{host.user.name}) '
                                                                                                                    '-type '
                                                                                                                    'f '
                                                                                                                    '-size '
                                                                                                                    '-500k '
                                                                                                                    '-maxdepth '
                                                                                                                    '5 '
                                                                                                                    '-exec '
                                                                                                                    'grep '
                                                                                                                    '-EIr '
                                                                                                                    '-o '
                                                                                                                    '"\\b[A-Za-z0-9._%+-]+@#{target.org.name}\\b" '
                                                                                                                    '2>/dev/null '
                                                                                                                    '{} '
                                                                                                                    '\\;\n'}}},
                                                                         'requirements': [{'plugins.stockpile.app.requirements.paw_provenance': [{'source': 'host.user.name'}]}],
                                                                         'tactic': 'collection',
                                                                         'technique': {'attack_id': 'T1005',
                                                                                       'name': 'Data '
                                                                                               'from '
                                                                                               'Local '
                                                                                               'System'}}},
 {'Mitre Stockpile - See the raw content of a socket': {'description': 'See '
                                                                       'the '
                                                                       'raw '
                                                                       'content '
                                                                       'of a '
                                                                       'socket',
                                                        'id': '89955f55-529d-4d58-bed4-fed9e42515ec',
                                                        'name': 'cURL socket '
                                                                'address',
                                                        'platforms': {'darwin': {'sh': {'command': 'curl '
                                                                                                   '#{remote.host.socket}\n'}},
                                                                      'linux': {'sh': {'command': 'curl '
                                                                                                  '#{remote.host.socket}\n'}}},
                                                        'tactic': 'collection',
                                                        'technique': {'attack_id': 'T1005',
                                                                      'name': 'Data '
                                                                              'from '
                                                                              'Local '
                                                                              'System'}}},
 {'Mitre Stockpile - Locate files deemed sensitive': {'description': 'Locate '
                                                                     'files '
                                                                     'deemed '
                                                                     'sensitive',
                                                      'id': '90c2efaa-8205-480d-8bb6-61d90dbaf81b',
                                                      'name': 'Find files',
                                                      'platforms': {'darwin': {'sh': {'command': 'find '
                                                                                                 '/Users '
                                                                                                 '-name '
                                                                                                 "'*.#{file.sensitive.extension}' "
                                                                                                 '-type '
                                                                                                 'f '
                                                                                                 '-not '
                                                                                                 '-path '
                                                                                                 "'*/\\.*' "
                                                                                                 '-size '
                                                                                                 '-500k '
                                                                                                 '2>/dev/null '
                                                                                                 '| '
                                                                                                 'head '
                                                                                                 '-5\n',
                                                                                      'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.file.path'}]}}},
                                                                    'linux': {'sh': {'command': 'find '
                                                                                                '/ '
                                                                                                '-name '
                                                                                                "'*.#{file.sensitive.extension}' "
                                                                                                '-type '
                                                                                                'f '
                                                                                                '-not '
                                                                                                '-path '
                                                                                                "'*/\\.*' "
                                                                                                '-size '
                                                                                                '-500k '
                                                                                                '2>/dev/null '
                                                                                                '| '
                                                                                                'head '
                                                                                                '-5\n',
                                                                                     'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.file.path'}]}}},
                                                                    'windows': {'psh,pwsh': {'command': 'Get-ChildItem '
                                                                                                        'C:\\Users '
                                                                                                        '-Recurse '
                                                                                                        '-Include '
                                                                                                        '*.#{file.sensitive.extension} '
                                                                                                        '-ErrorAction '
                                                                                                        "'SilentlyContinue' "
                                                                                                        '| '
                                                                                                        'foreach '
                                                                                                        '{$_.FullName} '
                                                                                                        '| '
                                                                                                        'Select-Object '
                                                                                                        '-first '
                                                                                                        '5;\n'
                                                                                                        'exit '
                                                                                                        '0;\n',
                                                                                             'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'host.file.path'}]}}}},
                                                      'tactic': 'collection',
                                                      'technique': {'attack_id': 'T1005',
                                                                    'name': 'Data '
                                                                            'from '
                                                                            'Local '
                                                                            'System'}}},
 {'Mitre Stockpile - Grep for IP addresses in file system per user': {'description': 'Grep '
                                                                                     'for '
                                                                                     'IP '
                                                                                     'addresses '
                                                                                     'in '
                                                                                     'file '
                                                                                     'system '
                                                                                     'per '
                                                                                     'user',
                                                                      'id': 'd69e8660-62c9-431e-87eb-8cf6bd4e35cf',
                                                                      'name': 'Find '
                                                                              'IP '
                                                                              'addresses',
                                                                      'platforms': {'darwin': {'sh': {'command': 'find '
                                                                                                                 '$(echo '
                                                                                                                 '~#{host.user.name}) '
                                                                                                                 '-type '
                                                                                                                 'f '
                                                                                                                 '-size '
                                                                                                                 '-500k '
                                                                                                                 '-maxdepth '
                                                                                                                 '5 '
                                                                                                                 '-exec '
                                                                                                                 'grep '
                                                                                                                 '-EIr '
                                                                                                                 '-o '
                                                                                                                 '"(($(echo '
                                                                                                                 '#{domain.broadcast.ip} '
                                                                                                                 '| '
                                                                                                                 'cut '
                                                                                                                 '-d. '
                                                                                                                 '-f-2))\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" '
                                                                                                                 '2>/dev/null '
                                                                                                                 '{} '
                                                                                                                 '\\;\n'}}},
                                                                      'requirements': [{'plugins.stockpile.app.requirements.paw_provenance': [{'source': 'host.user.name'}]}],
                                                                      'tactic': 'collection',
                                                                      'technique': {'attack_id': 'T1005',
                                                                                    'name': 'Data '
                                                                                            'from '
                                                                                            'Local '
                                                                                            'System'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1005',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/get_sql_column_sample_data":  '
                                                                                 '["T1005"],',
                                            'Empire Module': 'powershell/collection/get_sql_column_sample_data',
                                            'Technique': 'Data from Local '
                                                         'System'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1005',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/get_sql_query":  '
                                                                                 '["T1005"],',
                                            'Empire Module': 'powershell/collection/get_sql_query',
                                            'Technique': 'Data from Local '
                                                         'System'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1005',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/minidump":  '
                                                                                 '["T1005"],',
                                            'Empire Module': 'powershell/collection/minidump',
                                            'Technique': 'Data from Local '
                                                         'System'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1005',
                                            'ATT&CK Technique #2': 'T1145',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/sessiongopher":  '
                                                                                 '["T1005","T1145"],',
                                            'Empire Module': 'powershell/credentials/sessiongopher',
                                            'Technique': 'Data from Local '
                                                         'System'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1005',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/browser_dump":  '
                                                                                 '["T1005"],',
                                            'Empire Module': 'python/collection/osx/browser_dump',
                                            'Technique': 'Data from Local '
                                                         'System'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1005',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/imessage_dump":  '
                                                                                 '["T1005"],',
                                            'Empire Module': 'python/collection/osx/imessage_dump',
                                            'Technique': 'Data from Local '
                                                         'System'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1005',
                                            'ATT&CK Technique #2': 'T1082',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/host/osx/situational_awareness":  '
                                                                                 '["T1005","T1082"],',
                                            'Empire Module': 'python/situational_awareness/host/osx/situational_awareness',
                                            'Technique': 'Data from Local '
                                                         'System'}}]
```

# Tactics


* [Collection](../tactics/Collection.md)


# Mitigations


* [Data from Local System Mitigation](../mitigations/Data-from-Local-System-Mitigation.md)


# Actors


* [Ke3chang](../actors/Ke3chang.md)

* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [APT37](../actors/APT37.md)
    
* [APT3](../actors/APT3.md)
    
* [APT1](../actors/APT1.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Dust Storm](../actors/Dust-Storm.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Dark Caracal](../actors/Dark-Caracal.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [APT28](../actors/APT28.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Turla](../actors/Turla.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [Inception](../actors/Inception.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
* [APT39](../actors/APT39.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
