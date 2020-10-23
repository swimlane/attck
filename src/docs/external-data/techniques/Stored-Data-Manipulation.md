
# Stored Data Manipulation

## Description

### MITRE Description

> Adversaries may insert, delete, or manipulate data at rest in order to manipulate external outcomes or hide activity.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony 2018) By manipulating stored data, adversaries may attempt to affect a business process, organizational understanding, and decision making.

Stored data could include a variety of file formats, such as Office files, databases, stored emails, and custom file formats. The type of modification and the impact it will have depends on the type of data as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

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
* Wiki: https://attack.mitre.org/techniques/T1565/001

## Potential Commands

```
mv mission.go mission.exe;.\mission.exe -duration 60 -extension .caldera -dir 'C:\';
copy mission.go mission.exe &&mission.exe -duration 60 -extension .caldera -dir C:\
./mission.go -duration 60 -extension .caldera -dir '/'
```

## Commands Dataset

```
[{'command': "./mission.go -duration 60 -extension .caldera -dir '/'",
  'name': 'Hunts for files of a certain extension and inserts a message',
  'source': 'data/abilities/impact/55f9600a-756f-496b-b27f-682052dc429c.yml'},
 {'command': "./mission.go -duration 60 -extension .caldera -dir '/'",
  'name': 'Hunts for files of a certain extension and inserts a message',
  'source': 'data/abilities/impact/55f9600a-756f-496b-b27f-682052dc429c.yml'},
 {'command': 'copy mission.go mission.exe &&mission.exe -duration 60 '
             '-extension .caldera -dir C:\\',
  'name': 'Hunts for files of a certain extension and inserts a message',
  'source': 'data/abilities/impact/55f9600a-756f-496b-b27f-682052dc429c.yml'},
 {'command': 'mv mission.go mission.exe;.\\mission.exe -duration 60 -extension '
             ".caldera -dir 'C:\\';",
  'name': 'Hunts for files of a certain extension and inserts a message',
  'source': 'data/abilities/impact/55f9600a-756f-496b-b27f-682052dc429c.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - Hunts for files of a certain extension and inserts a message': {'description': 'Hunts '
                                                                                                    'for '
                                                                                                    'files '
                                                                                                    'of '
                                                                                                    'a '
                                                                                                    'certain '
                                                                                                    'extension '
                                                                                                    'and '
                                                                                                    'inserts '
                                                                                                    'a '
                                                                                                    'message',
                                                                                     'id': '55f9600a-756f-496b-b27f-682052dc429c',
                                                                                     'name': 'File '
                                                                                             'Hunter '
                                                                                             'Mission',
                                                                                     'platforms': {'darwin': {'sh': {'command': './mission.go '
                                                                                                                                '-duration '
                                                                                                                                '60 '
                                                                                                                                '-extension '
                                                                                                                                '.caldera '
                                                                                                                                '-dir '
                                                                                                                                "'/'",
                                                                                                                     'payloads': ['mission.go']}},
                                                                                                   'linux': {'sh': {'command': './mission.go '
                                                                                                                               '-duration '
                                                                                                                               '60 '
                                                                                                                               '-extension '
                                                                                                                               '.caldera '
                                                                                                                               '-dir '
                                                                                                                               "'/'",
                                                                                                                    'payloads': ['mission.go']}},
                                                                                                   'windows': {'cmd': {'command': 'copy '
                                                                                                                                  'mission.go '
                                                                                                                                  'mission.exe '
                                                                                                                                  '&&mission.exe '
                                                                                                                                  '-duration '
                                                                                                                                  '60 '
                                                                                                                                  '-extension '
                                                                                                                                  '.caldera '
                                                                                                                                  '-dir '
                                                                                                                                  'C:\\',
                                                                                                                       'payloads': ['mission.go']},
                                                                                                               'psh': {'command': 'mv '
                                                                                                                                  'mission.go '
                                                                                                                                  'mission.exe;.\\mission.exe '
                                                                                                                                  '-duration '
                                                                                                                                  '60 '
                                                                                                                                  '-extension '
                                                                                                                                  '.caldera '
                                                                                                                                  '-dir '
                                                                                                                                  "'C:\\';",
                                                                                                                       'payloads': ['mission.go']}}},
                                                                                     'tactic': 'impact',
                                                                                     'technique': {'attack_id': 'T1565.001',
                                                                                                   'name': 'Data '
                                                                                                           'Manipulation: '
                                                                                                           'Stored '
                                                                                                           'Data '
                                                                                                           'Manipulation'}}}]
```

# Tactics


* [Impact](../tactics/Impact.md)


# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)

* [Remote Data Storage](../mitigations/Remote-Data-Storage.md)
    
* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)
    

# Actors


* [APT38](../actors/APT38.md)

* [FIN4](../actors/FIN4.md)
    
