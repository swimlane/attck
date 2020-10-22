
# Input Capture

## Description

### MITRE Description

> Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004)) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. [Web Portal Capture](https://attack.mitre.org/techniques/T1056/003)).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM', 'root', 'User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1056

## Potential Commands

```
starting the keylogger:
keylogger {x86|x64} {pid}
when you're ready to view logs:
view -> keylog
when you're done keylogging:
jobs
jobkill {job id number}
starting the keylogger:
keyscan_start
when you're ready to get the logs:
keyscan_dump
when you're done keylogging:
keyscan_stop
powershell.exe Get-Keystrokes -LogPath C:\key.log
powershell/collection/USBKeylogger
powershell/collection/USBKeylogger
powershell/collection/keylogger
powershell/collection/keylogger
python/collection/linux/keylogger
python/collection/linux/keylogger
python/collection/linux/xkeylogger
python/collection/linux/xkeylogger
python/collection/osx/keylogger
python/collection/osx/keylogger
```

## Commands Dataset

```
[{'command': 'starting the keylogger:\n'
             'keylogger {x86|x64} {pid}\n'
             "when you're ready to view logs:\n"
             'view -> keylog\n'
             "when you're done keylogging:\n"
             'jobs\n'
             'jobkill {job id number}',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'starting the keylogger:\n'
             'keyscan_start\n'
             "when you're ready to get the logs:\n"
             'keyscan_dump\n'
             "when you're done keylogging:\n"
             'keyscan_stop',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'powershell.exe Get-Keystrokes -LogPath C:\\key.log',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell/collection/USBKeylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/USBKeylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/keylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/keylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/keylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/keylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/xkeylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/linux/xkeylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/keylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/keylogger',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Kernel drivers']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Kernel drivers']},
 {'data_source': ['API monitoring']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': '',
                                                  'Category': 'T1056',
                                                  'Cobalt Strike': 'starting '
                                                                   'the '
                                                                   'keylogger:\n'
                                                                   'keylogger '
                                                                   '{x86|x64} '
                                                                   '{pid}\n'
                                                                   'when '
                                                                   "you're "
                                                                   'ready to '
                                                                   'view '
                                                                   'logs:\n'
                                                                   'view -> '
                                                                   'keylog\n'
                                                                   'when '
                                                                   "you're "
                                                                   'done '
                                                                   'keylogging:\n'
                                                                   'jobs\n'
                                                                   'jobkill '
                                                                   '{job id '
                                                                   'number}',
                                                  'Description': 'Keylogging '
                                                                 'is extremely '
                                                                 'useful to '
                                                                 'get '
                                                                 'credentials '
                                                                 'and other '
                                                                 'information '
                                                                 'from the '
                                                                 'victim, but '
                                                                 'make sure '
                                                                 'that you are '
                                                                 'keylogging '
                                                                 'in a process '
                                                                 'belonging to '
                                                                 'the user you '
                                                                 'want to spy '
                                                                 'on. '
                                                                 'Keylogging '
                                                                 'within a '
                                                                 'SYSTEM '
                                                                 'process will '
                                                                 'not get you '
                                                                 'the '
                                                                 'keystrokes '
                                                                 'of other '
                                                                 'users on the '
                                                                 'system. For '
                                                                 'Cobalt '
                                                                 'Strike, make '
                                                                 'sure you '
                                                                 'specifiy the '
                                                                 'correct '
                                                                 'architecture '
                                                                 'and PID for '
                                                                 'a process '
                                                                 'running as '
                                                                 'the target '
                                                                 'victim. For '
                                                                 'Metasploit, '
                                                                 'make sure '
                                                                 "you've "
                                                                 'migrated to '
                                                                 'a process '
                                                                 'that is '
                                                                 'running as '
                                                                 'the target '
                                                                 'victim '
                                                                 '(explore.exe '
                                                                 'is always '
                                                                 'good).',
                                                  'Metasploit': 'starting the '
                                                                'keylogger:\n'
                                                                'keyscan_start\n'
                                                                "when you're "
                                                                'ready to get '
                                                                'the logs:\n'
                                                                'keyscan_dump\n'
                                                                "when you're "
                                                                'done '
                                                                'keylogging:\n'
                                                                'keyscan_stop'}},
 {'Threat Hunting Tables': {'chain_id': '100132',
                            'commandline_string': 'Get-Keystrokes -LogPath '
                                                  'C:\\key.log',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1056',
                            'mitre_caption': 'input_capture',
                            'os': 'windows',
                            'parent_process': 'powershell.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1056',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/USBKeylogger":  '
                                                                                 '["T1056"],',
                                            'Empire Module': 'powershell/collection/USBKeylogger',
                                            'Technique': 'Input Capture'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1056',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/keylogger":  '
                                                                                 '["T1056"],',
                                            'Empire Module': 'powershell/collection/keylogger',
                                            'Technique': 'Input Capture'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1056',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/linux/keylogger":  '
                                                                                 '["T1056"],',
                                            'Empire Module': 'python/collection/linux/keylogger',
                                            'Technique': 'Input Capture'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1056',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/linux/xkeylogger":  '
                                                                                 '["T1056"],',
                                            'Empire Module': 'python/collection/linux/xkeylogger',
                                            'Technique': 'Input Capture'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1056',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/keylogger":  '
                                                                                 '["T1056"],',
                                            'Empire Module': 'python/collection/osx/keylogger',
                                            'Technique': 'Input Capture'}}]
```

# Tactics


* [Collection](../tactics/Collection.md)

* [Credential Access](../tactics/Credential-Access.md)
    

# Mitigations

None

# Actors

None
