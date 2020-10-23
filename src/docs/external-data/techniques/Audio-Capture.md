
# Audio Capture

## Description

### MITRE Description

> An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.

Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture audio. Audio files may be written to disk and exfiltrated later.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1123

## Potential Commands

```
powershell.exe -Command WindowsAudioDevice-Powershell-Cmdlet
python/collection/osx/osx_mic_record
```

## Commands Dataset

```
[{'command': 'powershell.exe -Command WindowsAudioDevice-Powershell-Cmdlet\n',
  'name': None,
  'source': 'atomics/T1123/T1123.yaml'},
 {'command': 'python/collection/osx/osx_mic_record',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/osx_mic_record',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['API monitoring']}]
```

## Potential Queries

```json
[{'name': 'Audio Capture',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_path contains '
           '"SoundRecorder.exe"or process_command_line contains '
           '"*Get-AudioDevice*"or process_command_line contains '
           '"*WindowsAudioDevice-Powershell-Cmdlet*")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Audio Capture': {'atomic_tests': [{'auto_generated_guid': '9c3ad250-b185-4444-b5a9-d69218a10c95',
                                                             'description': '[AudioDeviceCmdlets](https://github.com/cdhunt/WindowsAudioDevice-Powershell-Cmdlet)\n',
                                                             'executor': {'command': 'powershell.exe '
                                                                                     '-Command '
                                                                                     'WindowsAudioDevice-Powershell-Cmdlet\n',
                                                                          'name': 'powershell'},
                                                             'name': 'using '
                                                                     'device '
                                                                     'audio '
                                                                     'capture '
                                                                     'commandlet',
                                                             'supported_platforms': ['windows']}],
                                           'attack_technique': 'T1123',
                                           'display_name': 'Audio Capture'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1123',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/osx_mic_record":  '
                                                                                 '["T1123"],',
                                            'Empire Module': 'python/collection/osx/osx_mic_record',
                                            'Technique': 'Audio Capture'}}]
```

# Tactics


* [Collection](../tactics/Collection.md)


# Mitigations


* [Audio Capture Mitigation](../mitigations/Audio-Capture-Mitigation.md)


# Actors


* [APT37](../actors/APT37.md)

