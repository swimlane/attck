
# Clipboard Data

## Description

### MITRE Description

> Adversaries may collect data stored in the clipboard from users copying information within or between applications. 

In Windows, Applications can access clipboard data by using the Windows API.(Citation: MSDN Clipboard) OSX provides a native command, <code>pbpaste</code>, to grab clipboard contents.(Citation: Operating with EmPyre)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1115

## Potential Commands

```
dir | clip
echo "T1115" > %temp%\T1115.txt
clip < %temp%\T1115.txt

echo Get-Process | clip
Get-Clipboard | iex

echo ifconfig | pbcopy
$(pbpaste)
{'darwin': {'sh': {'command': 'pbpaste\n'}}, 'windows': {'psh,pwsh': {'command': 'Get-Clipboard -raw\n'}}, 'linux': {'sh': {'command': 'xclip -o\n'}}}
cmd.exe <command> | clip
cmd.exe clip < readme.txt
powershell.exe echo Get-Process | clip
powershell.exe echo Get-Process | clip
powershell/collection/clipboard_monitor
powershell/collection/clipboard_monitor
python/collection/osx/clipboard
python/collection/osx/clipboard
```

## Commands Dataset

```
[{'command': 'dir | clip\n'
             'echo "T1115" > %temp%\\T1115.txt\n'
             'clip < %temp%\\T1115.txt\n',
  'name': None,
  'source': 'atomics/T1115/T1115.yaml'},
 {'command': 'echo Get-Process | clip\nGet-Clipboard | iex\n',
  'name': None,
  'source': 'atomics/T1115/T1115.yaml'},
 {'command': 'echo ifconfig | pbcopy\n$(pbpaste)',
  'name': None,
  'source': 'atomics/T1115/T1115.yaml'},
 {'command': {'darwin': {'sh': {'command': 'pbpaste\n'}},
              'linux': {'sh': {'command': 'xclip -o\n'}},
              'windows': {'psh,pwsh': {'command': 'Get-Clipboard -raw\n'}}},
  'name': 'copy the contents for the clipboard and print them',
  'source': 'data/abilities/collection/b007fe0c-c6b0-4fda-915c-255bbc070de2.yml'},
 {'command': 'cmd.exe <command> | clip',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe clip < readme.txt',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell.exe echo Get-Process | clip',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell.exe echo Get-Process | clip',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell/collection/clipboard_monitor',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/clipboard_monitor',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/clipboard',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/clipboard',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['API monitoring']}, {'data_source': ['API monitoring']}]
```

## Potential Queries

```json
[{'name': 'Clipboard Data',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains "clip.exe"or '
           'process_command_line contains "*Get-Clipboard*")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Clipboard Data': {'atomic_tests': [{'auto_generated_guid': '0cd14633-58d4-4422-9ede-daa2c9474ae7',
                                                              'description': 'Add '
                                                                             'data '
                                                                             'to '
                                                                             'clipboard '
                                                                             'to '
                                                                             'copy '
                                                                             'off '
                                                                             'or '
                                                                             'execute '
                                                                             'commands '
                                                                             'from.\n',
                                                              'executor': {'cleanup_command': 'del '
                                                                                              '%temp%\\T1115.txt '
                                                                                              '>nul '
                                                                                              '2>&1\n',
                                                                           'command': 'dir '
                                                                                      '| '
                                                                                      'clip\n'
                                                                                      'echo '
                                                                                      '"T1115" '
                                                                                      '> '
                                                                                      '%temp%\\T1115.txt\n'
                                                                                      'clip '
                                                                                      '< '
                                                                                      '%temp%\\T1115.txt\n',
                                                                           'name': 'command_prompt'},
                                                              'name': 'Utilize '
                                                                      'Clipboard '
                                                                      'to '
                                                                      'store '
                                                                      'or '
                                                                      'execute '
                                                                      'commands '
                                                                      'from',
                                                              'supported_platforms': ['windows']},
                                                             {'auto_generated_guid': 'd6dc21af-bec9-4152-be86-326b6babd416',
                                                              'description': 'Utilize '
                                                                             'PowerShell '
                                                                             'to '
                                                                             'echo '
                                                                             'a '
                                                                             'command '
                                                                             'to '
                                                                             'clipboard '
                                                                             'and '
                                                                             'execute '
                                                                             'it\n',
                                                              'executor': {'command': 'echo '
                                                                                      'Get-Process '
                                                                                      '| '
                                                                                      'clip\n'
                                                                                      'Get-Clipboard '
                                                                                      '| '
                                                                                      'iex\n',
                                                                           'name': 'powershell'},
                                                              'name': 'Execute '
                                                                      'Commands '
                                                                      'from '
                                                                      'Clipboard '
                                                                      'using '
                                                                      'PowerShell',
                                                              'supported_platforms': ['windows']},
                                                             {'auto_generated_guid': '1ac2247f-65f8-4051-b51f-b0ccdfaaa5ff',
                                                              'description': 'Echo '
                                                                             'a '
                                                                             'command '
                                                                             'to '
                                                                             'clipboard '
                                                                             'and '
                                                                             'execute '
                                                                             'it',
                                                              'executor': {'command': 'echo '
                                                                                      'ifconfig '
                                                                                      '| '
                                                                                      'pbcopy\n'
                                                                                      '$(pbpaste)',
                                                                           'name': 'bash'},
                                                              'name': 'Execute '
                                                                      'commands '
                                                                      'from '
                                                                      'clipboard',
                                                              'supported_platforms': ['macos']}],
                                            'attack_technique': 'T1115',
                                            'display_name': 'Clipboard Data'}},
 {'Mitre Stockpile - copy the contents for the clipboard and print them': {'description': 'copy '
                                                                                          'the '
                                                                                          'contents '
                                                                                          'for '
                                                                                          'the '
                                                                                          'clipboard '
                                                                                          'and '
                                                                                          'print '
                                                                                          'them',
                                                                           'id': 'b007fe0c-c6b0-4fda-915c-255bbc070de2',
                                                                           'name': 'Copy '
                                                                                   'Clipboard',
                                                                           'platforms': {'darwin': {'sh': {'command': 'pbpaste\n'}},
                                                                                         'linux': {'sh': {'command': 'xclip '
                                                                                                                     '-o\n'}},
                                                                                         'windows': {'psh,pwsh': {'command': 'Get-Clipboard '
                                                                                                                             '-raw\n'}}},
                                                                           'tactic': 'collection',
                                                                           'technique': {'attack_id': 'T1115',
                                                                                         'name': 'Clipboard '
                                                                                                 'Data'}}},
 {'Threat Hunting Tables': {'chain_id': '100128',
                            'commandline_string': '<command> | clip',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1115',
                            'mitre_caption': 'clipboard_data',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100129',
                            'commandline_string': 'clip < readme.txt',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1115',
                            'mitre_caption': 'clipboard_data',
                            'os': 'windows',
                            'parent_process': 'cmd.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100130',
                            'commandline_string': 'echo Get-Process | clip',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1115',
                            'mitre_caption': 'clipboard_data',
                            'os': 'windows',
                            'parent_process': 'powershell.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100131',
                            'commandline_string': 'echo Get-Process | clip',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1115',
                            'mitre_caption': 'clipboard_data',
                            'os': 'windows',
                            'parent_process': 'powershell.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1115',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/clipboard_monitor":  '
                                                                                 '["T1115"],',
                                            'Empire Module': 'powershell/collection/clipboard_monitor',
                                            'Technique': 'Clipboard Data'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1115',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/clipboard":  '
                                                                                 '["T1115"],',
                                            'Empire Module': 'python/collection/osx/clipboard',
                                            'Technique': 'Clipboard Data'}}]
```

# Tactics


* [Collection](../tactics/Collection.md)


# Mitigations


* [Clipboard Data Mitigation](../mitigations/Clipboard-Data-Mitigation.md)


# Actors


* [APT38](../actors/APT38.md)

* [APT39](../actors/APT39.md)
    
