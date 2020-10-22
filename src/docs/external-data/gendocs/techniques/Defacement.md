
# Defacement

## Description

### MITRE Description

> Adversaries may modify visual content available internally or externally to an enterprise network. Reasons for [Defacement](https://attack.mitre.org/techniques/T1491) include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion. Disturbing or offensive images may be used as a part of [Defacement](https://attack.mitre.org/techniques/T1491) in order to cause user discomfort, or to pressure compliance with accompanying messages. 


## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows', 'AWS', 'GCP', 'Azure']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1491

## Potential Commands

```
{'darwin': {'sh': {'command': 'echo "proof that this machine was hacked." > message.txt\n'}}, 'linux': {'sh': {'command': 'echo "proof that this machine was hacked." > message.txt\n'}}, 'windows': {'psh': {'command': "Set-Content -Path 'message.txt' -Value 'proof that this machine was hacked.'\n"}}}
{'windows': {'psh,pwsh': {'command': '.\\Invoke-MemeKatz.ps1\n', 'payloads': ['Invoke-MemeKatz.ps1']}, 'cmd': {'command': 'powershell.exe -ep bypass -c "Invoke-MemeKatz.ps1"\n', 'payloads': ['Invoke-MemeKatz.ps1']}}}
```

## Commands Dataset

```
[{'command': {'darwin': {'sh': {'command': 'echo "proof that this machine was '
                                           'hacked." > message.txt\n'}},
              'linux': {'sh': {'command': 'echo "proof that this machine was '
                                          'hacked." > message.txt\n'}},
              'windows': {'psh': {'command': "Set-Content -Path 'message.txt' "
                                             "-Value 'proof that this machine "
                                             "was hacked.'\n"}}},
  'name': 'Create a text file for the user to find',
  'source': 'data/abilities/impact/47d08617-5ce1-424a-8cc5-c9c978ce6bf9.yml'},
 {'command': {'windows': {'cmd': {'command': 'powershell.exe -ep bypass -c '
                                             '"Invoke-MemeKatz.ps1"\n',
                                  'payloads': ['Invoke-MemeKatz.ps1']},
                          'psh,pwsh': {'command': '.\\Invoke-MemeKatz.ps1\n',
                                       'payloads': ['Invoke-MemeKatz.ps1']}}},
  'name': 'Downloads random meme and sets as desktop background',
  'source': 'data/abilities/impact/68235976-2404-42a8-9105-68230cfef562.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - Create a text file for the user to find': {'description': 'Create '
                                                                               'a '
                                                                               'text '
                                                                               'file '
                                                                               'for '
                                                                               'the '
                                                                               'user '
                                                                               'to '
                                                                               'find',
                                                                'id': '47d08617-5ce1-424a-8cc5-c9c978ce6bf9',
                                                                'name': 'Leave '
                                                                        'note',
                                                                'platforms': {'darwin': {'sh': {'command': 'echo '
                                                                                                           '"proof '
                                                                                                           'that '
                                                                                                           'this '
                                                                                                           'machine '
                                                                                                           'was '
                                                                                                           'hacked." '
                                                                                                           '> '
                                                                                                           'message.txt\n'}},
                                                                              'linux': {'sh': {'command': 'echo '
                                                                                                          '"proof '
                                                                                                          'that '
                                                                                                          'this '
                                                                                                          'machine '
                                                                                                          'was '
                                                                                                          'hacked." '
                                                                                                          '> '
                                                                                                          'message.txt\n'}},
                                                                              'windows': {'psh': {'command': 'Set-Content '
                                                                                                             '-Path '
                                                                                                             "'message.txt' "
                                                                                                             '-Value '
                                                                                                             "'proof "
                                                                                                             'that '
                                                                                                             'this '
                                                                                                             'machine '
                                                                                                             'was '
                                                                                                             "hacked.'\n"}}},
                                                                'tactic': 'impact',
                                                                'technique': {'attack_id': 'T1491',
                                                                              'name': 'Defacement'}}},
 {'Mitre Stockpile - Downloads random meme and sets as desktop background': {'description': 'Downloads '
                                                                                            'random '
                                                                                            'meme '
                                                                                            'and '
                                                                                            'sets '
                                                                                            'as '
                                                                                            'desktop '
                                                                                            'background',
                                                                             'id': '68235976-2404-42a8-9105-68230cfef562',
                                                                             'name': 'Invoke-MemeKatz',
                                                                             'platforms': {'windows': {'cmd': {'command': 'powershell.exe '
                                                                                                                          '-ep '
                                                                                                                          'bypass '
                                                                                                                          '-c '
                                                                                                                          '"Invoke-MemeKatz.ps1"\n',
                                                                                                               'payloads': ['Invoke-MemeKatz.ps1']},
                                                                                                       'psh,pwsh': {'command': '.\\Invoke-MemeKatz.ps1\n',
                                                                                                                    'payloads': ['Invoke-MemeKatz.ps1']}}},
                                                                             'tactic': 'impact',
                                                                             'technique': {'attack_id': 'T1491',
                                                                                           'name': 'Defacement'}}}]
```

# Tactics


* [Impact](../tactics/Impact.md)


# Mitigations


* [Defacement Mitigation](../mitigations/Defacement-Mitigation.md)

* [Data Backup](../mitigations/Data-Backup.md)
    

# Actors

None
