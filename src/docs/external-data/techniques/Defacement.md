
# Defacement

## Description

### MITRE Description

> Adversaries may modify visual content available internally or externally to an enterprise network. Reasons for Defacement include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion. 

### Internal
An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users. This may take the form of modifications to internal websites, or directly to user systems with the replacement of the desktop wallpaper.(Citation: Novetta Blockbuster) Disturbing or offensive images may be used as a part of Defacement in order to cause user discomfort, or to pressure compliance with accompanying messages. While internally defacing systems exposes an adversary's presence, it often takes place after other intrusion goals have been accomplished.(Citation: Novetta Blockbuster Destructive Malware)

### External 
Websites are a common victim of defacement; often targeted by adversary and hacktivist groups in order to push a political message or spread propaganda.(Citation: FireEye Cyber Threats to Media Industries)(Citation: Kevin Mandia Statement to US Senate Committee on Intelligence)(Citation: Anonymous Hackers Deface Russian Govt Site) Defacement may be used as a catalyst to trigger events, or as a response to actions taken by an organization or government. Similarly, website defacement may also be used as setup, or a precursor, for future attacks such as [Drive-by Compromise](https://attack.mitre.org/techniques/T1189).(Citation: Trend Micro Deep Dive Into Defacement)


## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1491

## Potential Commands

```
{'darwin': {'osa': {'command': 'quit app "Microsoft Outlook.app"'}}}
{'darwin': {'sh': {'command': 'echo "proof that this machine was hacked." > message.txt\n'}}, 'linux': {'sh': {'command': 'echo "proof that this machine was hacked." > message.txt\n'}}, 'windows': {'psh': {'command': "Set-Content -Path 'message.txt' -Value 'proof that this machine was hacked.'\n"}}}
{'windows': {'psh,pwsh': {'command': '.\\Invoke-MemeKatz.ps1\n', 'payloads': ['Invoke-MemeKatz.ps1']}, 'cmd': {'command': 'powershell.exe -ep bypass -c "Invoke-MemeKatz.ps1"\n', 'payloads': ['Invoke-MemeKatz.ps1']}}}
```

## Commands Dataset

```
[{'command': {'darwin': {'osa': {'command': 'quit app "Microsoft '
                                            'Outlook.app"'}}},
  'name': 'Quit Outlook',
  'source': 'data/abilities/impact/3b007f46-23e7-4a11-9c14-e7085b6a754a.yml'},
 {'command': {'darwin': {'sh': {'command': 'echo "proof that this machine was '
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
[{'Mitre Stockpile - Quit Outlook': {'description': 'Quit Outlook',
                                     'id': '3b007f46-23e7-4a11-9c14-e7085b6a754a',
                                     'name': 'Quit Outlook',
                                     'platforms': {'darwin': {'osa': {'command': 'quit '
                                                                                 'app '
                                                                                 '"Microsoft '
                                                                                 'Outlook.app"'}}},
                                     'tactic': 'impact',
                                     'technique': {'attack_id': 'T1491',
                                                   'name': 'Service Stop'}}},
 {'Mitre Stockpile - Create a text file for the user to find': {'description': 'Create '
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

None

# Actors

None
