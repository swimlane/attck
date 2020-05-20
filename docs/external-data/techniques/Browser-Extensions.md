
# Browser Extensions

## Description

### MITRE Description

> Browser extensions or plugins are small programs that can add functionality and customize aspects of internet browsers. They can be installed directly or through a browser's app store. Extensions generally have access and permissions to everything that the browser can access. (Citation: Wikipedia Browser Extension) (Citation: Chrome Extensions Definition)

Malicious extensions can be installed into a browser through malicious app store downloads masquerading as legitimate extensions, through social engineering, or by an adversary that has already compromised a system. Security can be limited on browser app stores so may not be difficult for malicious extensions to defeat automated scanners and be uploaded. (Citation: Malicious Chrome Extension Numbers) Once the extension is installed, it can browse to websites in the background, (Citation: Chrome Extension Crypto Miner) (Citation: ICEBRG Chrome Extensions) steal all information that a user enters into a browser, to include credentials, (Citation: Banker Google Chrome Extension Steals Creds) (Citation: Catch All Chrome Extension) and be used as an installer for a RAT for persistence. There have been instances of botnets using a persistent backdoor through malicious Chrome extensions. (Citation: Stantinko Botnet) There have also been similar examples of extensions being used for command & control  (Citation: Chrome Extension C2 Malware).

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
* Wiki: https://attack.mitre.org/techniques/T1176

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['File Audit - 4663']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['Packet capture']},
 {'data_source': ['System calls']},
 {'data_source': ['Browser extensions']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['Packet capture']},
 {'data_source': ['System calls']},
 {'data_source': ['Browser extensions']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Browser Extensions': {'atomic_tests': [{'auto_generated_guid': '3ecd790d-2617-4abf-9a8c-4e8d47da9ee1',
                                                                  'description': '',
                                                                  'executor': {'name': 'manual',
                                                                               'steps': '1. '
                                                                                        'Navigate '
                                                                                        'to '
                                                                                        '[chrome://extensions](chrome://extensions) '
                                                                                        'and\n'
                                                                                        'tick '
                                                                                        "'Developer "
                                                                                        "Mode'.\n"
                                                                                        '\n'
                                                                                        '2. '
                                                                                        'Click '
                                                                                        "'Load "
                                                                                        'unpacked '
                                                                                        "extension...' "
                                                                                        'and '
                                                                                        'navigate '
                                                                                        'to\n'
                                                                                        '[Browser_Extension](../t1176/)\n'
                                                                                        '\n'
                                                                                        '3. '
                                                                                        'Click '
                                                                                        "'Select'\n"},
                                                                  'name': 'Chrome '
                                                                          '(Developer '
                                                                          'Mode)',
                                                                  'supported_platforms': ['linux',
                                                                                          'windows',
                                                                                          'macos']},
                                                                 {'auto_generated_guid': '4c83940d-8ca5-4bb2-8100-f46dc914bc3f',
                                                                  'description': '',
                                                                  'executor': {'name': 'manual',
                                                                               'steps': '1. '
                                                                                        'Navigate '
                                                                                        'to '
                                                                                        'https://chrome.google.com/webstore/detail/minimum-viable-malicious/odlpfdolehmhciiebahbpnaopneicend\n'
                                                                                        'in '
                                                                                        'Chrome\n'
                                                                                        '\n'
                                                                                        '2. '
                                                                                        'Click '
                                                                                        "'Add "
                                                                                        'to '
                                                                                        "Chrome'\n"},
                                                                  'name': 'Chrome '
                                                                          '(Chrome '
                                                                          'Web '
                                                                          'Store)',
                                                                  'supported_platforms': ['linux',
                                                                                          'windows',
                                                                                          'macos']},
                                                                 {'auto_generated_guid': 'cb790029-17e6-4c43-b96f-002ce5f10938',
                                                                  'description': 'Create '
                                                                                 'a '
                                                                                 'file '
                                                                                 'called '
                                                                                 'test.wma, '
                                                                                 'with '
                                                                                 'the '
                                                                                 'duration '
                                                                                 'of '
                                                                                 '30 '
                                                                                 'seconds\n',
                                                                  'executor': {'name': 'manual',
                                                                               'steps': '1. '
                                                                                        'Navigate '
                                                                                        'to '
                                                                                        '[about:debugging](about:debugging) '
                                                                                        'and\n'
                                                                                        'click '
                                                                                        '"Load '
                                                                                        'Temporary '
                                                                                        'Add-on"\n'
                                                                                        '\n'
                                                                                        '2. '
                                                                                        'Navigate '
                                                                                        'to '
                                                                                        '[manifest.json](./src/manifest.json)\n'
                                                                                        '\n'
                                                                                        '3. '
                                                                                        'Then '
                                                                                        'click '
                                                                                        "'Open'\n"},
                                                                  'name': 'Firefox',
                                                                  'supported_platforms': ['linux',
                                                                                          'windows',
                                                                                          'macos']},
                                                                 {'auto_generated_guid': '3d456e2b-a7db-4af8-b5b3-720e7c4d9da5',
                                                                  'description': 'Adversaries '
                                                                                 'may '
                                                                                 'use '
                                                                                 'VPN '
                                                                                 'extensions '
                                                                                 'in '
                                                                                 'an '
                                                                                 'attempt '
                                                                                 'to '
                                                                                 'hide '
                                                                                 'traffic '
                                                                                 'sent '
                                                                                 'from '
                                                                                 'a '
                                                                                 'compromised '
                                                                                 'host. '
                                                                                 'This '
                                                                                 'will '
                                                                                 'install '
                                                                                 'one '
                                                                                 '(of '
                                                                                 'many) '
                                                                                 'available '
                                                                                 'VPNS '
                                                                                 'in '
                                                                                 'the '
                                                                                 'Edge '
                                                                                 'add-on '
                                                                                 'store.\n',
                                                                  'executor': {'cleanup': '1. '
                                                                                          'Navigate '
                                                                                          'to '
                                                                                          '"..." '
                                                                                          'menu '
                                                                                          'in '
                                                                                          'top '
                                                                                          'right '
                                                                                          'of '
                                                                                          'browser '
                                                                                          'and '
                                                                                          'select.\n'
                                                                                          '2. '
                                                                                          'In '
                                                                                          'drop '
                                                                                          'down, '
                                                                                          'click '
                                                                                          'on '
                                                                                          '"Extensions".\n'
                                                                                          '3. '
                                                                                          'Remove '
                                                                                          'the '
                                                                                          'Extension.',
                                                                               'name': 'manual',
                                                                               'steps': '1. '
                                                                                        'Navigate '
                                                                                        'to '
                                                                                        'https://microsoftedge.microsoft.com/addons/detail/fjnehcbecaggobjholekjijaaekbnlgj\n'
                                                                                        'in '
                                                                                        'Edge '
                                                                                        'Chromium\n'
                                                                                        '\n'
                                                                                        '2. '
                                                                                        'Click '
                                                                                        "'Get'\n"},
                                                                  'name': 'Edge '
                                                                          'Chromium '
                                                                          'Addon '
                                                                          '- '
                                                                          'VPN',
                                                                  'supported_platforms': ['windows',
                                                                                          'macos']}],
                                                'attack_technique': 'T1176',
                                                'display_name': 'Browser '
                                                                'Extensions'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors


* [Stolen Pencil](../actors/Stolen-Pencil.md)

* [Kimsuky](../actors/Kimsuky.md)
    
