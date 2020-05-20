
# Hardware Additions

## Description

### MITRE Description

> Adversaries may introduce computer accessories, computers, or networking hardware into a system or network that can be used as a vector to gain access. While public references of usage by APT groups are scarce, many penetration testers leverage hardware additions for initial access. Commercial and open source products are leveraged with capabilities such as passive network tapping (Citation: Ossmann Star Feb 2011), man-in-the middle encryption breaking (Citation: Aleks Weapons Nov 2015), keystroke injection (Citation: Hak5 RubberDuck Dec 2016), kernel memory reading via DMA (Citation: Frisk DMA August 2016), adding new wireless access to an existing network (Citation: McMillan Pwn March 2012), and others.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows', 'Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1200

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'description': 'Detects plugged USB devices',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': [2003, 2100, 2102]}},
                  'falsepositives': ['Legitimate administrative activity'],
                  'id': '1a4bd6e3-4c6e-405d-a9a3-53a116e341d4',
                  'level': 'low',
                  'logsource': {'product': 'windows',
                                'service': 'driver-framework'},
                  'references': ['https://df-stream.com/2014/01/the-windows-7-event-log-and-usb-device/',
                                 'https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/'],
                  'status': 'experimental',
                  'tags': ['attack.initial_access', 'attack.t1200'],
                  'title': 'USB Device Plugged'}},
 {'data_source': ['Asset Management']},
 {'data_source': ['Data loss prevention']},
 {'data_source': ['Asset Management']},
 {'data_source': ['Data loss prevention']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Initial Access](../tactics/Initial-Access.md)


# Mitigations

None

# Actors

None
