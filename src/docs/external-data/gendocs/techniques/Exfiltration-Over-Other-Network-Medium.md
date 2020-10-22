
# Exfiltration Over Other Network Medium

## Description

### MITRE Description

> Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel.

Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network

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
* Wiki: https://attack.mitre.org/techniques/T1011

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': {'author': 'iwillkeepwatch',
                  'date': '2019/01/18',
                  'description': 'Detects the addition of a SSP to the '
                                 'registry. Upon a reboot or API call, SSP '
                                 'DLLs gain access to encrypted and plaintext '
                                 'passwords stored in Windows.',
                  'detection': {'condition': 'selection_registry and not '
                                             'exclusion_images',
                                'exclusion_images': [{'Image': 'C:\\Windows\\system32\\msiexec.exe'},
                                                     {'Image': 'C:\\Windows\\syswow64\\MsiExec.exe'}],
                                'selection_registry': {'EventID': 13,
                                                       'TargetObject': ['HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security '
                                                                        'Packages',
                                                                        'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security '
                                                                        'Packages']}},
                  'falsepositives': ['Unlikely'],
                  'id': 'eeb30123-9fbd-4ee8-aaa0-2e545bbed6dc',
                  'level': 'critical',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://attack.mitre.org/techniques/T1101/',
                                 'https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/'],
                  'status': 'experimental',
                  'tags': ['attack.persistence', 'attack.t1011'],
                  'title': 'Security Support Provider (SSP) added to LSA '
                           'configuration'}},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['User interface']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['User interface']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Exfiltration](../tactics/Exfiltration.md)


# Mitigations


* [Exfiltration Over Other Network Medium Mitigation](../mitigations/Exfiltration-Over-Other-Network-Medium-Mitigation.md)

* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    

# Actors

None
