
# Data Encoding

## Description

### MITRE Description

> Adversaries may encode data to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system. Use of data encoding may adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64, MIME, or other binary-to-text and character encoding systems.(Citation: Wikipedia Binary-to-text Encoding) (Citation: Wikipedia Character Encoding) Some data encoding systems may also result in data compression, such as gzip.

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

```

## Commands Dataset

```

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

```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations


* [Data Encoding Mitigation](../mitigations/Data-Encoding-Mitigation.md)

* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)
    

# Actors

None
