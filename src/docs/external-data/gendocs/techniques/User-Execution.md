
# User Execution

## Description

### MITRE Description

> An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions will typically be observed as follow-on behavior from forms of [Phishing](https://attack.mitre.org/techniques/T1566).

While [User Execution](https://attack.mitre.org/techniques/T1204) frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after [Internal Spearphishing](https://attack.mitre.org/techniques/T1534).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1204

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json
[{'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Anti-virus']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Anti-virus']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [User Execution Mitigation](../mitigations/User-Execution-Mitigation.md)

* [User Training](../mitigations/User-Training.md)
    
* [Restrict Web-Based Content](../mitigations/Restrict-Web-Based-Content.md)
    
* [Execution Prevention](../mitigations/Execution-Prevention.md)
    
* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)
    

# Actors

None
