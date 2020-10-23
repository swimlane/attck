
# Credentials in Registry

## Description

### MITRE Description

> Adversaries may search the Registry on compromised systems for insecurely stored credentials. The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services. Sometimes these credentials are used for automatic logons.

Example commands to find Registry keys related to password information: (Citation: Pentestlab Stored Credentials)

* Local Machine Hive: <code>reg query HKLM /f password /t REG_SZ /s</code>
* Current User Hive: <code>reg query HKCU /f password /t REG_SZ /s</code>

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1552/002

## Potential Commands

```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /t REG_SZ /s
```

## Commands Dataset

```
[{'command': 'reg query HKLM /f password /t REG_SZ /s\n'
             'reg query HKCU /f password /t REG_SZ /s\n',
  'name': None,
  'source': 'atomics/T1552.002/T1552.002.yaml'},
 {'command': 'reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions /t REG_SZ '
             '/s\n',
  'name': None,
  'source': 'atomics/T1552.002/T1552.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Unsecured Credentials: Credentials in Registry': {'atomic_tests': [{'auto_generated_guid': 'b6ec082c-7384-46b3-a111-9a9b8b14e5e7',
                                                                                              'description': 'Queries '
                                                                                                             'to '
                                                                                                             'enumerate '
                                                                                                             'for '
                                                                                                             'credentials '
                                                                                                             'in '
                                                                                                             'the '
                                                                                                             'Registry. '
                                                                                                             'Upon '
                                                                                                             'execution, '
                                                                                                             'any '
                                                                                                             'registry '
                                                                                                             'key '
                                                                                                             'containing '
                                                                                                             'the '
                                                                                                             'word '
                                                                                                             '"password" '
                                                                                                             'will '
                                                                                                             'be '
                                                                                                             'displayed.\n',
                                                                                              'executor': {'command': 'reg '
                                                                                                                      'query '
                                                                                                                      'HKLM '
                                                                                                                      '/f '
                                                                                                                      'password '
                                                                                                                      '/t '
                                                                                                                      'REG_SZ '
                                                                                                                      '/s\n'
                                                                                                                      'reg '
                                                                                                                      'query '
                                                                                                                      'HKCU '
                                                                                                                      '/f '
                                                                                                                      'password '
                                                                                                                      '/t '
                                                                                                                      'REG_SZ '
                                                                                                                      '/s\n',
                                                                                                           'name': 'command_prompt'},
                                                                                              'name': 'Enumeration '
                                                                                                      'for '
                                                                                                      'Credentials '
                                                                                                      'in '
                                                                                                      'Registry',
                                                                                              'supported_platforms': ['windows']},
                                                                                             {'auto_generated_guid': 'af197fd7-e868-448e-9bd5-05d1bcd9d9e5',
                                                                                              'description': 'Queries '
                                                                                                             'to '
                                                                                                             'enumerate '
                                                                                                             'for '
                                                                                                             'PuTTY '
                                                                                                             'credentials '
                                                                                                             'in '
                                                                                                             'the '
                                                                                                             'Registry. '
                                                                                                             'PuTTY '
                                                                                                             'must '
                                                                                                             'be '
                                                                                                             'installed '
                                                                                                             'for '
                                                                                                             'this '
                                                                                                             'test '
                                                                                                             'to '
                                                                                                             'work. '
                                                                                                             'If '
                                                                                                             'any '
                                                                                                             'registry\n'
                                                                                                             'entries '
                                                                                                             'are '
                                                                                                             'found, '
                                                                                                             'they '
                                                                                                             'will '
                                                                                                             'be '
                                                                                                             'displayed.\n',
                                                                                              'executor': {'command': 'reg '
                                                                                                                      'query '
                                                                                                                      'HKCU\\Software\\SimonTatham\\PuTTY\\Sessions '
                                                                                                                      '/t '
                                                                                                                      'REG_SZ '
                                                                                                                      '/s\n',
                                                                                                           'name': 'command_prompt'},
                                                                                              'name': 'Enumeration '
                                                                                                      'for '
                                                                                                      'PuTTY '
                                                                                                      'Credentials '
                                                                                                      'in '
                                                                                                      'Registry',
                                                                                              'supported_platforms': ['windows']}],
                                                                            'attack_technique': 'T1552.002',
                                                                            'display_name': 'Unsecured '
                                                                                            'Credentials: '
                                                                                            'Credentials '
                                                                                            'in '
                                                                                            'Registry'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Password Policies](../mitigations/Password-Policies.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Audit](../mitigations/Audit.md)
    
* [Credentials in Registry Mitigation](../mitigations/Credentials-in-Registry-Mitigation.md)
    

# Actors


* [APT32](../actors/APT32.md)

