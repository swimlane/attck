
# Local Groups

## Description

### MITRE Description

> Adversaries may attempt to find local system groups and permission settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group.

Commands such as <code>net localgroup</code> of the [Net](https://attack.mitre.org/software/S0039) utility, <code>dscl . -list /Groups</code> on macOS, and <code>groups</code> on Linux can list local groups.

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
* Wiki: https://attack.mitre.org/techniques/T1069/001

## Potential Commands

```
get-localgroup
Get-LocalGroupMember -Name "Administrators"
net localgroup
net localgroup "Administrators"
if [ -x "$(command -v dscacheutil)" ]; then dscacheutil -q group; else echo "dscacheutil is missing from the machine. skipping..."; fi;
if [ -x "$(command -v dscl)" ]; then dscl . -list /Groups; else echo "dscl is missing from the machine. skipping..."; fi;
if [ -x "$(command -v groups)" ]; then groups; else echo "groups is missing from the machine. skipping..."; fi;
```

## Commands Dataset

```
[{'command': 'if [ -x "$(command -v dscacheutil)" ]; then dscacheutil -q '
             'group; else echo "dscacheutil is missing from the machine. '
             'skipping..."; fi;\n'
             'if [ -x "$(command -v dscl)" ]; then dscl . -list /Groups; else '
             'echo "dscl is missing from the machine. skipping..."; fi;\n'
             'if [ -x "$(command -v groups)" ]; then groups; else echo "groups '
             'is missing from the machine. skipping..."; fi;\n',
  'name': None,
  'source': 'atomics/T1069.001/T1069.001.yaml'},
 {'command': 'net localgroup\nnet localgroup "Administrators"\n',
  'name': None,
  'source': 'atomics/T1069.001/T1069.001.yaml'},
 {'command': 'get-localgroup\nGet-LocalGroupMember -Name "Administrators"\n',
  'name': None,
  'source': 'atomics/T1069.001/T1069.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Permission Groups Discovery: Local Groups': {'atomic_tests': [{'auto_generated_guid': '952931a4-af0b-4335-bbbe-73c8c5b327ae',
                                                                                         'description': 'Permission '
                                                                                                        'Groups '
                                                                                                        'Discovery\n',
                                                                                         'executor': {'command': 'if '
                                                                                                                 '[ '
                                                                                                                 '-x '
                                                                                                                 '"$(command '
                                                                                                                 '-v '
                                                                                                                 'dscacheutil)" '
                                                                                                                 ']; '
                                                                                                                 'then '
                                                                                                                 'dscacheutil '
                                                                                                                 '-q '
                                                                                                                 'group; '
                                                                                                                 'else '
                                                                                                                 'echo '
                                                                                                                 '"dscacheutil '
                                                                                                                 'is '
                                                                                                                 'missing '
                                                                                                                 'from '
                                                                                                                 'the '
                                                                                                                 'machine. '
                                                                                                                 'skipping..."; '
                                                                                                                 'fi;\n'
                                                                                                                 'if '
                                                                                                                 '[ '
                                                                                                                 '-x '
                                                                                                                 '"$(command '
                                                                                                                 '-v '
                                                                                                                 'dscl)" '
                                                                                                                 ']; '
                                                                                                                 'then '
                                                                                                                 'dscl '
                                                                                                                 '. '
                                                                                                                 '-list '
                                                                                                                 '/Groups; '
                                                                                                                 'else '
                                                                                                                 'echo '
                                                                                                                 '"dscl '
                                                                                                                 'is '
                                                                                                                 'missing '
                                                                                                                 'from '
                                                                                                                 'the '
                                                                                                                 'machine. '
                                                                                                                 'skipping..."; '
                                                                                                                 'fi;\n'
                                                                                                                 'if '
                                                                                                                 '[ '
                                                                                                                 '-x '
                                                                                                                 '"$(command '
                                                                                                                 '-v '
                                                                                                                 'groups)" '
                                                                                                                 ']; '
                                                                                                                 'then '
                                                                                                                 'groups; '
                                                                                                                 'else '
                                                                                                                 'echo '
                                                                                                                 '"groups '
                                                                                                                 'is '
                                                                                                                 'missing '
                                                                                                                 'from '
                                                                                                                 'the '
                                                                                                                 'machine. '
                                                                                                                 'skipping..."; '
                                                                                                                 'fi;\n',
                                                                                                      'name': 'sh'},
                                                                                         'name': 'Permission '
                                                                                                 'Groups '
                                                                                                 'Discovery '
                                                                                                 '(Local)',
                                                                                         'supported_platforms': ['macos',
                                                                                                                 'linux']},
                                                                                        {'auto_generated_guid': '1f454dd6-e134-44df-bebb-67de70fb6cd8',
                                                                                         'description': 'Basic '
                                                                                                        'Permission '
                                                                                                        'Groups '
                                                                                                        'Discovery '
                                                                                                        'for '
                                                                                                        'Windows. '
                                                                                                        'This '
                                                                                                        'test '
                                                                                                        'will '
                                                                                                        'display '
                                                                                                        'some '
                                                                                                        'errors '
                                                                                                        'if '
                                                                                                        'run '
                                                                                                        'on '
                                                                                                        'a '
                                                                                                        'computer '
                                                                                                        'not '
                                                                                                        'connected '
                                                                                                        'to '
                                                                                                        'a '
                                                                                                        'domain. '
                                                                                                        'Upon '
                                                                                                        'execution, '
                                                                                                        'domain\n'
                                                                                                        'information '
                                                                                                        'will '
                                                                                                        'be '
                                                                                                        'displayed.\n',
                                                                                         'executor': {'command': 'net '
                                                                                                                 'localgroup\n'
                                                                                                                 'net '
                                                                                                                 'localgroup '
                                                                                                                 '"Administrators"\n',
                                                                                                      'name': 'command_prompt'},
                                                                                         'name': 'Basic '
                                                                                                 'Permission '
                                                                                                 'Groups '
                                                                                                 'Discovery '
                                                                                                 'Windows '
                                                                                                 '(Local)',
                                                                                         'supported_platforms': ['windows']},
                                                                                        {'auto_generated_guid': 'a580462d-2c19-4bc7-8b9a-57a41b7d3ba4',
                                                                                         'description': 'Permission '
                                                                                                        'Groups '
                                                                                                        'Discovery '
                                                                                                        'utilizing '
                                                                                                        'PowerShell. '
                                                                                                        'This '
                                                                                                        'test '
                                                                                                        'will '
                                                                                                        'display '
                                                                                                        'some '
                                                                                                        'errors '
                                                                                                        'if '
                                                                                                        'run '
                                                                                                        'on '
                                                                                                        'a '
                                                                                                        'computer '
                                                                                                        'not '
                                                                                                        'connected '
                                                                                                        'to '
                                                                                                        'a '
                                                                                                        'domain. '
                                                                                                        'Upon '
                                                                                                        'execution, '
                                                                                                        'domain\n'
                                                                                                        'information '
                                                                                                        'will '
                                                                                                        'be '
                                                                                                        'displayed.\n',
                                                                                         'executor': {'command': 'get-localgroup\n'
                                                                                                                 'Get-LocalGroupMember '
                                                                                                                 '-Name '
                                                                                                                 '"Administrators"\n',
                                                                                                      'name': 'powershell'},
                                                                                         'name': 'Permission '
                                                                                                 'Groups '
                                                                                                 'Discovery '
                                                                                                 'PowerShell '
                                                                                                 '(Local)',
                                                                                         'supported_platforms': ['windows']}],
                                                                       'attack_technique': 'T1069.001',
                                                                       'display_name': 'Permission '
                                                                                       'Groups '
                                                                                       'Discovery: '
                                                                                       'Local '
                                                                                       'Groups'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations

None

# Actors


* [admin@338](../actors/admin@338.md)

* [OilRig](../actors/OilRig.md)
    
* [Turla](../actors/Turla.md)
    
