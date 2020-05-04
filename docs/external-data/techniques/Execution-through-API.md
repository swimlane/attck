
# Execution through API

## Description

### MITRE Description

> Adversary tools may directly use the Windows application programming interface (API) to execute binaries. Functions such as the Windows API CreateProcess will allow programs and scripts to start other processes with proper path and argument parameters. (Citation: Microsoft CreateProcess)

Additional Windows API calls that can be used to execute binaries include: (Citation: Kanthak Verifier)

* CreateProcessA() and CreateProcessW(),
* CreateProcessAsUserA() and CreateProcessAsUserW(),
* CreateProcessInternalA() and CreateProcessInternalW(),
* CreateProcessWithLogonW(), CreateProcessWithTokenW(),
* LoadLibraryA() and LoadLibraryW(),
* LoadLibraryExA() and LoadLibraryExW(),
* LoadModule(),
* LoadPackagedLibrary(),
* WinExec(),
* ShellExecuteA() and ShellExecuteW(),
* ShellExecuteExA() and ShellExecuteExW()

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1106

## Potential Commands

```
python/situational_awareness/network/dcos/chronos_api_add_job
python/situational_awareness/network/dcos/chronos_api_add_job
python/situational_awareness/network/dcos/chronos_api_delete_job
python/situational_awareness/network/dcos/chronos_api_delete_job
python/situational_awareness/network/dcos/chronos_api_start_job
python/situational_awareness/network/dcos/chronos_api_start_job
python/situational_awareness/network/dcos/marathon_api_create_start_app
python/situational_awareness/network/dcos/marathon_api_create_start_app
python/situational_awareness/network/dcos/marathon_api_delete_app
python/situational_awareness/network/dcos/marathon_api_delete_app
python/situational_awareness/network/http_rest_api
python/situational_awareness/network/http_rest_api
```

## Commands Dataset

```
[{'command': 'python/situational_awareness/network/dcos/chronos_api_add_job',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/chronos_api_add_job',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/chronos_api_delete_job',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/chronos_api_delete_job',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/chronos_api_start_job',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/chronos_api_start_job',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/marathon_api_create_start_app',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/marathon_api_create_start_app',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/marathon_api_delete_app',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/dcos/marathon_api_delete_app',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/http_rest_api',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/http_rest_api',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1106',
                                            'ATT&CK Technique #2': 'T1168',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/dcos/chronos_api_add_job":  '
                                                                                 '["T1106","T1168"],',
                                            'Empire Module': 'python/situational_awareness/network/dcos/chronos_api_add_job',
                                            'Technique': 'Execution through '
                                                         'API'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1106',
                                            'ATT&CK Technique #2': 'T1168',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/dcos/chronos_api_delete_job":  '
                                                                                 '["T1106","T1168"],',
                                            'Empire Module': 'python/situational_awareness/network/dcos/chronos_api_delete_job',
                                            'Technique': 'Execution through '
                                                         'API'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1106',
                                            'ATT&CK Technique #2': 'T1168',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/dcos/chronos_api_start_job":  '
                                                                                 '["T1106","T1168"],',
                                            'Empire Module': 'python/situational_awareness/network/dcos/chronos_api_start_job',
                                            'Technique': 'Execution through '
                                                         'API'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1106',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/dcos/marathon_api_create_start_app":  '
                                                                                 '["T1106"],',
                                            'Empire Module': 'python/situational_awareness/network/dcos/marathon_api_create_start_app',
                                            'Technique': 'Execution through '
                                                         'API'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1106',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/dcos/marathon_api_delete_app":  '
                                                                                 '["T1106"],',
                                            'Empire Module': 'python/situational_awareness/network/dcos/marathon_api_delete_app',
                                            'Technique': 'Execution through '
                                                         'API'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1106',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/http_rest_api":  '
                                                                                 '["T1106"],',
                                            'Empire Module': 'python/situational_awareness/network/http_rest_api',
                                            'Technique': 'Execution through '
                                                         'API'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations

None

# Actors


* [APT37](../actors/APT37.md)

* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [Silence](../actors/Silence.md)
    
* [Turla](../actors/Turla.md)
    
