
# Component Object Model Hijacking

## Description

### MITRE Description

> Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system.(Citation: Microsoft Component Object Model)  References to various COM objects are stored in the Registry. 

Adversaries can use the COM system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead.(Citation: GDATA COM Hijacking) An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection. 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1546/015

## Potential Commands

```
\\Software\\Classes\\CLSID\\.+\\InprocServer32
```

## Commands Dataset

```
[{'command': '\\\\Software\\\\Classes\\\\CLSID\\\\.+\\\\InprocServer32',
  'name': None,
  'source': 'SysmonHunter - Component Object Model Hijacking'},
 {'command': '\\\\Software\\\\Classes\\\\CLSID\\\\.+\\\\InprocServer32',
  'name': None,
  'source': 'SysmonHunter - Component Object Model Hijacking'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Kutepov Anton, oscd.community',
                  'date': '2019/10/23',
                  'description': 'Detects COM object hijacking via TreatAs '
                                 'subkey',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 12,
                                              'TargetObject|contains': '_Classes\\CLSID\\',
                                              'TargetObject|endswith': '\\TreatAs',
                                              'TargetObject|startswith': 'HKU\\'}},
                  'falsepositives': ['Maybe some system utilities in rare '
                                     'cases use linking keys for backward '
                                     'compability'],
                  'id': '9b0f8a61-91b2-464f-aceb-0527e0a45020',
                  'level': 'medium',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'modified': '2019/11/07',
                  'references': ['https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/'],
                  'status': 'experimental',
                  'tags': ['attack.persistence', 'attack.t1122'],
                  'title': 'Windows Registry Persistence - COM key linking'}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['DLL monitoring']},
 {'data_source': ['Loaded DLLs']},
 {'data_source': ['LOG-MD', 'Windows Registry', 'Compare']},
 {'data_source': ['LOG-MD', 'Windows Registry', 'Compare']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['Sysmon - ID 7', 'DLL monitoring']},
 {'data_source': ['Sysmon - ID 7', 'Loaded DLLs']}]
```

## Potential Queries

```json
[{'name': 'Component Object Model Hijacking',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           'registry_key_path contains "\\\\Software\\\\Classes\\\\CLSID\\\\"'}]
```

## Raw Dataset

```json
[{'SysmonHunter - T1122': {'description': None,
                           'level': 'medium',
                           'name': 'Component Object Model Hijacking',
                           'phase': 'Persistence',
                           'query': [{'reg': {'path': {'flag': 'regex',
                                                       'pattern': '\\\\Software\\\\Classes\\\\CLSID\\\\.+\\\\InprocServer32'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'flag': 'regex',
                                                              'pattern': '\\\\Software\\\\Classes\\\\CLSID\\\\.+\\\\InprocServer32'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors


* [APT28](../actors/APT28.md)

