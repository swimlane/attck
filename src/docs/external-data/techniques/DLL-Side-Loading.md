
# DLL Side-Loading

## Description

### MITRE Description

> Programs may specify DLLs that are loaded at runtime. Programs that improperly or vaguely specify a required DLL may be open to a vulnerability in which an unintended DLL is loaded. Side-loading vulnerabilities specifically occur when Windows Side-by-Side (WinSxS) manifests (Citation: MSDN Manifests) are not explicit enough about characteristics of the DLL to be loaded. Adversaries may take advantage of a legitimate program that is vulnerable to side-loading to load a malicious DLL. (Citation: Stewart 2014)

Adversaries likely use this technique as a means of masking actions they perform under a legitimate, trusted system or software process.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Process whitelisting', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1073

## Potential Commands

```
#{gup_executable}

PathToAtomicsFolder\T1073\bin\GUP.exe

```

## Commands Dataset

```
[{'command': '#{gup_executable}\n',
  'name': None,
  'source': 'atomics/T1073/T1073.yaml'},
 {'command': 'PathToAtomicsFolder\\T1073\\bin\\GUP.exe\n',
  'name': None,
  'source': 'atomics/T1073/T1073.yaml'}]
```

## Potential Detections

```json
[{'data_source': {'action': 'global',
                  'author': 'Florian Roth',
                  'date': '2017/05/08',
                  'description': 'Detects the installation of a plugin DLL via '
                                 'ServerLevelPluginDll parameter in Registry, '
                                 'which can be used to execute code in context '
                                 'of the DNS server (restart required)',
                  'detection': {'condition': '1 of them'},
                  'falsepositives': ['unknown'],
                  'fields': ['EventID',
                             'CommandLine',
                             'ParentCommandLine',
                             'Image',
                             'User',
                             'TargetObject'],
                  'id': 'e61e8a88-59a9-451c-874e-70fcc9740d67',
                  'level': 'high',
                  'references': ['https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion', 'attack.t1073'],
                  'title': 'DNS ServerLevelPluginDll Install'}},
 {'data_source': {'detection': {'dnsregmod': {'EventID': 13,
                                              'TargetObject': '*\\services\\DNS\\Parameters\\ServerLevelPluginDll'}},
                  'logsource': {'product': 'windows', 'service': 'sysmon'}}},
 {'data_source': {'detection': {'dnsadmin': {'CommandLine': 'dnscmd.exe '
                                                            '/config '
                                                            '/serverlevelplugindll '
                                                            '*'}},
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'}}},
 {'data_source': {'author': 'Markus Neis',
                  'date': '2018/01/07',
                  'description': 'Detects Loading of samlib.dll, WinSCard.dll '
                                 'from untypical process e.g. through process '
                                 'hollowing by Mimikatz',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 7,
                                              'Image': ['*\\notepad.exe'],
                                              'ImageLoaded': ['*\\samlib.dll',
                                                              '*\\WinSCard.dll']}},
                  'falsepositives': ['Very likely, needs more tuning'],
                  'id': 'e32ce4f5-46c6-4c47-ba69-5de3c9193cd7',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion', 'attack.t1073'],
                  'title': 'Possible Process Hollowing Image Loading'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2017/06/12',
                  'description': 'Detects the execution of an executable that '
                                 'is typically used by PlugX for DLL side '
                                 'loading started from an uncommon location',
                  'detection': {'condition': '( selection_cammute and not '
                                             'filter_cammute ) or ( '
                                             'selection_chrome_frame and not '
                                             'filter_chrome_frame ) or ( '
                                             'selection_devemu and not '
                                             'filter_devemu ) or ( '
                                             'selection_gadget and not '
                                             'filter_gadget ) or ( '
                                             'selection_hcc and not filter_hcc '
                                             ') or ( selection_hkcmd and not '
                                             'filter_hkcmd ) or ( selection_mc '
                                             'and not filter_mc ) or ( '
                                             'selection_msmpeng and not '
                                             'filter_msmpeng ) or ( '
                                             'selection_msseces and not '
                                             'filter_msseces ) or ( '
                                             'selection_oinfo and not '
                                             'filter_oinfo ) or ( '
                                             'selection_oleview and not '
                                             'filter_oleview ) or ( '
                                             'selection_rc and not filter_rc )',
                                'filter_cammute': {'Image': '*\\Lenovo\\Communication '
                                                            'Utility\\\\*'},
                                'filter_chrome_frame': {'Image': '*\\Google\\Chrome\\application\\\\*'},
                                'filter_devemu': {'Image': '*\\Microsoft '
                                                           'Device '
                                                           'Emulator\\\\*'},
                                'filter_gadget': {'Image': '*\\Windows Media '
                                                           'Player\\\\*'},
                                'filter_hcc': {'Image': '*\\HTML Help '
                                                        'Workshop\\\\*'},
                                'filter_hkcmd': {'Image': ['*\\System32\\\\*',
                                                           '*\\SysNative\\\\*',
                                                           '*\\SysWowo64\\\\*']},
                                'filter_mc': {'Image': ['*\\Microsoft Visual '
                                                        'Studio*',
                                                        '*\\Microsoft SDK*',
                                                        '*\\Windows Kit*']},
                                'filter_msmpeng': {'Image': ['*\\Microsoft '
                                                             'Security '
                                                             'Client\\\\*',
                                                             '*\\Windows '
                                                             'Defender\\\\*',
                                                             '*\\AntiMalware\\\\*']},
                                'filter_msseces': {'Image': ['*\\Microsoft '
                                                             'Security '
                                                             'Center\\\\*',
                                                             '*\\Microsoft '
                                                             'Security '
                                                             'Client\\\\*',
                                                             '*\\Microsoft '
                                                             'Security '
                                                             'Essentials\\\\*']},
                                'filter_oinfo': {'Image': '*\\Common '
                                                          'Files\\Microsoft '
                                                          'Shared\\\\*'},
                                'filter_oleview': {'Image': ['*\\Microsoft '
                                                             'Visual Studio*',
                                                             '*\\Microsoft '
                                                             'SDK*',
                                                             '*\\Windows Kit*',
                                                             '*\\Windows '
                                                             'Resource '
                                                             'Kit\\\\*']},
                                'filter_rc': {'Image': ['*\\Microsoft Visual '
                                                        'Studio*',
                                                        '*\\Microsoft SDK*',
                                                        '*\\Windows Kit*',
                                                        '*\\Windows Resource '
                                                        'Kit\\\\*',
                                                        '*\\Microsoft.NET\\\\*']},
                                'selection_cammute': {'Image': '*\\CamMute.exe'},
                                'selection_chrome_frame': {'Image': '*\\chrome_frame_helper.exe'},
                                'selection_devemu': {'Image': '*\\dvcemumanager.exe'},
                                'selection_gadget': {'Image': '*\\Gadget.exe'},
                                'selection_hcc': {'Image': '*\\hcc.exe'},
                                'selection_hkcmd': {'Image': '*\\hkcmd.exe'},
                                'selection_mc': {'Image': '*\\Mc.exe'},
                                'selection_msmpeng': {'Image': '*\\MsMpEng.exe'},
                                'selection_msseces': {'Image': '*\\msseces.exe'},
                                'selection_oinfo': {'Image': '*\\OInfoP11.exe'},
                                'selection_oleview': {'Image': '*\\OleView.exe'},
                                'selection_rc': {'Image': '*\\rc.exe'}},
                  'falsepositives': ['Unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': 'aeab5ec5-be14-471a-80e8-e344418305c2',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['http://www.hexacorn.com/blog/2016/03/10/beyond-good-ol-run-key-part-36/',
                                 'https://countuponsecurity.com/2017/06/07/threat-hunting-in-the-enterprise-with-appcompatprocessor/'],
                  'status': 'experimental',
                  'tags': ['attack.s0013',
                           'attack.defense_evasion',
                           'attack.t1073'],
                  'title': 'Executable used by PlugX in Uncommon Location - '
                           'Sysmon Version'}},
 {'data_source': {'author': 'Dimitrios Slamaris',
                  'date': '2017/05/15',
                  'description': 'This rule detects a DHCP server in which a '
                                 'specified Callout DLL (in registry) was '
                                 'loaded',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 1033}},
                  'falsepositives': ['Unknown'],
                  'id': '13fc89a9-971e-4ca6-b9dc-aa53a445bf40',
                  'level': 'critical',
                  'logsource': {'product': 'windows', 'service': 'system'},
                  'references': ['https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html',
                                 'https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx',
                                 'https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion', 'attack.t1073'],
                  'title': 'DHCP Server Loaded the CallOut DLL'}},
 {'data_source': {'author': 'Dimitrios Slamaris, @atc_project (fix)',
                  'date': '2017/05/15',
                  'description': 'This rule detects a DHCP server error in '
                                 'which a specified Callout DLL (in registry) '
                                 'could not be loaded',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': [1031, 1032, 1034],
                                              'Source': 'Microsoft-Windows-DHCP-Server'}},
                  'falsepositives': ['Unknown'],
                  'id': '75edd3fd-7146-48e5-9848-3013d7f0282c',
                  'level': 'critical',
                  'logsource': {'product': 'windows', 'service': 'system'},
                  'modified': '2019/07/17',
                  'references': ['https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html',
                                 'https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx',
                                 'https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion', 'attack.t1073'],
                  'title': 'DHCP Server Error Failed Loading the CallOut DLL'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2017/05/08',
                  'description': 'This rule detects a DNS server error in '
                                 'which a specified plugin DLL (in registry) '
                                 'could not be loaded',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': [150, 770]}},
                  'falsepositives': ['Unknown'],
                  'id': 'cbe51394-cd93-4473-b555-edf0144952d9',
                  'level': 'critical',
                  'logsource': {'product': 'windows', 'service': 'dns-server'},
                  'references': ['https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83',
                                 'https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx',
                                 'https://twitter.com/gentilkiwi/status/861641945944391680'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion', 'attack.t1073'],
                  'title': 'DNS Server Error Failed Loading the '
                           'ServerLevelPluginDLL'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2019/02/06',
                  'description': 'Detects execution of the Notepad++ updater '
                                 'in a suspicious directory, which is often '
                                 'used in DLL side-loading attacks',
                  'detection': {'condition': 'selection and not filter',
                                'filter': {'Image': ['C:\\Users\\\\*\\AppData\\Local\\Notepad++\\updater\\gup.exe',
                                                     'C:\\Users\\\\*\\AppData\\Roaming\\Notepad++\\updater\\gup.exe',
                                                     'C:\\Program '
                                                     'Files\\Notepad++\\updater\\gup.exe',
                                                     'C:\\Program Files '
                                                     '(x86)\\Notepad++\\updater\\gup.exe']},
                                'selection': {'Image': '*\\GUP.exe'}},
                  'falsepositives': ['Execution of tools named GUP.exe and '
                                     'located in folders different than '
                                     'Notepad++\\updater'],
                  'id': '0a4f6091-223b-41f6-8743-f322ec84930b',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion', 'attack.t1073'],
                  'title': 'Suspicious GUP Usage'}},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Sysmon - ID 7', 'Loaded DLLs']},
 {'data_source': ['Sysmon - ID 7', 'Loaded DLLs']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - DLL Side-Loading': {'atomic_tests': [{'auto_generated_guid': '65526037-7079-44a9-bda1-2cb624838040',
                                                                'dependencies': [{'description': 'Gup.exe '
                                                                                                 'binary '
                                                                                                 'must '
                                                                                                 'exist '
                                                                                                 'on '
                                                                                                 'disk '
                                                                                                 'at '
                                                                                                 'specified '
                                                                                                 'location '
                                                                                                 '(#{gup_executable})\n',
                                                                                  'get_prereq_command': 'New-Item '
                                                                                                        '-Type '
                                                                                                        'Directory '
                                                                                                        '(split-path '
                                                                                                        '#{gup_executable}) '
                                                                                                        '-ErrorAction '
                                                                                                        'ignore '
                                                                                                        '| '
                                                                                                        'Out-Null\n'
                                                                                                        'Invoke-WebRequest '
                                                                                                        '"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1073/bin/GUP.exe" '
                                                                                                        '-OutFile '
                                                                                                        '"#{gup_executable}"\n',
                                                                                  'prereq_command': 'if '
                                                                                                    '(Test-Path '
                                                                                                    '#{gup_executable}) '
                                                                                                    '{exit '
                                                                                                    '0} '
                                                                                                    'else '
                                                                                                    '{exit '
                                                                                                    '1}\n'}],
                                                                'dependency_executor_name': 'powershell',
                                                                'description': 'GUP '
                                                                               'is '
                                                                               'an '
                                                                               'open '
                                                                               'source '
                                                                               'signed '
                                                                               'binary '
                                                                               'used '
                                                                               'by '
                                                                               'Notepad++ '
                                                                               'for '
                                                                               'software '
                                                                               'updates, '
                                                                               'and '
                                                                               'is '
                                                                               'vulnerable '
                                                                               'to '
                                                                               'DLL '
                                                                               'Side-Loading, '
                                                                               'thus '
                                                                               'enabling '
                                                                               'the '
                                                                               'libcurl '
                                                                               'dll '
                                                                               'to '
                                                                               'be '
                                                                               'loaded.\n'
                                                                               'Upon '
                                                                               'execution, '
                                                                               'calc.exe '
                                                                               'will '
                                                                               'be '
                                                                               'opened.\n',
                                                                'executor': {'cleanup_command': 'taskkill '
                                                                                                '/F '
                                                                                                '/IM '
                                                                                                '#{process_name} '
                                                                                                '>nul '
                                                                                                '2>&1\n',
                                                                             'command': '#{gup_executable}\n',
                                                                             'elevation_required': False,
                                                                             'name': 'command_prompt'},
                                                                'input_arguments': {'gup_executable': {'default': 'PathToAtomicsFolder\\T1073\\bin\\GUP.exe',
                                                                                                       'description': 'GUP '
                                                                                                                      'is '
                                                                                                                      'an '
                                                                                                                      'open '
                                                                                                                      'source '
                                                                                                                      'signed '
                                                                                                                      'binary '
                                                                                                                      'used '
                                                                                                                      'by '
                                                                                                                      'Notepad++ '
                                                                                                                      'for '
                                                                                                                      'software '
                                                                                                                      'updates',
                                                                                                       'type': 'path'},
                                                                                    'process_name': {'default': 'calculator.exe',
                                                                                                     'description': 'Name '
                                                                                                                    'of '
                                                                                                                    'the '
                                                                                                                    'created '
                                                                                                                    'process',
                                                                                                     'type': 'string'}},
                                                                'name': 'DLL '
                                                                        'Side-Loading '
                                                                        'using '
                                                                        'the '
                                                                        'Notepad++ '
                                                                        'GUP.exe '
                                                                        'binary',
                                                                'supported_platforms': ['windows']}],
                                              'attack_technique': 'T1073',
                                              'display_name': 'DLL '
                                                              'Side-Loading'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [Patchwork](../actors/Patchwork.md)

* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT19](../actors/APT19.md)
    
* [menuPass](../actors/menuPass.md)
    
* [APT3](../actors/APT3.md)
    
* [APT32](../actors/APT32.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
