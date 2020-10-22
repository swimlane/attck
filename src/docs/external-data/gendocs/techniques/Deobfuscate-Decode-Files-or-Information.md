
# Deobfuscate/Decode Files or Information

## Description

### MITRE Description

> Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware or by using utilities present on the system.

One such example is use of [certutil](https://attack.mitre.org/software/S0160) to decode a remote access tool portable executable file that has been hidden inside a certificate file. (Citation: Malwarebytes Targeted Attack against Saudi Arabia) Another example is using the Windows <code>copy /b</code> command to reassemble binary fragments into a malicious payload. (Citation: Carbon Black Obfuscation Sept 2016)

Sometimes a user's action may be required to open it for deobfuscation or decryption as part of [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti-virus', 'Host intrusion prevention systems', 'Signature-based detection', 'Network intrusion detection system']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows', 'Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1140

## Potential Commands

```
certutil -encode C:\Windows\System32\calc.exe %temp%\T1140_calc.txt
certutil -decode %temp%\T1140_calc.txt %temp%\T1140_calc_decoded.exe

copy %windir%\system32\certutil.exe %temp%\tcm.tmp
%temp%\tcm.tmp -encode C:\Windows\System32\calc.exe %temp%\T1140_calc2.txt
%temp%\tcm.tmp -decode %temp%\T1140_calc2.txt %temp%\T1140_calc2_decoded.exe

certutil.exe -decode
certutil.exe-decode|-urlcache
certutil.exe|-decode|-urlcache
```

## Commands Dataset

```
[{'command': 'certutil -encode C:\\Windows\\System32\\calc.exe '
             '%temp%\\T1140_calc.txt\n'
             'certutil -decode %temp%\\T1140_calc.txt '
             '%temp%\\T1140_calc_decoded.exe\n',
  'name': None,
  'source': 'atomics/T1140/T1140.yaml'},
 {'command': 'copy %windir%\\system32\\certutil.exe %temp%\\tcm.tmp\n'
             '%temp%\\tcm.tmp -encode C:\\Windows\\System32\\calc.exe '
             '%temp%\\T1140_calc2.txt\n'
             '%temp%\\tcm.tmp -decode %temp%\\T1140_calc2.txt '
             '%temp%\\T1140_calc2_decoded.exe\n',
  'name': None,
  'source': 'atomics/T1140/T1140.yaml'},
 {'command': 'certutil.exe -decode',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'certutil.exe-decode|-urlcache',
  'name': None,
  'source': 'SysmonHunter - Deobfuscate/Decode Files or Information'},
 {'command': 'certutil.exe|-decode|-urlcache',
  'name': None,
  'source': 'SysmonHunter - Deobfuscate/Decode Files or Information'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'date': '2019/08/24',
                  'description': 'Detects a base64 encoded FromBase64String '
                                 'keyword in a process command line',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine|base64offset|contains': '::FromBase64String'}},
                  'falsepositives': ['unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': 'fdb62a13-9a81-4e5c-a38f-ea93a16f6d7c',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'status': 'experimental',
                  'tags': ['attack.t1086',
                           'attack.t1140',
                           'attack.execution',
                           'attack.defense_evasion'],
                  'title': 'Encoded FromBase64String'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2019/08/23',
                  'description': 'Detects a base64 encoded IEX command string '
                                 'in a process command line',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine|base64offset|contains': ['IEX '
                                                                                    '([',
                                                                                    'iex '
                                                                                    '([',
                                                                                    'iex '
                                                                                    '(New',
                                                                                    'IEX '
                                                                                    '(New']}},
                  'falsepositives': ['unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '88f680b8-070e-402c-ae11-d2914f2257f1',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'status': 'experimental',
                  'tags': ['attack.t1086', 'attack.t1140', 'attack.execution'],
                  'title': 'Encoded IEX'}},
 {'data_source': {'author': 'juju4',
                  'description': 'Detects suspicious process that use escape '
                                 'characters',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['^h^t^t^p',
                                                              'h"t"t"p']}},
                  'falsepositives': ['False positives depend on scripts and '
                                     'administrative tools used in the '
                                     'monitored environment'],
                  'id': 'f0cdd048-82dc-4f7a-8a7a-b87a52b6d0fd',
                  'level': 'low',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2018/12/11',
                  'references': ['https://twitter.com/vysecurity/status/885545634958385153',
                                 'https://twitter.com/Hexacorn/status/885553465417756673',
                                 'https://twitter.com/Hexacorn/status/885570278637678592',
                                 'https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html',
                                 'http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion', 'attack.t1140'],
                  'title': 'Suspicious Commandline Escape'}},
 {'data_source': {'author': 'Diego Perez (@darkquassar)',
                  'date': '22/02/2019',
                  'description': 'Detection for mshta.exe suspicious execution '
                                 'patterns sometimes involving file '
                                 'polyglotism',
                  'detection': {'condition': 'selection1 or selection2',
                                'selection1': {'CommandLine': ['*mshta '
                                                               'vbscript:CreateObject("Wscript.Shell")*',
                                                               '*mshta '
                                                               'vbscript:Execute("Execute*',
                                                               '*mshta '
                                                               'vbscript:CreateObject("Wscript.Shell").Run("mshta.exe*']},
                                'selection2': {'CommandLine': ['*.jpg*',
                                                               '*.png*',
                                                               '*.lnk*',
                                                               '*.xls*',
                                                               '*.doc*',
                                                               '*.zip*'],
                                               'Image': ['C:\\Windows\\system32\\mshta.exe']}},
                  'falsepositives': ['False positives depend on scripts and '
                                     'administrative tools used in the '
                                     'monitored environment'],
                  'id': 'cc7abbd0-762b-41e3-8a26-57ad50d2eea3',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '22/02/2019',
                  'references': ['http://blog.sevagas.com/?Hacking-around-HTA-files',
                                 'https://0x00sec.org/t/clientside-exploitation-in-2018-how-pentesting-has-changed/7356',
                                 'https://docs.microsoft.com/en-us/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script',
                                 'https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion', 'attack.t1140'],
                  'title': 'MSHTA Suspicious Execution 01'}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']}]
```

## Potential Queries

```json
[{'name': 'Deobfuscate Decode Files Or Information',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_path contains '
           '"certutil.exe"and process_command_line contains "decode")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Deobfuscate/Decode Files or Information': {'atomic_tests': [{'auto_generated_guid': 'dc6fe391-69e6-4506-bd06-ea5eeb4082f8',
                                                                                       'description': 'Encode/Decode '
                                                                                                      'executable\n'
                                                                                                      'Upon '
                                                                                                      'execution '
                                                                                                      'a '
                                                                                                      'file '
                                                                                                      'named '
                                                                                                      'T1140_calc_decoded.exe '
                                                                                                      'will '
                                                                                                      'be '
                                                                                                      'placed '
                                                                                                      'in '
                                                                                                      'the '
                                                                                                      'temp '
                                                                                                      'folder\n',
                                                                                       'executor': {'cleanup_command': 'del '
                                                                                                                       '%temp%\\T1140_calc.txt '
                                                                                                                       '>nul '
                                                                                                                       '2>&1\n'
                                                                                                                       'del '
                                                                                                                       '%temp%\\T1140_calc_decoded.exe '
                                                                                                                       '>nul '
                                                                                                                       '2>&1\n',
                                                                                                    'command': 'certutil '
                                                                                                               '-encode '
                                                                                                               '#{executable} '
                                                                                                               '%temp%\\T1140_calc.txt\n'
                                                                                                               'certutil '
                                                                                                               '-decode '
                                                                                                               '%temp%\\T1140_calc.txt '
                                                                                                               '%temp%\\T1140_calc_decoded.exe\n',
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'executable': {'default': 'C:\\Windows\\System32\\calc.exe',
                                                                                                                          'description': 'name '
                                                                                                                                         'of '
                                                                                                                                         'executable',
                                                                                                                          'type': 'path'}},
                                                                                       'name': 'Deobfuscate/Decode '
                                                                                               'Files '
                                                                                               'Or '
                                                                                               'Information',
                                                                                       'supported_platforms': ['windows']},
                                                                                      {'auto_generated_guid': '71abc534-3c05-4d0c-80f7-cbe93cb2aa94',
                                                                                       'description': 'Rename '
                                                                                                      'certutil '
                                                                                                      'and '
                                                                                                      'decode '
                                                                                                      'a '
                                                                                                      'file. '
                                                                                                      'This '
                                                                                                      'is '
                                                                                                      'in '
                                                                                                      'reference '
                                                                                                      'to '
                                                                                                      'latest '
                                                                                                      'research '
                                                                                                      'by '
                                                                                                      'FireEye '
                                                                                                      '[here](https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)\n',
                                                                                       'executor': {'cleanup_command': 'del '
                                                                                                                       '%temp%\\tcm.tmp '
                                                                                                                       '>nul '
                                                                                                                       '2>&1\n'
                                                                                                                       'del '
                                                                                                                       '%temp%\\T1140_calc2.txt '
                                                                                                                       '>nul '
                                                                                                                       '2>&1\n'
                                                                                                                       'del '
                                                                                                                       '%temp%\\T1140_calc2_decoded.exe '
                                                                                                                       '>nul '
                                                                                                                       '2>&1\n',
                                                                                                    'command': 'copy '
                                                                                                               '%windir%\\system32\\certutil.exe '
                                                                                                               '%temp%\\tcm.tmp\n'
                                                                                                               '%temp%\\tcm.tmp '
                                                                                                               '-encode '
                                                                                                               '#{executable} '
                                                                                                               '%temp%\\T1140_calc2.txt\n'
                                                                                                               '%temp%\\tcm.tmp '
                                                                                                               '-decode '
                                                                                                               '%temp%\\T1140_calc2.txt '
                                                                                                               '%temp%\\T1140_calc2_decoded.exe\n',
                                                                                                    'name': 'command_prompt'},
                                                                                       'input_arguments': {'executable': {'default': 'C:\\Windows\\System32\\calc.exe',
                                                                                                                          'description': 'name '
                                                                                                                                         'of '
                                                                                                                                         'executable/file '
                                                                                                                                         'to '
                                                                                                                                         'decode',
                                                                                                                          'type': 'path'}},
                                                                                       'name': 'Certutil '
                                                                                               'Rename '
                                                                                               'and '
                                                                                               'Decode',
                                                                                       'supported_platforms': ['windows']}],
                                                                     'attack_technique': 'T1140',
                                                                     'display_name': 'Deobfuscate/Decode '
                                                                                     'Files '
                                                                                     'or '
                                                                                     'Information'}},
 {'Threat Hunting Tables': {'chain_id': '100014',
                            'commandline_string': '-decode',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': 'c0d67fa9ef4292d1e6f18005163f1d86fbe18f68a6ef70e0744f12b12f44cf7c',
                            'loaded_dll': '',
                            'mitre_attack': 'T1140',
                            'mitre_caption': 'deobfuscation',
                            'os': 'windows',
                            'parent_process': 'certutil.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'SysmonHunter - T1140': {'description': None,
                           'level': 'high',
                           'name': 'Deobfuscate/Decode Files or Information',
                           'phase': 'Defense Evasion, Execution',
                           'query': [{'process': {'cmdline': {'pattern': '-decode|-urlcache'},
                                                  'image': {'pattern': 'certutil.exe'}},
                                      'type': 'process'},
                                     {'process': {'cmdline': {'pattern': 'certutil.exe|-decode|-urlcache'}},
                                      'type': 'process'}]}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Deobfuscate/Decode Files or Information Mitigation](../mitigations/Deobfuscate-Decode-Files-or-Information-Mitigation.md)


# Actors


* [OilRig](../actors/OilRig.md)

* [Leviathan](../actors/Leviathan.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [APT19](../actors/APT19.md)
    
* [APT28](../actors/APT28.md)
    
* [WIRTE](../actors/WIRTE.md)
    
* [Turla](../actors/Turla.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
* [Molerats](../actors/Molerats.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
* [Rocke](../actors/Rocke.md)
    
