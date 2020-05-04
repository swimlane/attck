
# Deobfuscate/Decode Files or Information

## Description

### MITRE Description

> Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware, [Scripting](https://attack.mitre.org/techniques/T1064), [PowerShell](https://attack.mitre.org/techniques/T1086), or by using utilities present on the system.

One such example is use of [certutil](https://attack.mitre.org/software/S0160) to decode a remote access tool portable executable file that has been hidden inside a certificate file. (Citation: Malwarebytes Targeted Attack against Saudi Arabia)

Another example is using the Windows <code>copy /b</code> command to reassemble binary fragments into a malicious payload. (Citation: Carbon Black Obfuscation Sept 2016)

Payloads may be compressed, archived, or encrypted in order to avoid detection.  These payloads may be used with [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open it for deobfuscation or decryption as part of [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as Javascript.

## Additional Attributes

* Bypass: ['Anti-virus', 'Host intrusion prevention systems', 'Signature-based detection', 'Network intrusion detection system']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1140

## Potential Commands

```
certutil -encode C:\Windows\System32\calc.exe %temp%\T1140_calc.txt
certutil -decode %temp%\T1140_calc.txt %temp%\T1140_calc_decoded.exe

copy %windir%\system32\certutil.exe %temp%\tcm.tmp
%temp%\tcm.tmp -encode C:\Windows\System32\calc.exe %temp%\T1140_calc.txt
%temp%\tcm.tmp -decode %temp%\T1140_calc.txt %temp%\T1140_calc_decoded.exe

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
             '%temp%\\T1140_calc.txt\n'
             '%temp%\\tcm.tmp -decode %temp%\\T1140_calc.txt '
             '%temp%\\T1140_calc_decoded.exe\n',
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
[{'Atomic Red Team Test - Deobfuscate/Decode Files Or Information': {'atomic_tests': [{'description': 'Encode/Decode '
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
                                                                                                                       '%temp%T1140_calc_decoded.exe '
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
                                                                                                    'elevation_required': False,
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
                                                                                      {'description': 'Rename '
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
                                                                                                                       '%temp%\\T1140_calc.txt '
                                                                                                                       '>nul '
                                                                                                                       '2>&1\n'
                                                                                                                       'del '
                                                                                                                       '%temp%T1140_calc_decoded.exe '
                                                                                                                       '>nul '
                                                                                                                       '2>&1\n',
                                                                                                    'command': 'copy '
                                                                                                               '%windir%\\system32\\certutil.exe '
                                                                                                               '%temp%\\tcm.tmp\n'
                                                                                                               '%temp%\\tcm.tmp '
                                                                                                               '-encode '
                                                                                                               '#{executable} '
                                                                                                               '%temp%\\T1140_calc.txt\n'
                                                                                                               '%temp%\\tcm.tmp '
                                                                                                               '-decode '
                                                                                                               '%temp%\\T1140_calc.txt '
                                                                                                               '%temp%\\T1140_calc_decoded.exe\n',
                                                                                                    'elevation_required': False,
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
                                                                                     'Or '
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

None

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
    
