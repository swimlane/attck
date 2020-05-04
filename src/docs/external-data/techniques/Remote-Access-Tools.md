
# Remote Access Tools

## Description

### MITRE Description

> An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks. These services are commonly used as legitimate technical support software, and may be whitelisted within a target environment. Remote access tools like VNC, Ammy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)

Remote access tools may be established and used post-compromise as alternate communications channel for [Redundant Access](https://attack.mitre.org/techniques/T1108) or as a way to establish an interactive remote desktop session with the target system. They may also be used as a component of malware to establish a reverse connection or back-connect to a service or adversary controlled system.

Admin tools such as TeamViewer have been used by several groups targeting institutions in countries of interest to the Russian state and criminal campaigns. (Citation: CrowdStrike 2015 Global Threat Report) (Citation: CrySyS Blog TeamSpy)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: ['User']
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1219

## Potential Commands

```
Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\TeamViewer_Setup.exe https://download.teamviewer.com/download/TeamViewer_Setup.exe
C:\Users\$env:username\Desktop\TeamViewer_Setup.exe

Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\AnyDesk.exe https://download.anydesk.com/AnyDesk.exe
C:\Users\$env:username\Desktop\AnyDesk.exe

Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\LogMeInIgnition.msi https://secure.logmein.com/LogMeInIgnition.msi
C:\Users\$env:username\Desktop\LogMeInIgnition.msi

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
             'C:\\Users\\$env:username\\Desktop\\TeamViewer_Setup.exe\n',
  'name': None,
  'source': 'atomics/T1219/T1219.yaml'},
 {'command': 'Invoke-WebRequest -OutFile '
             'C:\\Users\\$env:username\\Desktop\\AnyDesk.exe '
             'https://download.anydesk.com/AnyDesk.exe\n'
             'C:\\Users\\$env:username\\Desktop\\AnyDesk.exe\n',
  'name': None,
  'source': 'atomics/T1219/T1219.yaml'},
 {'command': 'Invoke-WebRequest -OutFile '
             'C:\\Users\\$env:username\\Desktop\\LogMeInIgnition.msi '
             'https://secure.logmein.com/LogMeInIgnition.msi\n'
             'C:\\Users\\$env:username\\Desktop\\LogMeInIgnition.msi\n',
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

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Remote Access Tools': {'atomic_tests': [{'description': 'An '
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
                                                                   'executor': {'command': 'Invoke-WebRequest '
                                                                                           '-OutFile '
                                                                                           'C:\\Users\\$env:username\\Desktop\\TeamViewer_Setup.exe '
                                                                                           'https://download.teamviewer.com/download/TeamViewer_Setup.exe\n'
                                                                                           'C:\\Users\\$env:username\\Desktop\\TeamViewer_Setup.exe\n',
                                                                                'elevation_required': True,
                                                                                'name': 'powershell'},
                                                                   'name': 'TeamViewer '
                                                                           'Files '
                                                                           'Detected '
                                                                           'Test '
                                                                           'on '
                                                                           'Windows',
                                                                   'supported_platforms': ['windows']},
                                                                  {'description': 'An '
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
                                                                   'executor': {'command': 'Invoke-WebRequest '
                                                                                           '-OutFile '
                                                                                           'C:\\Users\\$env:username\\Desktop\\AnyDesk.exe '
                                                                                           'https://download.anydesk.com/AnyDesk.exe\n'
                                                                                           'C:\\Users\\$env:username\\Desktop\\AnyDesk.exe\n',
                                                                                'elevation_required': True,
                                                                                'name': 'powershell'},
                                                                   'name': 'AnyDesk '
                                                                           'Files '
                                                                           'Detected '
                                                                           'Test '
                                                                           'on '
                                                                           'Windows',
                                                                   'supported_platforms': ['windows']},
                                                                  {'description': 'An '
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
                                                                   'executor': {'command': 'Invoke-WebRequest '
                                                                                           '-OutFile '
                                                                                           'C:\\Users\\$env:username\\Desktop\\LogMeInIgnition.msi '
                                                                                           'https://secure.logmein.com/LogMeInIgnition.msi\n'
                                                                                           'C:\\Users\\$env:username\\Desktop\\LogMeInIgnition.msi\n',
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
                                                                 'Tools'}},
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

None

# Actors


* [Thrip](../actors/Thrip.md)

* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [Carbanak](../actors/Carbanak.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
